"""Tests for the verify_finding tool and its deterministic helpers.

Covers:
- Pure helpers (_parse_poc_output, _compute_verdict, _extract_meta_from_poc)
- End-to-end flow against a local HTTP server (positive case, timeout)
- Error paths (missing META block, invalid JSON extras)
- Persistence to vulnerabilities.json
- Report rendering: the verification block in the per-finding MD

All tests use tmp_path; no LLM, no remote network, no sandbox session.
The HTTP server tests bind to 127.0.0.1:0 so there's no port conflict.
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from prometheus.core.deep_audit import generate_poc_script
from prometheus.core.paths import configure_runs_dir
from prometheus.report.state import ReportState, set_global_report_state
from prometheus.report.writer import render_vulnerability_md
from prometheus.tools.verification.tool import (
    _compute_verdict,
    _extract_meta_from_poc,
    _parse_poc_output,
    verify_finding_impl,
)


# ---------------------------------------------------------------------------
# Canned stdout fixtures
# ---------------------------------------------------------------------------

CANNED_CONFIRMED_STDOUT = """
============================================================
PoC: Test
Endpoint: GET http://127.0.0.1:1234/api
============================================================

[1] Testing: invalid email (value=a@b.com)
    Status: 200
    Body: ok

[2] Testing: sqli (value=' OR 1=1--)
    Status: 500
    Body: error

============================================================
ANALYSIS
============================================================

Distinct response codes: 2
  HTTP 200: ['invalid email (value=a@b.com)']
  HTTP 500: ["sqli (value=' OR 1=1--)"]

[CONFIRMED] Differential responses detected!
The endpoint returns different responses based on input.
"""


CANNED_NOT_CONFIRMED_STDOUT = """
============================================================
PoC: Test
Endpoint: GET http://127.0.0.1:1234/api
============================================================

[1] Testing: case1 (value=x)
    Status: 200
    Body: ok

[2] Testing: case2 (value=y)
    Status: 200
    Body: ok

============================================================
ANALYSIS
============================================================

Distinct response codes: 1
  HTTP 200: ['case1 (value=x)', 'case2 (value=y)']

[NOT CONFIRMED] All responses were identical.
"""


def _build_poc_with_meta(endpoint: str, method: str, body: str, cases: list[dict]) -> str:
    """Build a PoC string with the META block prepended (matches generate_poc_script)."""
    # Call the real generator — it now embeds the META block.
    return generate_poc_script(
        finding_title="Test",
        endpoint=endpoint,
        method=method,
        request_body_template=body,
        test_cases=cases,
    )


# ---------------------------------------------------------------------------
# Pure-helper tests
# ---------------------------------------------------------------------------


def test_parse_poc_output_extracts_distinct_responses_and_groups() -> None:
    parsed = _parse_poc_output(CANNED_CONFIRMED_STDOUT)
    assert parsed["distinct_responses"] == 2
    assert "200" in parsed["status_groups"]
    assert "500" in parsed["status_groups"]
    assert len(parsed["status_groups"]["200"]) == 1
    assert parsed["confirmed_line"] == "confirmed"


def test_parse_poc_output_marks_not_confirmed() -> None:
    parsed = _parse_poc_output(CANNED_NOT_CONFIRMED_STDOUT)
    assert parsed["distinct_responses"] == 1
    assert parsed["confirmed_line"] == "not_confirmed"


def test_parse_poc_output_extracts_per_case() -> None:
    parsed = _parse_poc_output(CANNED_CONFIRMED_STDOUT)
    assert len(parsed["per_case"]) == 2
    assert parsed["per_case"][0]["value"] == "a@b.com"
    assert parsed["per_case"][0]["status"] == 200
    assert parsed["per_case"][1]["value"] == "' OR 1=1--"
    assert parsed["per_case"][1]["status"] == 500


def test_compute_verdict_positive_only_confirms_on_distinct() -> None:
    parsed = _parse_poc_output(CANNED_CONFIRMED_STDOUT)
    verified, neg_passed = _compute_verdict(parsed, None)
    assert verified is True
    assert neg_passed is None


def test_compute_verdict_positive_only_denies_on_uniform() -> None:
    parsed = _parse_poc_output(CANNED_NOT_CONFIRMED_STDOUT)
    verified, neg_passed = _compute_verdict(parsed, None)
    assert verified is False
    assert neg_passed is None


def test_compute_verdict_negative_control_misbehavior_overrides_positive() -> None:
    """Control produces a status that doesn't appear in any positive case → fail."""
    parsed = {
        "distinct_responses": 2,
        "status_groups": {"200": ["pos"], "999": ["neg"]},
        "per_case": [
            {"index": 1, "description": "pos", "value": "x", "status": 200},
            {"index": 2, "description": "neg", "value": "y", "status": 999},
        ],
        "confirmed_line": "confirmed",
    }
    verified, neg_passed = _compute_verdict(parsed, "neg")
    assert verified is False
    assert neg_passed is False


def test_compute_verdict_negative_control_passes() -> None:
    """Control lands in the positive status set → verdict holds, control marked passed."""
    parsed = {
        "distinct_responses": 2,
        "status_groups": {"200": ["neg", "well_formed"], "302": ["pos"]},
        "per_case": [
            {"index": 1, "description": "well_formed", "value": "ok@x.com", "status": 200},
            {"index": 2, "description": "neg", "value": "control@x.com", "status": 200},
            {"index": 3, "description": "pos", "value": "bad", "status": 302},
        ],
        "confirmed_line": "confirmed",
    }
    verified, neg_passed = _compute_verdict(parsed, "neg")
    assert verified is True
    assert neg_passed is True


def test_compute_verdict_missing_control_denies() -> None:
    """If the control description isn't in per_case, fail."""
    parsed = {
        "distinct_responses": 1,
        "per_case": [
            {"index": 1, "description": "pos", "value": "x", "status": 200},
        ],
        "confirmed_line": "not_confirmed",
    }
    verified, neg_passed = _compute_verdict(parsed, "neg")
    assert verified is False
    assert neg_passed is False


def test_extract_meta_from_poc_recovers_json() -> None:
    poc = _build_poc_with_meta(
        endpoint="http://x.example/api",
        method="POST",
        body='{"email": "{input}"}',
        cases=[
            {"value": "a@b", "expected_status": 200, "description": "well-formed"},
            {"value": "bad", "expected_status": 500, "description": "malformed"},
        ],
    )
    meta = _extract_meta_from_poc(poc)
    assert meta is not None
    assert meta["endpoint"] == "http://x.example/api"
    assert meta["method"] == "POST"
    assert meta["body_template"] == '{"email": "{input}"}'
    assert len(meta["test_cases"]) == 2
    assert meta["test_cases"][0]["value"] == "a@b"


def test_extract_meta_returns_none_for_missing_block() -> None:
    assert _extract_meta_from_poc("print('hello world')") is None
    assert _extract_meta_from_poc("") is None


# ---------------------------------------------------------------------------
# End-to-end: local HTTP server
# ---------------------------------------------------------------------------


class _DifferentialHandler(BaseHTTPRequestHandler):
    """Handler that returns 200 when ``q=ok`` and 500 when ``q=bad``.
    Used to test differential-response detection.

    The PoC script template appends ``?q=<value>`` to the endpoint for
    GET requests (see ``generate_poc_script``'s GET branch at
    ``prometheus/core/deep_audit.py:573``), so the handler inspects
    the query string rather than the path.
    """

    def do_GET(self) -> None:  # noqa: N802 - http.server protocol
        from urllib.parse import urlparse, parse_qs

        qs = parse_qs(urlparse(self.path).query)
        value = (qs.get("q") or [""])[0]

        if value in ("ok", "control"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
        elif value == "bad":
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"server error")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        # Silence the test server's stderr output.
        return


def _start_http_server(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[HTTPServer, str]:
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://{host}:{port}"


def _setup_state(tmp_path: Path) -> ReportState:
    configure_runs_dir(str(tmp_path))
    state = ReportState(run_name="verify-test")
    set_global_report_state(state)
    return state


def _add_finding_with_meta(
    state: ReportState,
    endpoint: str,
    method: str,
    body: str,
    cases: list[dict],
    title: str = "Test Finding",
) -> str:
    poc = _build_poc_with_meta(endpoint, method, body, cases)
    report_id = state.add_vulnerability_report(
        title=title,
        severity="high",
        description="end-to-end verification test",
        poc_description="Run the embedded PoC and check the response",
        poc_script_code=poc,
        endpoint=endpoint,
        method=method,
    )
    return report_id


def test_verify_finding_end_to_end_with_local_http_server(tmp_path) -> None:
    server, base_url = _start_http_server(_DifferentialHandler)
    try:
        state = _setup_state(tmp_path)
        cases = [
            {"value": "ok", "expected_status": 200, "description": "well-formed input"},
            {"value": "bad", "expected_status": 500, "description": "malicious input"},
        ]
        finding_id = _add_finding_with_meta(
            state,
            endpoint=f"{base_url}/probe",
            method="GET",
            body="q={input}",
            cases=cases,
        )

        result_json = asyncio.run(
            verify_finding_impl(
                finding_id=finding_id,
            )
        )
        result = json.loads(result_json)

        assert result["success"] is True, result
        assert result["finding_id"] == finding_id
        assert result["verified"] is True
        assert result["distinct_responses"] == 2
        assert "200" in result["status_groups"]
        assert "500" in result["status_groups"]

        # The verification block is now attached to the in-memory report.
        report = next(r for r in state.vulnerability_reports if r["id"] == finding_id)
        assert "verification" in report
        assert report["verification"]["verified"] is True
        assert report["verification"]["negative_control_passed"] is None
    finally:
        server.shutdown()


def test_verify_finding_with_negative_control_passes(tmp_path) -> None:
    """A control payload that produces the same status as the well-formed
    positive case should pass the negative-control check."""
    server, base_url = _start_http_server(_DifferentialHandler)
    try:
        state = _setup_state(tmp_path)
        cases = [
            {"value": "ok", "expected_status": 200, "description": "well-formed input"},
        ]
        finding_id = _add_finding_with_meta(
            state,
            endpoint=f"{base_url}/probe",
            method="GET",
            body="q={input}",
            cases=cases,
        )

        # We add a second positive case (/bad → 500) plus a control (/ok → 200).
        # Note: verify_finding appends to the existing test_cases.
        result_json = asyncio.run(
            verify_finding_impl(
                finding_id=finding_id,
                negative_control_value="control",
                negative_control_description="benign control",
                extra_test_cases_json=json.dumps(
                    [
                        {"value": "bad", "expected_status": 500, "description": "malicious input"},
                    ]
                ),
            )
        )
        result = json.loads(result_json)

        assert result["success"] is True, result
        assert result["verified"] is True
        assert result["negative_control_passed"] is True
        assert result["distinct_responses"] == 2
    finally:
        server.shutdown()


def test_verify_finding_returns_error_on_missing_meta(tmp_path) -> None:
    state = _setup_state(tmp_path)
    # File a finding with a PoC that has NO META block.
    report_id = state.add_vulnerability_report(
        title="No-meta finding",
        severity="low",
        description="test",
        poc_description="test",
        poc_script_code="print('no meta here')\n",
    )
    result_json = asyncio.run(
        verify_finding_impl(
            finding_id=report_id,
        )
    )
    result = json.loads(result_json)
    assert result["success"] is False
    assert "PROMETHEUS_META" in result["error"]


def test_verify_finding_returns_error_on_unknown_id(tmp_path) -> None:
    _setup_state(tmp_path)
    result_json = asyncio.run(
        verify_finding_impl(
            finding_id="vuln-9999",
        )
    )
    result = json.loads(result_json)
    assert result["success"] is False
    assert "vuln-9999" in result["error"]


def test_verify_finding_returns_error_on_invalid_extras_json(tmp_path) -> None:
    server, base_url = _start_http_server(_DifferentialHandler)
    try:
        state = _setup_state(tmp_path)
        finding_id = _add_finding_with_meta(
            state,
            endpoint=f"{base_url}/ok",
            method="GET",
            body="q={input}",
            cases=[{"value": "x", "expected_status": 200, "description": "x"}],
        )
        result_json = asyncio.run(
            verify_finding_impl(
                finding_id=finding_id,
                extra_test_cases_json="not json",
            )
        )
        result = json.loads(result_json)
        assert result["success"] is False
        assert "extra_test_cases_json" in result["error"]
    finally:
        server.shutdown()


def test_verify_finding_persists_to_vulnerabilities_json(tmp_path) -> None:
    server, base_url = _start_http_server(_DifferentialHandler)
    try:
        state = _setup_state(tmp_path)
        finding_id = _add_finding_with_meta(
            state,
            endpoint=f"{base_url}/probe",
            method="GET",
            body="q={input}",
            cases=[
                {"value": "ok", "expected_status": 200, "description": "ok"},
                {"value": "bad", "expected_status": 500, "description": "bad"},
            ],
        )

        result = json.loads(
            asyncio.run(
                verify_finding_impl(
                    finding_id=finding_id,
                )
            )
        )
        assert result["success"] is True

        # verify_finding calls state.save_run_data() which flushes
        # vulnerabilities.json. Read it back from disk.
        run_dir = state.get_run_dir()
        vuln_json = run_dir / "vulnerabilities.json"
        assert vuln_json.exists(), f"missing {vuln_json}"
        data = json.loads(vuln_json.read_text())
        match = next((r for r in data if r["id"] == finding_id), None)
        assert match is not None
        assert "verification" in match
        assert match["verification"]["verified"] is True
        assert match["verification"]["distinct_responses"] == 2
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# Markdown rendering of the verification block
# ---------------------------------------------------------------------------


def test_render_vulnerability_md_includes_verification_block(tmp_path) -> None:
    """If a report has a verification block, the MD render should include it."""
    poc = _build_poc_with_meta(
        endpoint="http://x/api",
        method="GET",
        body="q={input}",
        cases=[{"value": "x", "expected_status": 200, "description": "x"}],
    )
    report = {
        "id": "vuln-0001",
        "title": "Test",
        "severity": "high",
        "timestamp": "2026-06-13 12:00:00 UTC",
        "description": "desc",
        "poc_description": "poc desc",
        "poc_script_code": poc,
        "verification": {
            "verified": True,
            "exit_code": 0,
            "distinct_responses": 2,
            "status_groups": {"200": ["ok"], "500": ["bad"]},
            "per_case": [
                {"index": 1, "description": "ok", "value": "x", "status": 200},
                {"index": 2, "description": "bad", "value": "y", "status": 500},
            ],
            "negative_control_passed": True,
            "evidence_excerpt": "Distinct response codes: 2",
            "verified_at": "2026-06-13T12:00:01+00:00",
        },
    }
    md = render_vulnerability_md(report)
    assert "## Verification" in md
    assert "VERIFIED" in md
    assert "Distinct response codes: 2" in md
    assert "Negative control:** passed" in md
    # The per-case table is present.
    assert "| 1 | ok |" in md


def test_render_vulnerability_md_omits_verification_when_absent() -> None:
    """Findings without a verification key should not get the block."""
    report = {
        "id": "vuln-0001",
        "title": "Test",
        "severity": "low",
        "timestamp": "2026-06-13 12:00:00 UTC",
        "description": "desc",
    }
    md = render_vulnerability_md(report)
    assert "## Verification" not in md
