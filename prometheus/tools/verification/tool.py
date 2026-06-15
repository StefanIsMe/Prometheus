"""``verification`` — execute a filed PoC and persist a deterministic verdict.

Closes the gap between ``generate_verified_poc`` (which *writes* a PoC
script) and ``create_vulnerability_report`` (which *files* a finding): the
agent can call ``verify_finding`` to actually run the PoC, parse the
output deterministically, optionally apply a negative-control check, and
persist a structured ``verification`` block back onto the finding in
``ReportState``.

The tool's decision path is LLM-free: it shells out via the host
``subprocess.run`` (mirroring the existing pattern in
``prometheus/core/poc_validation.py``), parses stdout with regex, and
applies set-membership logic to compute the verdict.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from prometheus.core.deep_audit import generate_poc_script
from prometheus.report.state import get_global_report_state

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default wall-clock budget for one PoC run. Multi-case PoCs run
# sequentially with 15s per request hard-coded inside the script, so 120s
# comfortably fits ~5-7 test cases plus overhead.
_POC_TIMEOUT = 120

# Matches the META block injected by generate_poc_script. The block is a
# Python comment so it has no runtime effect, but it lets us round-trip
# the inputs (endpoint, method, body_template, test_cases) from a filed
# finding's poc_script_code back into a re-runnable script.
_PROM_META_PATTERN = re.compile(
    r"#\s*===PROMETHEUS_META_BEGIN===\s*\n(.*?)\n#\s*===PROMETHEUS_META_END===",
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Pure helpers (no LLM, no I/O — easily unit-testable)
# ---------------------------------------------------------------------------


def _parse_poc_output(stdout: str) -> dict[str, Any]:
    """Deterministic regex parse of ``generate_poc_script``'s standard output.

    The script template prints (in this order):

        ============================================================
        PoC: <title>
        Endpoint: <METHOD> <ENDPOINT>
        ============================================================

        [1] Testing: <description> (value=<value>)
            Status: <code>
            Body: <first 200 chars>

        [...more cases...]

        ============================================================
        ANALYSIS
        ============================================================
        Distinct response codes: N
          HTTP <code>: ['<desc>', ...]
        [CONFIRMED] Differential responses detected!
        — or —
        [NOT CONFIRMED] All responses were identical.

    Returns a dict with ``distinct_responses`` (int), ``status_groups``
    (dict[str, list[str]]), ``per_case`` (list[dict]), and
    ``confirmed_line`` (str | None).
    """
    result: dict[str, Any] = {
        "distinct_responses": 0,
        "status_groups": {},
        "per_case": [],
        "confirmed_line": None,
    }

    distinct_m = re.search(r"Distinct response codes:\s*(\d+)", stdout)
    if distinct_m:
        result["distinct_responses"] = int(distinct_m.group(1))

    for sm in re.finditer(r"HTTP\s+(\d+):\s*\[([^\]]*)\]", stdout):
        status = sm.group(1)
        cases_raw = sm.group(2)
        cases = [c.strip().strip("'\"") for c in cases_raw.split(",") if c.strip()]
        result["status_groups"][status] = cases

    for cm in re.finditer(
        r"\[(\d+)\] Testing:\s*(.+?)\s*\(value=(.+?)\).*?Status:\s*(\d+)",
        stdout,
        re.DOTALL,
    ):
        result["per_case"].append(
            {
                "index": int(cm.group(1)),
                "description": cm.group(2).strip(),
                "value": cm.group(3).strip(),
                "status": int(cm.group(4)),
            }
        )

    if "[CONFIRMED]" in stdout:
        result["confirmed_line"] = "confirmed"
    elif "[NOT CONFIRMED]" in stdout:
        result["confirmed_line"] = "not_confirmed"

    return result


def _compute_verdict(
    parsed: dict[str, Any],
    negative_control_desc: str | None,
) -> tuple[bool, bool | None]:
    """Pure function. Returns ``(verified, negative_control_passed_or_None)``.

    Positive check: ``distinct_responses >= 2`` OR the script printed
    ``[CONFIRMED]``. Otherwise not verified.

    Negative control check (only if ``negative_control_desc`` is set):
    find the per-case entry whose description matches, then check its
    status appears in the set of statuses observed for the *positive*
    cases. If the control's status is unique (i.e. it triggered a
    response class that wasn't shared with any positive case), the
    test setup is broken — return ``False`` and mark
    ``negative_control_passed=False``.

    If the control's status *is* in the positive set, return
    ``True`` (or the positive-only verdict) with
    ``negative_control_passed=True``.
    """
    distinct = parsed.get("distinct_responses", 0)
    confirmed = parsed.get("confirmed_line") == "confirmed"
    positive_verified = distinct >= 2 or confirmed

    if not negative_control_desc:
        return positive_verified, None

    per_case = parsed.get("per_case", [])
    neg = next(
        (c for c in per_case if c["description"] == negative_control_desc),
        None,
    )
    if neg is None:
        # Couldn't find the control's response — bad test setup.
        return False, False

    pos_statuses = {c["status"] for c in per_case if c["description"] != negative_control_desc}
    if not pos_statuses:
        # No positive cases — the control is the only thing that ran.
        return False, False

    neg_passed = neg["status"] in pos_statuses
    if not neg_passed:
        # Negative control produced a status not seen in positives.
        # Override the positive verdict — the test setup is suspect.
        return False, False

    return positive_verified, True


def _extract_meta_from_poc(poc_code: str) -> dict[str, Any] | None:
    """Recover the original PoC inputs from a filed ``poc_script_code``.

    Returns ``None`` if the META block is missing or malformed.
    """
    if not poc_code:
        return None
    m = _PROM_META_PATTERN.search(poc_code)
    if not m:
        return None
    meta_text = m.group(1)
    # Strip the leading "# " from each line of the comment block.
    lines = [ln[2:] if ln.startswith("# ") else ln for ln in meta_text.splitlines()]
    meta_str = "\n".join(lines)
    try:
        return json.loads(meta_str)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------


async def verify_finding_impl(  # noqa: PLR0915 - tool body, not a library function
    finding_id: str,
    *,
    negative_control_value: str | None = None,
    negative_control_description: str | None = None,
    extra_test_cases_json: str = "[]",
    timeout: int = _POC_TIMEOUT,
) -> str:
    """Pure implementation of verify_finding. Called by the @function_tool
    wrapper below and directly by unit tests.

    Looks up the finding by ``finding_id`` (e.g. ``"vuln-0001"``) in the
    current run's ``vulnerability_reports``, regenerates the PoC from the
    inputs encoded in its ``poc_script_code`` META block, optionally
    appends a negative-control test case, runs the script via
    ``subprocess.run``, parses the output deterministically, and writes a
    structured ``verification`` block back onto the finding.

    The verdict is purely mechanical (regex + set membership). No LLM
    participates in the decision.
    """
    state = get_global_report_state()
    if state is None:
        return json.dumps(
            {
                "success": False,
                "error": "no active report state — cannot locate findings",
            }
        )

    try:
        report = next(r for r in state.vulnerability_reports if r["id"] == finding_id)
    except StopIteration:
        return json.dumps(
            {
                "success": False,
                "finding_id": finding_id,
                "error": f"finding_id {finding_id!r} not found in current run",
            }
        )

    meta = _extract_meta_from_poc(report.get("poc_script_code", ""))
    if meta is None:
        return json.dumps(
            {
                "success": False,
                "finding_id": finding_id,
                "error": (
                    "poc_script_code has no PROMETHEUS_META block; cannot "
                    "reconstruct inputs (re-file the finding via "
                    "create_vulnerability_report with a generated PoC)"
                ),
            }
        )

    # Augment test cases: optional extras from caller, then the negative
    # control (if any).
    test_cases: list[dict[str, Any]] = list(meta.get("test_cases", []))
    if extra_test_cases_json and extra_test_cases_json.strip() not in ("", "[]"):
        try:
            extras = json.loads(extra_test_cases_json)
        except json.JSONDecodeError as exc:
            return json.dumps(
                {
                    "success": False,
                    "finding_id": finding_id,
                    "error": f"extra_test_cases_json is not valid JSON: {exc}",
                }
            )
        if isinstance(extras, list):
            test_cases.extend(extras)

    neg_desc: str | None = None
    if negative_control_value and negative_control_description:
        test_cases.append(
            {
                "value": negative_control_value,
                "expected_status": 200,
                "description": negative_control_description,
            }
        )
        neg_desc = negative_control_description

    # Regenerate the script with the augmented test cases.
    script = generate_poc_script(
        finding_title=report.get("title", finding_id),
        endpoint=meta["endpoint"],
        method=meta["method"],
        request_body_template=meta["body_template"],
        test_cases=test_cases,
    )

    # Write to a temp file, run, parse, persist.
    script_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            prefix="prom_poc_",
            delete=False,
            dir=tempfile.gettempdir(),
        ) as f:
            f.write(script)
            script_path = Path(f.name)

        try:
            result = subprocess.run(  # noqa: S603 - argv execution, no shell
                ["python3", str(script_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            verification = {
                "verified": False,
                "error": "timeout",
                "timeout_seconds": timeout,
                "verified_at": datetime.now(UTC).isoformat(),
            }
            report["verification"] = verification
            try:
                state.save_run_data()
            except Exception:  # noqa: BLE001 - persistence is best-effort
                logger.exception("save_run_data failed after timeout")
            return json.dumps(
                {
                    "success": False,
                    "finding_id": finding_id,
                    **verification,
                },
                default=str,
            )

        parsed = _parse_poc_output(result.stdout)
        verified, neg_passed = _compute_verdict(parsed, neg_desc)
        verification = {
            "verified": verified,
            "exit_code": result.returncode,
            "distinct_responses": parsed["distinct_responses"],
            "status_groups": parsed["status_groups"],
            "per_case": parsed["per_case"],
            "negative_control_passed": neg_passed,
            "evidence_excerpt": result.stdout[:500],
            "stderr_excerpt": (result.stderr or "")[:500],
            "verified_at": datetime.now(UTC).isoformat(),
        }
        report["verification"] = verification
        try:
            state.save_run_data()
        except Exception:  # noqa: BLE001 - persistence is best-effort
            logger.exception("save_run_data failed after verification")

        return json.dumps(
            {
                "success": True,
                "finding_id": finding_id,
                **verification,
            },
            default=str,
        )
    except Exception as exc:  # noqa: BLE001 - last-resort safety net
        logger.exception("verify_finding failed for %s", finding_id)
        return json.dumps(
            {
                "success": False,
                "finding_id": finding_id,
                "error": f"verify_finding crashed: {exc!s}",
            }
        )
    finally:
        if script_path is not None:
            script_path.unlink(missing_ok=True)


@function_tool
async def verify_finding(  # type: ignore[no-redef]
    ctx: RunContextWrapper[Any],
    finding_id: str,
    negative_control_value: str | None = None,
    negative_control_description: str | None = None,
    extra_test_cases_json: str = "[]",
    timeout: int = _POC_TIMEOUT,
) -> str:
    """Execute the PoC for a filed finding and persist a deterministic verdict.

    Look up the finding by ``finding_id``, regenerate the PoC from its
    encoded META block, optionally append a negative-control test case,
    run the script, parse the output, and persist the verdict on the
    finding. The decision path is LLM-free.

    Args:
        finding_id: The ``vuln-NNNN`` identifier of the filed finding to
            verify. The current run's ``ReportState`` must be active.
        negative_control_value: Optional payload that should NOT trigger
            the vulnerability.
        negative_control_description: Human-readable label for the
            negative-control test case.
        extra_test_cases_json: Optional JSON array of additional
            ``{value, expected_status, description}`` test cases to
            append to the original set before re-running.
        timeout: Wall-clock budget in seconds. Default 120.

    Returns:
        JSON object — see ``verify_finding_impl`` for the exact schema.
    """
    return await verify_finding_impl(
        finding_id,
        negative_control_value=negative_control_value,
        negative_control_description=negative_control_description,
        extra_test_cases_json=extra_test_cases_json,
        timeout=timeout,
    )
