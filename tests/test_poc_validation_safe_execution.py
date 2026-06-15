from __future__ import annotations

from prometheus.core.candidate_store import CandidateStore
from prometheus.core.poc_validation import _execute_curl_command, validate_poc_execution
from prometheus.tools.knowledge.store import KnowledgeStore


def test_curl_execution_does_not_use_shell(tmp_path) -> None:
    marker = tmp_path / "pwned"

    _execute_curl_command(f"curl --version; touch {marker}", timeout=2)

    assert not marker.exists()


def test_poc_execution_stores_structured_validation_run(tmp_path) -> None:
    db = tmp_path / "prometheus.db"
    payload = tmp_path / "payload.json"
    payload.write_text('{"token":"abc","user":"victim@example.com"}', encoding="utf-8")
    KnowledgeStore(db)
    store = CandidateStore(db)
    result = store.ingest_raw_finding(
        {
            "title": "Auth bypass returned token",
            "endpoint": str(payload),
            "vuln_type": "auth_bypass",
        },
        domain="example.com",
        scan_id="scan-1",
    )
    candidate_id = result["id"]

    verdict = validate_poc_execution(
        {
            "id": candidate_id,
            "db_path": db,
            "title": "Auth bypass returned token",
            "poc_description": "curl returns access_token data",
            "poc_script_code": f"curl file://{payload}",
        },
        execute_poc=True,
        timeout=5,
    )

    runs = store.list_validation_runs(candidate_id)
    assert verdict.poc_executed is True
    assert verdict.verdict == "exploitable"
    assert runs
    assert runs[0]["validator"] == "poc_execution"
    assert runs[0]["status"] == "success"
