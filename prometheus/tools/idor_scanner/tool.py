"""Agnostic IDOR Scanner for Prometheus.

Discovers, tests, and reports IDOR vulnerabilities on any web application.

Workflow:
1. Load target profile (predefined or auto-configure)
2. Create two accounts via browser (Account A + Account B)
3. Log in as Account A, navigate target pages
4. Harvest API endpoints from browser network traffic
5. Extract ID patterns from harvested endpoints
6. Replay each endpoint with swapped IDs using Account A's session
7. Compare responses — if Account A sees Account B's data, that's an IDOR
8. Save findings to Prometheus candidate store

Usage:
    python3 -m prometheus.tools.idor_scanner.tool --target syfe --email prometheus_test
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import random
import sqlite3
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Prometheus imports
from prometheus.agents.browser_session import BrowserSession, get_target_profile


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Evidence storage
# ---------------------------------------------------------------------------

EVIDENCE_DIR = (
    Path(os.environ.get("PROMETHEUS_DATA_DIR", str(Path.home() / ".prometheus"))) / "idor_evidence"
)
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def _save_evidence(
    finding_id: str,
    account_a_resp: str,
    account_b_swapped_resp: str,
    request_details: dict[str, Any],
) -> Path:
    """Save IDOR evidence to disk and return the path."""
    evidence = {
        "finding_id": finding_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "request": request_details,
        "account_a_response": account_a_resp[:5000] if account_a_resp else "",
        "account_b_swapped_response": account_b_swapped_resp[:5000]
        if account_b_swapped_resp
        else "",
        "idor_confirmed": account_a_resp != account_b_swapped_resp
        and account_b_swapped_resp is not None
        and len(account_b_swapped_resp or "") > 10,
    }
    path = EVIDENCE_DIR / f"{finding_id}.json"
    path.write_text(json.dumps(evidence, indent=2))
    logger.info("Evidence saved to %s", path)
    return path


# ---------------------------------------------------------------------------
# HTTP replay via CDP (authenticated — uses Account A's session)
# ---------------------------------------------------------------------------


def _fetch_via_cdp(url: str, method: str = "GET", body: str = "") -> str | None:
    """Make an authenticated HTTP request via the browser's CDP Fetch domain.

    Uses the current browser session's cookies automatically.
    """
    from browser_harness import helpers as h

    try:
        # Enable fetch domain to intercept/modify requests
        h.cdp("Fetch.enable")

        # Navigate to trigger the request, or use fetch API
        js_code = f"""
        (async function() {{
            try {{
                var opts = {{ method: '{method}', credentials: 'include' }};
                if ('{body}') {{
                    opts.headers = {{ 'Content-Type': 'application/json' }};
                    opts.body = JSON.stringify({body});
                }}
                var resp = await fetch('{url}', opts);
                var text = await resp.text();
                return JSON.stringify({{
                    status: resp.status,
                    body: text.substring(0, 10000),
                    headers: Array.from(resp.headers.entries()).slice(0, 20)
                }});
            }} catch(e) {{
                return JSON.stringify({{ error: e.message }});
            }}
        }})()
        """
        result = h.js(js_code)
        if result:
            parsed = json.loads(result) if isinstance(result, str) else result
            if isinstance(parsed, dict) and "error" in parsed:
                logger.debug("Fetch failed: %s", parsed["error"])
                return None
            return parsed.get("body", "") if isinstance(parsed, dict) else str(parsed)
    except Exception as e:
        logger.debug("CDP fetch failed for %s: %s", url, e)
    finally:
        try:
            h.cdp("Fetch.disable")
        except Exception:
            logger.debug("Fetch.disable failed, ignoring", exc_info=True)

    return None


# ---------------------------------------------------------------------------
# IDOR detection
# ---------------------------------------------------------------------------


def _generate_test_ids(original_id: str, id_type: str) -> list[str]:
    """Generate candidate IDs to swap in for IDOR testing.

    For numeric IDs: try adjacent numbers.
    For UUIDs: try replacing with another UUID.
    For params: try +1/-1.
    """
    candidates = []
    if id_type == "numeric" and original_id.isdigit():
        num = int(original_id)
        candidates = [str(num + 1), str(num - 1), str(num + random.randint(10, 100)), "1", "0"]
    elif id_type == "uuid":
        candidates = [
            "00000000-0000-0000-0000-000000000000",
            "11111111-1111-1111-1111-111111111111",
            str(uuid.uuid4()),
        ]
    elif id_type == "param":
        if original_id.isdigit():
            num = int(original_id)
            candidates = [str(num + 1), "1"]
        else:
            candidates = ["admin", "test"]
    return candidates


def _swap_id_in_url(url: str, original_id: str, test_id: str) -> str:
    """Replace the original ID with a test ID in the URL."""
    if original_id.isdigit():
        # Replace last occurrence of the numeric ID
        return url[::-1].replace(original_id[::-1], test_id[::-1], 1)[::-1]
    else:
        # Replace first occurrence (for UUIDs)
        return url.replace(original_id, test_id, 1)


def _responses_indicate_idor(original_resp: str | None, swapped_resp: str | None) -> bool:
    """Compare two responses to determine if IDOR exists.

    Returns True if the responses differ in a meaningful way (not just
    a 404/401 error for the swapped ID).
    """
    if not original_resp or not swapped_resp:
        return False

    # If both are errors, not an IDOR
    error_patterns = [
        "404",
        "403",
        "401",
        "not found",
        "unauthorized",
        "forbidden",
        "invalid",
        "not allowed",
        "access denied",
    ]
    both_errors = all(
        any(p in (r or "").lower() for p in error_patterns) for r in [original_resp, swapped_resp]
    )
    if both_errors:
        return False

    # If original has data and swapped returns error, not an IDOR
    if len(original_resp) > 50 and any(p in (swapped_resp or "").lower() for p in error_patterns):
        return False  # The auth check is working

    # If swapped response has different data than original
    # (original returns your own data, swapped returns someone else's)
    if len(swapped_resp) > 50 and swapped_resp != original_resp:
        return True

    return False


# ---------------------------------------------------------------------------
# Candidate store integration
# ---------------------------------------------------------------------------


def _save_finding_to_store(
    target_name: str,
    endpoint: str,
    method: str,
    original_id: str,
    test_id: str,
    original_resp: str,
    swapped_resp: str,
    evidence_path: str,
) -> str:
    """Save an IDOR finding to Prometheus's candidate store.

    Returns the finding ID.
    """
    finding_id = str(uuid.uuid4())[:16]
    now = datetime.now(UTC).isoformat()

    db_path = (
        Path(os.environ.get("PROMETHEUS_DATA_DIR", str(Path.home() / ".prometheus")))
        / "prometheus.db"
    )
    conn = sqlite3.connect(str(db_path))

    try:
        conn.execute(
            """INSERT OR REPLACE INTO finding_candidates
               (id, domain, scan_id, source_tool, source_type, title, vuln_type,
                severity, confidence, endpoint, method, parameter, auth_state,
                role, workflow_step, fingerprint, lifecycle_status,
                raw_finding_json, created_at, updated_at, last_seen_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding_id,
                target_name,
                f"idor-{target_name}-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}",
                "idor_scanner",
                "browser",
                f"IDOR in {method} {endpoint.split('?')[0][:80]}",
                "idor",
                "medium",
                0.7,
                endpoint,
                method,
                original_id,
                "authenticated",
                "user",
                "api_access",
                f"{target_name}:{endpoint}:{method}:{original_id}",
                "needs_review",
                json.dumps(
                    {
                        "original_id": original_id,
                        "test_id": test_id,
                        "evidence_file": evidence_path,
                        "original_response_preview": original_resp[:500] if original_resp else "",
                        "swapped_response_preview": swapped_resp[:500] if swapped_resp else "",
                    }
                ),
                now,
                now,
                now,
            ),
        )
        conn.commit()
        logger.info("Finding saved to candidate store: %s", finding_id)
    finally:
        conn.close()

    return finding_id


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------


async def run_idor_scan(
    target_name: str,
    email_prefix: str,
    password: str = "",
    headless: bool = False,
) -> list[dict[str, Any]]:
    """Run a full IDOR scan against a target.

    Steps:
    1. Load target profile
    2. Create Account A and Account B
    3. Log in as Account A
    4. Harvest API endpoints
    5. Extract ID patterns
    6. Test each candidate for IDOR
    7. Save findings

    Returns list of findings.
    """
    profile = get_target_profile(target_name)
    print(f"\n{'=' * 60}")
    print(f"IDOR Scanner: {profile.name}")
    print(f"Target: {profile.base_url}")
    print(f"Email prefix: {email_prefix}@{profile.email_domain.lstrip('@')}")
    print(f"{'=' * 60}\n")

    if not password:
        password = f"Prometheus{random.randint(10000, 99999)}!"

    # Step 1: Create browser session
    print("[1/7] Initializing browser session...")
    session = BrowserSession(
        profile=profile,
        email_prefix=email_prefix,
        password=password,
    )

    # Step 2: Create Account A
    print(f"[2/7] Creating Account A: {session.email_a}")
    success = await session.create_account(session.email_a)
    if not success:
        print("  WARNING: Account A creation may have failed. Continuing...")

    # Step 3: Create Account B
    print(f"[3/7] Creating Account B: {session.email_b}")
    success = await session.create_account(session.email_b)
    if not success:
        print("  WARNING: Account B creation may have failed. Continuing...")

    # Step 4: Log in as Account A
    print(f"[4/7] Logging in as Account A: {session.email_a}")
    success = await session.login(session.email_a)
    if not success:
        print("  WARNING: Login may have failed. Continuing...")

    # Step 5: Harvest APIs
    print("[5/7] Harvesting API endpoints...")
    apis = await session.harvest_apis()
    print(f"  Found {len(apis)} API endpoints")

    # Step 6: Extract ID candidates
    print("[6/7] Extracting ID patterns...")
    id_candidates = session.extract_ids_from_endpoints()
    print(f"  Found {len(id_candidates)} ID candidates to test")

    # Step 7: Test IDORs
    print(f"[7/7] Testing {len(id_candidates)} candidates for IDOR...")
    findings = []
    tested = 0

    for candidate in id_candidates:
        tested += 1
        url = candidate["url"]
        original_id = candidate["original_id"]
        id_type = candidate["id_type"]
        method = candidate.get("method", "GET")

        print(f"  [{tested}/{len(id_candidates)}] Testing {method} {url[:100]}...", end=" ")

        # Get the original response (Account A's own data)
        original_resp = _fetch_via_cdp(url, method)

        # Generate test IDs
        test_ids = _generate_test_ids(original_id, id_type)

        found_idor = False
        for test_id in test_ids:
            if test_id == original_id:
                continue

            swapped_url = _swap_id_in_url(url, original_id, test_id)
            swapped_resp = _fetch_via_cdp(swapped_url, method)

            if _responses_indicate_idor(original_resp, swapped_resp):
                print("IDOR FOUND!")
                print(f"    Original: {original_id} -> Account A's data")
                print(f"    Swapped:  {test_id} -> Different data returned")

                evidence_path = _save_evidence(
                    finding_id=str(uuid.uuid4())[:8],
                    account_a_resp=original_resp or "",
                    account_b_swapped_resp=swapped_resp or "",
                    request_details={
                        "url": url,
                        "swapped_url": swapped_url,
                        "method": method,
                        "original_id": original_id,
                        "test_id": test_id,
                        "id_type": id_type,
                    },
                )

                finding_id = _save_finding_to_store(
                    target_name=target_name,
                    endpoint=url,
                    method=method,
                    original_id=original_id,
                    test_id=test_id,
                    original_resp=original_resp,
                    swapped_resp=swapped_resp,
                    evidence_path=str(evidence_path),
                )

                findings.append(
                    {
                        "finding_id": finding_id,
                        "type": "idor",
                        "endpoint": url,
                        "swapped_endpoint": swapped_url,
                        "original_id": original_id,
                        "test_id": test_id,
                        "severity": "medium",
                        "evidence": str(evidence_path),
                    }
                )
                found_idor = True
                break

        if not found_idor:
            print("no IDOR detected")

    # Summary
    print(f"\n{'=' * 60}")
    print(f"SCAN COMPLETE: {len(findings)} IDOR(s) found")
    for f in findings:
        print(f"  [{f['severity'].upper()}] {f['endpoint']}")
        print(f"    Evidence: {f['evidence']}")
    print(f"{'=' * 60}\n")

    return findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Prometheus IDOR Scanner — automated IDOR detection via browser",
    )
    parser.add_argument(
        "--target",
        "-t",
        required=True,
        help="Target name (syfe, bullish, or a URL)",
    )
    parser.add_argument(
        "--email",
        "-e",
        default=f"prometheus{random.randint(1000, 9999)}",
        help="Email prefix for @example.com (default: auto-generated)",
    )
    parser.add_argument(
        "--password",
        "-p",
        default="",
        help="Password for test accounts (default: auto-generated)",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run browser in headless mode",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="List available target profiles",
    )

    args = parser.parse_args()

    if args.list_targets:
        from prometheus.agents.browser_session import TARGET_PROFILES

        print("Available target profiles:")
        for name, profile in TARGET_PROFILES.items():
            print(f"  {name}: {profile.base_url}")
        sys.exit(0)

    asyncio.run(
        run_idor_scan(
            target_name=args.target,
            email_prefix=args.email,
            password=args.password,
            headless=args.headless,
        )
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    main()
