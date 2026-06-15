"""Auto-detect program from target URL and run browser prescan on ALL scoped assets."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)

DB_PATH = (
    Path(os.environ.get("PROMETHEUS_DATA_DIR", str(Path.home() / ".prometheus"))) / "prometheus.db"
)
EVIDENCE_DIR = (
    Path(os.environ.get("PROMETHEUS_DATA_DIR", str(Path.home() / ".prometheus"))) / "idor_evidence"
)
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def _get_program_scope(program_name: str) -> list[str]:
    """Get all in-scope URLs from the programs table for a given program."""
    if not DB_PATH.exists():
        return []
    try:
        conn = sqlite3.connect(str(DB_PATH))
        row = conn.execute("SELECT scope FROM programs WHERE name = ?", (program_name,)).fetchone()
        conn.close()
        if row and row[0]:
            scope = json.loads(row[0])
            return [item["value"] for item in scope if item.get("value")]
    except Exception as e:
        logger.debug("Failed to get scope for %s: %s", program_name, e)
    return []


def _base_domain(url: str) -> str:
    """Extract the base domain from a URL (scheme + hostname)."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _match_target_to_program(target_url: str) -> dict[str, Any] | None:
    """Check if a URL target matches a known program in the database.

    Returns program info dict or None.
    """
    if not DB_PATH.exists():
        return None

    try:
        conn = sqlite3.connect(str(DB_PATH))
        rows = conn.execute("SELECT name, platform, handle, url FROM programs").fetchall()
        conn.close()

        for prog_name, platform, handle, program_url in rows:
            name_key = prog_name.lower().replace(" ", "").replace("/", "-")

            # Check by handle or name in URL
            if handle and handle in target_url:
                return {
                    "name": prog_name,
                    "platform": platform,
                    "handle": handle,
                    "url": program_url,
                }
            if name_key in target_url.lower():
                return {
                    "name": prog_name,
                    "platform": platform,
                    "handle": handle,
                    "url": program_url,
                }

            # Check scope JSON
            try:
                conn2 = sqlite3.connect(str(DB_PATH))
                scope_row = conn2.execute(
                    "SELECT scope FROM programs WHERE name = ?", (prog_name,)
                ).fetchone()
                conn2.close()
                if scope_row and scope_row[0]:
                    scope = json.loads(scope_row[0])
                    for item in scope:
                        val = item.get("value", "")
                        if val and val.rstrip("/") in target_url.rstrip("/"):
                            return {
                                "name": prog_name,
                                "platform": platform,
                                "handle": handle,
                                "url": program_url,
                            }
            except Exception:
                continue

    except Exception as e:
        logger.debug("Program lookup failed: %s", e)

    return None


def _derive_email(handle: str, platform: str) -> str:
    """Derive the email alias from handle and platform.

    Defaults to ``@example.com`` so demo accounts don't accidentally
    resolve to a real platform address. Override per-program via the
    ``email_domain`` field on a ``TargetProfile`` (see
    ``target_profiles.py``).
    """
    if platform == "bugcrowd":
        return f"{handle}@example.com"
    elif platform == "hackerone":
        return f"{handle}@example.com"
    return f"{handle}@example.com"


def _lightweight_scan(url: str, findings: list) -> None:
    """Quick HTTP-level checks for non-browser targets (streams, APIs, docs).

    Tests:
    - Unauthenticated access (does the endpoint return data without cookies?)
    - CORS misconfiguration (Access-Control-Allow-Origin: *)
    - Information disclosure in response headers
    """
    print(f"    Lightweight scan: {url}")

    try:
        resp = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Prometheus/1.0"},
            allow_redirects=True,
        )

        # Check CORS
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            findings.append(
                {
                    "type": "cors_misconfiguration",
                    "url": url,
                    "detail": "Access-Control-Allow-Origin: *",
                    "severity": "low",
                }
            )
            print(f"      CORS: Access-Control-Allow-Origin: *")

        # Check for data returned without auth
        if resp.status_code == 200 and len(resp.text) > 100:
            # Check if response contains sensitive-sounding data
            sensitive_keywords = [
                "user",
                "email",
                "token",
                "api_key",
                "secret",
                "password",
                "internal",
                "private",
                "config",
            ]
            text_lower = resp.text.lower()
            found = [kw for kw in sensitive_keywords if kw in text_lower]
            if found:
                findings.append(
                    {
                        "type": "information_disclosure",
                        "url": url,
                        "detail": f"Potential info disclosure: {', '.join(found)}",
                        "severity": "medium",
                    }
                )
                print(f"      Potential info disclosure: {', '.join(found)}")

    except requests.exceptions.Timeout:
        print(f"      Timeout")
    except Exception as e:
        print(f"      Error: {e}")


def run_browser_prescan(targets_info: list[dict[str, Any]], args: Any = None) -> list[str]:
    """Run browser-based prescan across ALL in-scope assets for each matched program.

    For main web apps: full authenticated browser scan (IDOR, API harvesting).
    For other assets (streams, APIs, docs): lightweight HTTP-level checks.

    Zero LLM token usage. Findings saved to candidate store automatically.

    Returns list of ALL target URLs to scan (expanded from program scope).
    Used by main.py to expand the main scan's target list.
    """
    all_findings = []
    all_scope_urls: list[str] = []

    for target_info in targets_info:
        if target_info.get("type") != "url":
            continue

        original = target_info.get("original", "")
        if not original:
            continue

        program = _match_target_to_program(original)
        if not program:
            logger.info("No matching program for %s, skipping browser prescan", original)
            continue

        name = program["name"]
        handle = program["handle"]
        platform = program["platform"]
        email = _derive_email(handle, platform)

        logger.info("Browser prescan: %s (%s) -> %s", name, platform, email)
        print(f"\n=== Browser prescan: {name} ({platform}) ===")
        print(f"   Email alias: {email}")

        # Get ALL in-scope URLs from the program entry
        scope_urls = _get_program_scope(name)
        if not scope_urls:
            scope_urls = [original]

        print(f"   In-scope assets: {len(scope_urls)}")
        for u in scope_urls:
            print(f"     - {u}")

        # Collect all unique scope URLs for main scan expansion
        for u in scope_urls:
            domain_key = _base_domain(u).rstrip("/")
            if domain_key not in all_scope_urls:
                all_scope_urls.append(domain_key)

        # Run browser scan on the MAIN web app URL
        profile_key = name.lower().replace(" ", "-").replace("/", "-")
        main_url = scope_urls[0] if scope_urls else original

        print(f"\n   [Browser] Web app scan: {main_url}")
        try:
            from prometheus.tools.idor_scanner.tool import run_idor_scan
            import asyncio

            browser_findings = asyncio.run(
                run_idor_scan(
                    target_name=profile_key,
                    email_prefix=handle,
                )
            )
            all_findings.extend(browser_findings)
            print(f"   Browser scan: {len(browser_findings)} finding(s)")
        except Exception as e:
            logger.warning("Browser scan failed for %s: %s", profile_key, e)
            print(f"   Browser scan failed: {e}")

        # Lightweight scan on remaining scope URLs (different domains)
        scanned_domains = set()
        for scope_url in scope_urls[1:]:
            domain = _base_domain(scope_url)
            if domain in scanned_domains:
                continue
            scanned_domains.add(domain)

            if domain.rstrip("/") != _base_domain(main_url).rstrip("/"):
                print(f"\n   [HTTP] Lightweight scan: {domain}")
                sub_findings = []
                _lightweight_scan(domain, sub_findings)
                for f in sub_findings:
                    all_findings.append(f)
                    # Save to candidate store
                    _save_finding(name, f)
                print(f"   Lightweight scan: {len(sub_findings)} finding(s)")

    if all_findings:
        print(f"\n=== Prescan complete: {len(all_findings)} total finding(s) ===")
    else:
        print(f"\n=== Prescan complete: no findings ===")

    return all_scope_urls


def _save_finding(program_name: str, finding: dict[str, Any]) -> None:
    """Save a lightweight finding to the candidate store."""
    import uuid
    from datetime import UTC, datetime

    finding_id = str(uuid.uuid4())[:16]
    now = datetime.now(UTC).isoformat()
    vuln_type = finding.get("type", "unknown")
    severity = finding.get("severity", "low")

    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute(
            """INSERT OR REPLACE INTO finding_candidates
               (id, domain, scan_id, source_tool, source_type, title, vuln_type,
                severity, confidence, endpoint, method, parameter, auth_state,
                role, workflow_step, fingerprint, lifecycle_status,
                raw_finding_json, created_at, updated_at, last_seen_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding_id,
                program_name,
                f"prescan-{program_name}-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}",
                "browser_prescan",
                "http",
                finding.get("detail", f"{vuln_type} on {finding.get('url', '?')}")[:200],
                vuln_type,
                severity,
                0.6,
                finding.get("url", ""),
                "GET",
                "",
                "unauthenticated",
                "anonymous",
                "discovery",
                f"{program_name}:{finding.get('url', '')}:{vuln_type}",
                "needs_review",
                json.dumps(finding),
                now,
                now,
                now,
            ),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.debug("Failed to save finding: %s", e)
