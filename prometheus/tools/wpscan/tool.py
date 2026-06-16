"""WPScan runner for Prometheus — WordPress vulnerability scanner behind Tor.

Runs inside the Docker sandbox via session.exec().  The WPScan install in the
Docker image has its one DNS leak (IPSocket.getaddress in web_site.rb) patched
at build time, and all requests go through Tor's SOCKS5h proxy.

Usage (imported by prometheus.core.runner, not run directly):
    from prometheus.tools.wpscan.tool import run_wpscan
    results = await run_wpscan(session, "https://example.com", "/workspace")
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Tor SOCKS5h proxy reachable from inside Docker sandbox
TOR_PROXY = "socks5h://[IP_ADDRESS]:9050"

# WPScan enumeration flags — covers all useful WP items
ENUM_FLAGS = "vp,vt,tt,cb,dbe,u,m"  # vuln plugins, vuln themes, timthumbs, config backups, db exports, users, media


async def run_wpscan(
    session: Any,
    target_url: str,
    output_dir: str = "/workspace",
    timeout: int = 600,
) -> dict[str, Any]:
    """Run WPScan against *target_url* inside the Docker sandbox through Tor.

    Returns parsed JSON results dict, or an error dict on failure.
    """
    domain = target_url.split("/")[2] if "//" in target_url else target_url
    output_path = f"{output_dir}/wpscan_{domain.replace('.', '_')}.json"

    cmd = (
        f"wpscan --url {target_url} "
        f"--proxy {TOR_PROXY} "
        f"--random-user-agent "
        f"--no-update "
        f"--disable-tls-checks "
        f"--format json "
        f"-o {output_path} "
        f"-e {ENUM_FLAGS} "
        f"--max-threads 3 "
        f"--request-timeout 30 "
        f"--connect-timeout 15 "
        f"2>&1"
    )

    logger.info("WPScan: running against %s through Tor (timeout=%ds)", target_url, timeout)
    logger.debug("WPScan command: %s", cmd)

    try:
        result = await session.exec("sh", "-c", cmd, timeout=timeout)
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""

        # Try to read JSON output file
        read_cmd = f"cat {output_path} 2>/dev/null || echo '{{}}'"
        read_result = await session.exec("sh", "-c", read_cmd, timeout=10)
        raw_json = read_result.stdout.decode("utf-8", errors="replace")

        if raw_json and raw_json.strip():
            try:
                parsed = json.loads(raw_json)
                parsed["_raw_stdout"] = stdout[:2000]
                parsed["_raw_stderr"] = stderr[:1000]
                parsed["_exit_code"] = result.exit_code if hasattr(result, "exit_code") else 0
                logger.info(
                    "WPScan: completed against %s (exit=%s, findings=%d)",
                    target_url,
                    parsed.get("_exit_code"),
                    _count_findings(parsed),
                )
                return parsed
            except json.JSONDecodeError:
                logger.warning("WPScan: JSON parse failed for %s, using stdout", target_url)

        return {
            "error": True,
            "message": "No WPScan JSON output produced",
            "_raw_stdout": stdout[:2000],
            "_raw_stderr": stderr[:1000],
            "_exit_code": result.exit_code if hasattr(result, "exit_code") else -1,
        }

    except Exception as exc:
        logger.error("WPScan: execution failed for %s: %s", target_url, exc)
        return {
            "error": True,
            "message": str(exc),
            "target_url": target_url,
        }


def parse_wpscan_results(
    wpscan_data: dict[str, Any],
    domain: str,
) -> list[dict[str, Any]]:
    """Parse WPScan JSON output into structured finding entries.

    Each entry has: type, title, severity, location, detail, raw.
    Returns list suitable for saving to KnowledgeStore or injecting into
    the scan root task.
    """
    findings: list[dict[str, Any]] = []

    if wpscan_data.get("error"):
        findings.append(
            {
                "type": "error",
                "domain": domain,
                "title": "WPScan execution error",
                "detail": wpscan_data.get("message", "Unknown error"),
                "severity": "info",
            }
        )
        return findings

    # --- WordPress version ---
    version_info = wpscan_data.get("version", {})
    if version_info:
        version_number = version_info.get("number", "unknown")
        status = "outdated" if version_info.get("status") == "outdated" else "current"
        findings.append(
            {
                "type": "wordpress_version",
                "domain": domain,
                "title": f"WordPress {version_number} ({status})",
                "location": version_info.get("found_by", ""),
                "severity": "high" if status == "outdated" else "info",
                "detail": json.dumps(version_info, ensure_ascii=False)[:2000],
                "raw": version_info,
            }
        )
        # Individual vulnerabilities for outdated version
        for vuln in version_info.get("vulnerabilities", []):
            findings.append(
                {
                    "type": "vulnerability",
                    "domain": domain,
                    "title": f"[WP {version_number}] {vuln.get('title', 'Unknown vulnerability')}",
                    "location": f"WordPress {version_number}",
                    "severity": _cvss_to_severity(vuln),
                    "detail": json.dumps(vuln, ensure_ascii=False)[:2000],
                    "raw": vuln,
                    "references": vuln.get("references", {}),
                    "cve": _extract_cve(vuln),
                }
            )

    # --- Plugins ---
    for plugin_name, plugin_data in wpscan_data.get("plugins", {}).items():
        plugin_status = plugin_data.get("status", "unknown")
        plugin_version = plugin_data.get("version", {})
        version_number = plugin_version.get("number", "unknown") if plugin_version else "unknown"

        findings.append(
            {
                "type": "plugin",
                "domain": domain,
                "title": f"Plugin: {plugin_name} v{version_number} ({plugin_status})",
                "location": plugin_data.get("found_by", ""),
                "severity": "medium" if plugin_status == "outdated" else "low",
                "detail": json.dumps(plugin_data, ensure_ascii=False)[:2000],
                "raw": plugin_data,
            }
        )

        for vuln in plugin_data.get("vulnerabilities", []):
            findings.append(
                {
                    "type": "vulnerability",
                    "domain": domain,
                    "title": f"[Plugin {plugin_name}] {vuln.get('title', 'Unknown vulnerability')}",
                    "location": f"/wp-content/plugins/{plugin_name}/",
                    "severity": _cvss_to_severity(vuln),
                    "detail": json.dumps(vuln, ensure_ascii=False)[:2000],
                    "raw": vuln,
                    "references": vuln.get("references", {}),
                    "cve": _extract_cve(vuln),
                }
            )

    # --- Themes ---
    for theme_name, theme_data in wpscan_data.get("themes", {}).items():
        theme_status = theme_data.get("status", "unknown")
        theme_version = theme_data.get("version", {})
        version_number = theme_version.get("number", "unknown") if theme_version else "unknown"

        findings.append(
            {
                "type": "theme",
                "domain": domain,
                "title": f"Theme: {theme_name} v{version_number} ({theme_status})",
                "location": theme_data.get("found_by", ""),
                "severity": "medium" if theme_status == "outdated" else "low",
                "detail": json.dumps(theme_data, ensure_ascii=False)[:2000],
                "raw": theme_data,
            }
        )

        for vuln in theme_data.get("vulnerabilities", []):
            findings.append(
                {
                    "type": "vulnerability",
                    "domain": domain,
                    "title": f"[Theme {theme_name}] {vuln.get('title', 'Unknown vulnerability')}",
                    "location": f"/wp-content/themes/{theme_name}/",
                    "severity": _cvss_to_severity(vuln),
                    "detail": json.dumps(vuln, ensure_ascii=False)[:2000],
                    "raw": vuln,
                    "references": vuln.get("references", {}),
                    "cve": _extract_cve(vuln),
                }
            )

    # --- Users ---
    for user in wpscan_data.get("users", []):
        findings.append(
            {
                "type": "user",
                "domain": domain,
                "title": f"User: {user.get('username', 'unknown')} (ID: {user.get('id', '?')})",
                "location": user.get("found_by", ""),
                "severity": "medium",
                "detail": json.dumps(user, ensure_ascii=False)[:1000],
                "raw": user,
            }
        )

    # --- Interesting findings ---
    for finding in wpscan_data.get("interesting_findings", []):
        findings.append(
            {
                "type": "interesting_finding",
                "domain": domain,
                "title": finding.get("name", "Interesting finding"),
                "location": finding.get("url", ""),
                "severity": finding.get("severity", "info"),
                "detail": json.dumps(finding, ensure_ascii=False)[:2000],
                "raw": finding,
            }
        )

    # --- Config backups / DB exports ---
    for cb_type, cb_key in [("config_backup", "config_backups"), ("db_export", "db_exports")]:
        for item in wpscan_data.get(cb_key, []):
            findings.append(
                {
                    "type": cb_type,
                    "domain": domain,
                    "title": item.get("name", f"{cb_type} found"),
                    "location": item.get("url", ""),
                    "severity": "critical" if cb_type == "db_export" else "high",
                    "detail": json.dumps(item, ensure_ascii=False)[:2000],
                    "raw": item,
                }
            )

    # --- Timthumbs ---
    for timthumb in wpscan_data.get("timthumbs", []):
        findings.append(
            {
                "type": "timthumb",
                "domain": domain,
                "title": "TimThumb script found",
                "location": timthumb.get("url", ""),
                "severity": "medium",
                "detail": json.dumps(timthumb, ensure_ascii=False)[:2000],
                "raw": timthumb,
            }
        )

    return findings


def findings_to_knowledge_entries(
    findings: list[dict[str, Any]],
    domain: str,
    scan_id: str | None = None,
) -> list[dict[str, Any]]:
    """Convert parsed WPScan findings to KnowledgeStore-compatible entries."""
    entries: list[dict[str, Any]] = []
    seen_vulns: set[str] = set()

    for f in findings:
        # Only save high/critical vulnerabilities and user enumerations to knowledge store
        if f["type"] == "vulnerability" and f["severity"] in ("critical", "high", "medium"):
            dedup_key = f["title"][:120]  # truncate long titles for dedup
            if dedup_key not in seen_vulns:
                seen_vulns.add(dedup_key)
                entries.append(
                    {
                        "domain": domain,
                        "category": "vulnerability",
                        "key": f["title"],
                        "value": (
                            f"Severity: {f['severity']} | "
                            f"Location: {f['location']} | "
                            f"CVE: {f.get('cve', 'N/A')} | "
                            f"Detail: {f['detail'][:500]}"
                        ),
                        "confidence": 0.85,
                        "source": "wpscan",
                        "scan_id": scan_id,
                    }
                )

        elif f["type"] == "user":
            entries.append(
                {
                    "domain": domain,
                    "category": "vulnerability",
                    "key": f"WP User: {f['title']}",
                    "value": f"Location: {f['location']} | Detail: {f['detail'][:500]}",
                    "confidence": 0.9,
                    "source": "wpscan",
                    "scan_id": scan_id,
                }
            )

        elif f["type"] in ("config_backup", "db_export") and f["severity"] in ("critical", "high"):
            entries.append(
                {
                    "domain": domain,
                    "category": "vulnerability",
                    "key": f["title"],
                    "value": f"URL: {f['location']} | Detail: {f['detail'][:500]}",
                    "confidence": 0.95,
                    "source": "wpscan",
                    "scan_id": scan_id,
                }
            )

    return entries


def build_wpscan_context_block(
    wpscan_data: dict[str, Any],
    domain: str,
) -> str:
    """Build a human-readable context block for the root task prompt."""
    if wpscan_data.get("error"):
        return (
            f"--- WPScan for {domain} ---\nFAILED: {wpscan_data.get('message', 'Unknown error')}\n"
        )

    findings = parse_wpscan_results(wpscan_data, domain)
    if not findings:
        return f"--- WPScan for {domain} ---\nNo findings detected.\n"

    lines: list[str] = [
        f"--- WPScan for {domain} ---",
        f"WPScan found {len(findings)} items on this WordPress site.",
        "",
    ]

    # Group by severity
    by_severity: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        by_severity.setdefault(f["severity"], []).append(f)

    for severity in ("critical", "high", "medium", "low", "info"):
        items = by_severity.get(severity, [])
        if not items:
            continue
        lines.append(f"[{severity.upper()}] — {len(items)} item(s):")
        for item in items:
            cve_str = f" ({item.get('cve', '')})" if item.get("cve") else ""
            lines.append(f"  - {item['title']}{cve_str}")
        lines.append("")

    # Add version info
    version_info = wpscan_data.get("version", {})
    if version_info:
        vnum = version_info.get("number", "?")
        vstatus = version_info.get("status", "?")
        lines.append(f"WordPress version: {vnum} ({vstatus})")

    # Add plugin/theme summary
    plugins = wpscan_data.get("plugins", {})
    themes = wpscan_data.get("themes", {})
    users = wpscan_data.get("users", [])
    lines.append(f"Plugins detected: {len(plugins)}")
    lines.append(f"Themes detected: {len(themes)}")
    lines.append(f"Users enumerated: {len(users)}")

    return "\n".join(lines)


# --- Internal helpers ---


def _count_findings(data: dict[str, Any]) -> int:
    return (
        sum(len(v.get("vulnerabilities", [])) for v in data.get("plugins", {}).values())
        + sum(len(v.get("vulnerabilities", [])) for v in data.get("themes", {}).values())
        + len(data.get("version", {}).get("vulnerabilities", []))
        + len(data.get("users", []))
        + len(data.get("interesting_findings", []))
        + len(data.get("config_backups", []))
        + len(data.get("db_exports", []))
        + len(data.get("timthumbs", []))
    )


def _cvss_to_severity(vuln: dict[str, Any]) -> str:
    cvss = vuln.get("cvss", {}) or {}
    score = cvss.get("score")
    if score is None:
        score = vuln.get("cvss_score")
    if score is not None:
        try:
            score = float(score)
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            if score >= 0.1:
                return "low"
            return "info"
        except (ValueError, TypeError):
            pass
    # Fall back to WPScan's own severity label
    wp_sev = (vuln.get("severity") or "").lower()
    sev_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    return sev_map.get(wp_sev, "medium")


def _extract_cve(vuln: dict[str, Any]) -> str | None:
    refs = vuln.get("references", {}) or {}
    cves = refs.get("cve", []) or refs.get("CVE", [])
    if cves:
        return cves[0] if isinstance(cves, list) else str(cves)
    return None
