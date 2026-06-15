"""Agent-facing knowledge tools for cross-scan learning.

These tools let the prometheus agent persist and retrieve facts across scans.
Knowledge lives in ``~/.prometheus/prometheus.db`` and survives process
restarts, making subsequent scans against the same target smarter.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

from prometheus.tools.knowledge.store import KnowledgeStore


logger = logging.getLogger(__name__)


def _store() -> KnowledgeStore:
    return KnowledgeStore()


# ------------------------------------------------------------------
# Tools
# ------------------------------------------------------------------


@function_tool(timeout=60)
async def save_knowledge(
    ctx: RunContextWrapper,
    target_id: str,
    category: str,
    key: str,
    value: str,
    confidence: float = 0.8,
    source: str = "scan",
) -> str:
    """Persist a fact about a target domain for future scans.

    Use this to store anything you discover that would be useful in
    later scans: tech stacks, endpoints, auth mechanisms, successful
    techniques, failed approaches, or confirmed vulnerabilities.

    Categories (``category`` parameter):
    - ``tech_stack`` — frameworks, languages, CMS, server software.
    - ``endpoint`` — API routes, interesting URLs, parameter names.
    - ``auth_mechanism`` — OAuth flows, session cookie names, token types.
    - ``vulnerability`` — confirmed issues with reproduction details.
    - ``failed_approach`` — things that didn't work (save future time).
    - ``successful_technique`` — payloads or methods that succeeded.
    - ``tor_status`` — whether target rejects Tor connections. Use key=``tor_rejected``, value=``true`` or ``false`` plus details.

    Args:
        target_id: Target domain or identifier (e.g. ``example.com``).
        category: One of the categories listed above.
        key: Short label (e.g. ``framework``, ``/api/v1/login``).
        value: Full detail — be descriptive so a future scan benefits.
        confidence: 0.0–1.0 how certain you are. Default 0.8.
        source: Where this came from (``scan``, ``manual``, ``nuclei``…).
    """
    try:
        result = await asyncio.to_thread(
            _store().store,
            domain=target_id,
            category=category,
            key=key,
            value=value,
            confidence=confidence,
            source=source,
            scan_id=None,
        )
    except Exception as exc:
        logger.exception("save_knowledge failed")
        result = {"success": False, "error": str(exc)}

    # Auto-trigger CVE lookup when category is "tech_stack"
    cve_findings = None
    if category == "tech_stack" and result.get("success", True):
        cve_findings = await _auto_cve_lookup(target_id, key, value)
        if cve_findings:
            # Store CVE results as knowledge entries
            for cve in cve_findings:
                try:
                    cve_key = cve.get("cve_id", "unknown")
                    cve_value = (
                        f"Severity: {cve.get('severity', 'N/A')} | "
                        f"CVSS: {cve.get('cvss_score', 'N/A')} | "
                        f"EPSS: {cve.get('epss_score', 'N/A')} | "
                        f"Exploit: {'yes' if cve.get('has_exploit') else 'no'} | "
                        f"Source: {cve.get('source', 'N/A')} | "
                        f"Desc: {cve.get('description', '')[:200]}"
                    )
                    await asyncio.to_thread(
                        _store().store,
                        domain=target_id,
                        category="auto_cve_lookup",
                        key=cve_key,
                        value=cve_value,
                        confidence=0.7,
                        source="auto_cve_lookup",
                        scan_id=None,
                    )
                except Exception as exc:
                    logger.warning("Failed to store CVE finding: %s", exc, exc_info=True)

    response = {"knowledge_stored": result}
    if cve_findings:
        response["auto_cve_findings"] = cve_findings
        response["auto_cve_count"] = len(cve_findings)
    return json.dumps(response, ensure_ascii=False, default=str)


async def _auto_cve_lookup(
    domain: str, tech_key: str, tech_value: str
) -> list[dict[str, Any]] | None:
    """Parse technology/version from a tech_stack value and query threats.

    Returns list of CVE dicts or None if no lookup was possible.
    """
    import re as _re

    try:
        from prometheus.tools.threat_intel.query_engine import query_threats

        # Try to extract technology and version from key/value
        # Common patterns:
        #   key="framework", value="next.js 14.2.0"
        #   key="server", value="nginx/1.24.0"
        #   key="express", value="4.17.1"
        #   key="next.js", value="14.2.0"

        technology = ""
        version = ""

        # Guard: reject values that are clearly descriptions, not tech names
        # (long strings with many words, sentences, etc.)
        value_stripped = tech_value.strip()
        if len(value_stripped) > 100:
            logger.debug(
                "Auto CVE lookup: value too long (%d chars), likely description, skipping",
                len(value_stripped),
            )
            return None

        word_count = len(value_stripped.split())
        if word_count > 8:
            logger.debug(
                "Auto CVE lookup: value has %d words, likely description, skipping", word_count
            )
            return None

        # Guard: reject keys that look like descriptions too
        key_stripped = tech_key.strip()
        if len(key_stripped) > 60 or len(key_stripped.split()) > 5:
            logger.debug("Auto CVE lookup: key too long/complex, likely description, skipping")
            return None

        # Try to split value by common separators to find version
        # Pattern: "tech_name version" or "tech_name/version"
        for sep in ["/", " "]:
            if sep in tech_value:
                parts = tech_value.split(sep, 1)
                potential_tech = parts[0].strip()
                potential_ver = parts[1].strip()
                # Check if the second part looks like a version (starts with digit)
                if potential_ver and _re.match(r"^[\d]", potential_ver):
                    technology = potential_tech
                    version = potential_ver
                    break

        # If key itself looks like a tech name and value looks like a version
        if not technology:
            if _re.match(r"^[\d]", tech_value.strip()):
                technology = tech_key
                version = tech_value.strip()
            else:
                # Use value as technology, no version
                technology = tech_value.strip()

        if not technology:
            return None

        # Guard: validate technology looks like a real tech name
        if len(technology) > 60 or len(technology.split()) > 4:
            logger.debug(
                "Auto CVE lookup: extracted technology '%s' too long/complex, skipping",
                technology[:60],
            )
            return None

        # Clean up version (remove trailing garbage)
        if version:
            # Strip things like " LTS", " (current)", etc.
            version = _re.split(r"[,;\s(]", version)[0].strip()

        logger.info("Auto CVE lookup for %s: tech=%s, version=%s", domain, technology, version)

        fingerprints = [{"technology": technology, "version": version}]
        result = await query_threats(fingerprints)

        if not result.get("success") or not result.get("results"):
            return None

        # Collect all vulnerabilities from all results
        all_vulns = []
        for tech_result in result["results"]:
            for vuln in tech_result.get("vulnerabilities", []):
                all_vulns.append(vuln)

        return all_vulns if all_vulns else None

    except Exception as exc:
        logger.warning(
            "Auto CVE lookup failed for %s/%s: %s", tech_key, tech_value, exc, exc_info=True
        )
        return None


@function_tool(timeout=30)
async def query_knowledge(
    ctx: RunContextWrapper,
    target_id: str,
    category: str | None = None,
) -> str:
    """Retrieve previously stored knowledge for a target.

    Call this at the start of a scan to load prior findings. Filter by
    category to narrow results (e.g. only ``tech_stack`` or
    ``vulnerability``).

    Args:
        target_id: Target domain to query.
        category: Optional filter — one of ``tech_stack``, ``endpoint``,
            ``auth_mechanism``, ``vulnerability``, ``failed_approach``,
            ``successful_technique``, ``tor_status``.
    """
    try:
        entries = await asyncio.to_thread(
            _store().query,
            domain=target_id,
            category=category,
        )
    except Exception as exc:
        logger.exception("query_knowledge failed")
        return json.dumps({"success": False, "error": str(exc)}, default=str)
    return json.dumps(
        {"success": True, "count": len(entries), "entries": entries},
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def search_knowledge(
    ctx: RunContextWrapper,
    query: str,
) -> str:
    """Full-text search across all stored knowledge.

    Searches key and value fields across every domain. Useful for
    finding patterns (e.g. "SQL injection" or "next.js") across all
    previous scans.

    Args:
        query: Search terms. Supports FTS5 syntax (AND, OR, NOT, phrases).
    """
    try:
        entries = await asyncio.to_thread(
            _store().search,
            query_text=query,
        )
    except Exception as exc:
        logger.exception("search_knowledge failed")
        return json.dumps({"success": False, "error": str(exc)}, default=str)
    return json.dumps(
        {"success": True, "count": len(entries), "entries": entries},
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def get_target_profile(
    ctx: RunContextWrapper,
    target_id: str,
) -> str:
    """Get the full target profile for a target — scan history, consolidated
    findings, tech stack, failed approaches, and successful techniques.

    Call this at the start of a rescan to understand what was previously
    discovered and what to focus on next. The profile includes:
    - Scan history (all previous runs, their status and finding counts)
    - Knowledge grouped by category (tech_stack, endpoints, vulns, etc.)
    - Failed approaches to avoid repeating
    - Successful techniques to build on

    Args:
        target_id: Target domain or URL (e.g. "https://example.com" or "example.com").
    """
    try:
        profile = await asyncio.to_thread(
            _store().get_target_profile,
            domain=target_id,
        )
    except Exception as exc:
        logger.exception("get_target_profile failed")
        return json.dumps({"success": False, "error": str(exc)}, default=str)
    return json.dumps(
        {"success": True, **profile},
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def list_target_profiles(
    ctx: RunContextWrapper,
) -> str:
    """List all target profiles — shows every domain that has been scanned
    with summary stats (scan count, finding counts, last scan date).

    Use this to see an overview of all targets without querying a specific domain.
    """
    try:
        profiles = await asyncio.to_thread(
            _store().list_profiles,
        )
    except Exception as exc:
        logger.exception("list_target_profiles failed")
        return json.dumps({"success": False, "error": str(exc)}, default=str)
    return json.dumps(
        {"success": True, "count": len(profiles), "profiles": profiles},
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def update_report_status(
    ctx: RunContextWrapper,
    target_id: str,
    finding_title: str,
    status: str,
    platform: str | None = None,
    report_url: str | None = None,
    h1_report_id: str | None = None,
    notes: str | None = None,
    endpoint: str | None = None,
) -> str:
    """Update the lifecycle status of a vulnerability finding.

    Use this to track what happened to a finding after the scan:
    - ``new`` — just discovered, not yet reviewed
    - ``reviewing`` — you are evaluating whether to submit
    - ``submitted`` — sent to a bug bounty platform (set ``platform`` and ``report_url``)
    - ``accepted`` — the platform accepted the report
    - ``rejected`` — the platform closed it as NA/informational
    - ``needs_info`` — platform requested more details
    - ``dismissed`` — you decided not to submit (false positive, out of scope, etc.)

    Args:
        target_id: Target domain (e.g. ``anthropic.com``).
        finding_title: The exact title of the finding.
        status: One of the statuses listed above.
        platform: Where you submitted (``hackerone``, ``bugcrowd``, ``internal``).
        report_url: URL to the submitted report.
        h1_report_id: HackerOne report ID (e.g. ``#12345``).
        notes: Your notes about this finding.
        endpoint: The affected endpoint (helps dedup if same title on different endpoints).
    """
    try:
        result = await asyncio.to_thread(
            _store().upsert_report_status,
            domain=target_id,
            scan_id="manual",
            finding_title=finding_title,
            status=status,
            platform=platform,
            report_url=report_url,
            h1_report_id=h1_report_id,
            notes=notes,
            endpoint=endpoint,
        )
    except Exception as exc:
        logger.exception("update_report_status failed")
        return json.dumps({"success": False, "error": str(exc)}, default=str)
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def get_report_details(
    ctx: RunContextWrapper,
    target_id: str,
    finding_title: str,
    endpoint: str = "",
) -> str:
    """Get full details for a specific finding — status, metadata, and related
    knowledge entries.

    Use this when you want to drill into a specific report: see its current
    status, when it was submitted, what platform, any notes, and all knowledge
    entries related to that finding.

    Args:
        target_id: Target domain (e.g. ``anthropic.com``).
        finding_title: The exact title of the finding.
        endpoint: The affected endpoint (helps locate the right entry).
    """
    try:
        report = await asyncio.to_thread(
            _store().get_report,
            domain=target_id,
            finding_title=finding_title,
            endpoint=endpoint,
        )
        if report is None:
            return json.dumps(
                {
                    "success": False,
                    "error": f"No report found for '{finding_title}' on {target_id}",
                },
                default=str,
            )

        # Also pull related knowledge entries
        knowledge = await asyncio.to_thread(
            _store().query,
            domain=target_id,
            category="vulnerability",
        )
        # Filter to entries that mention the finding title
        title_lower = finding_title.lower()
        related = [
            k
            for k in knowledge
            if title_lower in k.get("key", "").lower() or title_lower in k.get("value", "").lower()
        ]

    except Exception as exc:
        logger.exception("get_report_details failed")
        return json.dumps({"success": False, "error": str(exc)}, default=str)
    return json.dumps(
        {"success": True, "report": report, "related_knowledge": related},
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def list_reports(
    ctx: RunContextWrapper,
    target_id: str | None = None,
    status: str | None = None,
) -> str:
    """List all tracked vulnerability reports, optionally filtered.

    Use this to see what findings exist across all targets, or filter by
    target and/or status. Results are sorted by priority: new findings first,
    then reviewing, submitted, accepted/rejected.

    Args:
        target_id: Filter by target domain (e.g. ``anthropic.com``). Omit for all.
        status: Filter by status (``new``, ``reviewing``, ``submitted``,
            ``accepted``, ``rejected``, ``needs_info``, ``dismissed``). Omit for all.
    """
    try:
        reports = await asyncio.to_thread(
            _store().list_reports,
            domain=target_id,
            status=status,
        )
    except Exception as exc:
        logger.exception("list_reports failed")
        return json.dumps({"success": False, "error": str(exc)}, default=str)
    return json.dumps(
        {"success": True, "count": len(reports), "reports": reports},
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def get_findings_summary(
    ctx: RunContextWrapper,
    target_id: str | None = None,
) -> str:
    """Get an aggregate summary of all tracked vulnerability findings.

    Returns counts broken down by status (new, reviewing, submitted, accepted,
    rejected, revalidated), severity (critical, high, medium, low, info), and
    target.  Optionally scope to a single target.

    Args:
        target_id: Optional target domain to scope the summary to.
    """
    try:
        summary = await asyncio.to_thread(
            _store().get_findings_summary,
            domain=target_id,
        )
    except Exception as exc:
        logger.exception("get_findings_summary failed")
        return json.dumps({"success": False, "error": str(exc)}, default=str)
    return json.dumps({"success": True, **summary}, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def get_ready_to_submit(
    ctx: RunContextWrapper,
) -> str:
    """List all findings that are ready for bug-bounty submission.

    Returns findings with status ``new`` that have all required fields filled
    in (title, severity, endpoint, CWE, and full finding content).  Results
    are sorted by severity (critical first).

    Use this to identify which findings are complete enough to write up and
    submit to a platform like HackerOne or Bugcrowd.
    """
    try:
        findings = await asyncio.to_thread(
            _store().get_ready_to_submit,
        )
    except Exception as exc:
        logger.exception("get_ready_to_submit failed")
        return json.dumps({"success": False, "error": str(exc)}, default=str)
    return json.dumps(
        {"success": True, "count": len(findings), "findings": findings},
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def revalidate_findings(
    ctx: RunContextWrapper,
    target_id: str,
    cve_ids_json: str,
) -> str:
    """Revalidate existing findings for a target against newly discovered CVE IDs.

    Searches all tracked findings for the target and checks if any reference
    the given CVE IDs.  Matching findings have their status updated to
    ``revalidated`` and a timeline comment is logged.

    Use this after running a new vulnerability scan or threat-intel check
    that discovers new CVEs -- it will automatically flag affected findings
    that may need re-evaluation.

    Args:
        target_id: Target domain (e.g. ``example.com``).
        cve_ids_json: JSON array of CVE IDs, e.g. ``["CVE-2024-1234", "CVE-2024-5678"]``.
    """
    try:
        cve_ids: list[str] = json.loads(cve_ids_json)
        result = await asyncio.to_thread(
            _store().revalidate_findings,
            domain=target_id,
            new_cve_ids=cve_ids,
        )
    except json.JSONDecodeError as exc:
        return json.dumps({"success": False, "error": f"Invalid JSON: {exc}"}, default=str)
    except Exception as exc:
        logger.exception("revalidate_findings failed")
        return json.dumps({"success": False, "error": str(exc)}, default=str)
    return json.dumps(
        {"success": True, "count": len(result), "revalidated": result},
        ensure_ascii=False,
        default=str,
    )
