"""Local-first threat intelligence query engine.

Query flow:
1. Check local SQLite DB for matching CVEs (fast, free, offline)
2. For fingerprints with 0 local results, query online sources
3. Store online results locally for next time
4. Merge, deduplicate, score, return
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

from prometheus.tools.threat_intel.local_db import ThreatIntelDB
from prometheus.tools.threat_intel.tool import (
    _ECOSYSTEM_MAP,
    _get_github_token,
    _guess_ecosystem,
)


logger = logging.getLogger(__name__)


# Phase 1D: the audit found 19 NVD, 30 VulnerableCode, and many CIRCL
# failures all stemming from one root cause — the agent's free-form
# fingerprint text was being passed verbatim as the search term to
# online APIs, producing 200+ char `?purl=pkg:npm/...` URLs that the
# APIs rejected. ``slugify_tech`` reduces each fingerprint to a short
# slug (max 64 chars, alphanumeric+dash) before any online call.
_SLUG_MAX_LEN = 64
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")
_FALLBACK_TOKEN_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9._-]*")


def slugify_tech(tech: str) -> str:
    """Reduce a free-form technology string to a 64-char slug.

    Priority:

    1. The first CVE-like substring (``CVE-YYYY-NNNN``) — this matches
       what the agent actually wants to look up.
    2. The first 5 alphanumeric tokens of the input, lowercased and
       joined with single dashes.
    3. The original string, truncated to ``_SLUG_MAX_LEN``.

    Always returns a string that is at most ``_SLUG_MAX_LEN`` chars
    long and contains only ``[A-Za-z0-9._-]`` (safe for URL paths).
    """
    if not tech:
        return ""
    if not isinstance(tech, str):
        tech = str(tech)
    # 1. CVE id?
    m = _CVE_PATTERN.search(tech)
    if m:
        return m.group(0)
    # 2. First 5 alphanumeric tokens
    tokens = _FALLBACK_TOKEN_PATTERN.findall(tech)
    if tokens:
        slug = "-".join(t.lower() for t in tokens[:5])
        if len(slug) > _SLUG_MAX_LEN:
            slug = slug[:_SLUG_MAX_LEN].rstrip("-")
        return slug
    # 3. Truncate the original (will be re-cleaned of unsafe chars)
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", tech).strip("-")
    return cleaned[:_SLUG_MAX_LEN]


def _normalize_ecosystem(tech: str) -> str | None:
    """Map a technology name to a normalized ecosystem string."""
    tech_lower = tech.lower().strip()

    if tech_lower in _ECOSYSTEM_MAP:
        return _ECOSYSTEM_MAP[tech_lower].lower()
    for key, eco in _ECOSYSTEM_MAP.items():
        if key in tech_lower:
            return eco.lower()
    return None


def _normalize_package_name(tech: str, ecosystem: str) -> str:
    """Resolve technology name to actual package name for an ecosystem."""
    tech_lower = tech.lower().strip()
    _PKG_VARIANTS: dict[str, dict[str, str]] = {
        "next.js": {"npm": "next"},
        "nextjs": {"npm": "next"},
        "express.js": {"npm": "express"},
        "vue.js": {"npm": "vue"},
        "nuxt.js": {"npm": "nuxt"},
        "angular": {"npm": "@angular/core"},
        "laravel": {"packagist": "laravel/framework"},
        "spring": {"maven": "org.springframework"},
    }

    if tech_lower in _PKG_VARIANTS and ecosystem in _PKG_VARIANTS[tech_lower]:
        return _PKG_VARIANTS[tech_lower][ecosystem]
    return tech_lower


# ---------------------------------------------------------------------------
# New online vulnerability feed functions (no auth required)
# ---------------------------------------------------------------------------


async def _query_circl(client: Any, tech: str, version: str) -> list[dict[str, Any]]:
    """Query CIRCL Vulnerability-Lookup for CVEs matching a vendor/product."""
    # CIRCL expects vendor/product in the path; best-effort split
    tech_lower = tech.lower().strip()

    # Guard: reject overly long strings (descriptions, not tech names)
    if len(tech_lower) > 80:
        logger.debug(
            "CIRCL: tech string too long (%d chars), skipping: %s...",
            len(tech_lower),
            tech_lower[:60],
        )
        return []

    # Guard: reject strings that look like descriptions (contain spaces + long words)
    word_count = len(tech_lower.split())
    if word_count > 5:
        logger.debug(
            "CIRCL: tech string has %d words, looks like description, skipping", word_count
        )
        return []

    # Try splitting vendor/product heuristically
    parts = tech_lower.split("/", 1)
    if len(parts) == 2:
        vendor, product = parts
    else:
        # Use tech as both vendor and product
        vendor = tech_lower
        product = tech_lower

    # Sanitize: remove characters that break URL paths
    import re as _re

    vendor = _re.sub(r"[^a-z0-9._-]", "", vendor)
    product = _re.sub(r"[^a-z0-9._-]", "", product)
    if not vendor or not product:
        return []

    url = f"https://cve.circl.lu/api/search/{vendor}/{product}"
    try:
        resp = await client.get(url, timeout=15.0)
        resp.raise_for_status()
        data = resp.json()

        results = []
        # CIRCL returns {"products": [...], "vulnerabilities": [...]}
        vulnerabilities = data.get("vulnerabilities", [])
        if isinstance(vulnerabilities, list):
            for entry in vulnerabilities:
                cve_id = entry.get("id", "") or entry.get("cve", {}).get("id", "")
                if not cve_id:
                    continue

                # Extract CVSS from summary or metrics
                cvss_score = 0.0
                severity = ""
                summary_text = entry.get("summary", "")[:300]

                # Try to get CVSS from the entry
                cvss_data = entry.get("cvss", {})
                if isinstance(cvss_data, (int, float)):
                    cvss_score = float(cvss_data)
                elif isinstance(cvss_data, dict):
                    cvss_score = cvss_data.get("score", 0.0) or 0.0

                # Try severity from entry
                severity_str = entry.get("severity", "")
                if isinstance(severity_str, str) and severity_str:
                    severity = severity_str.upper()

                # Check references for exploits
                has_exploit = False
                for ref in entry.get("references", []):
                    ref_lower = (ref if isinstance(ref, str) else ref.get("url", "")).lower()
                    if "exploit" in ref_lower or "poc" in ref_lower:
                        has_exploit = True
                        break

                results.append(
                    {
                        "cve_id": cve_id,
                        "source": "CIRCL",
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "has_exploit": has_exploit,
                        "description": summary_text,
                    }
                )
        return results
    except Exception as exc:
        logger.warning("CIRCL query failed for '%s': %s", tech, exc)
        return []


async def _query_vulnerablecode(client: Any, tech: str, version: str) -> list[dict[str, Any]]:
    """Query VulnerableCode for package vulnerabilities."""
    # Guard: reject overly long strings (descriptions, not tech names)
    tech_stripped = tech.strip()
    if len(tech_stripped) > 80:
        logger.debug(
            "VulnerableCode: tech string too long (%d chars), skipping: %s...",
            len(tech_stripped),
            tech_stripped[:60],
        )
        return []

    # Guard: reject strings that look like descriptions (too many words)
    word_count = len(tech_stripped.split())
    if word_count > 5:
        logger.debug(
            "VulnerableCode: tech string has %d words, looks like description, skipping", word_count
        )
        return []

    ecosystem = _guess_ecosystem(tech)
    if not ecosystem:
        logger.debug("No ecosystem for '%s', skipping VulnerableCode", tech)
        return []

    # Map to VulnerableCode PURL ecosystem names
    eco_to_purl = {
        "npm": "npm",
        "pypi": "pypi",
        "go": "golang",
        "maven": "maven",
        "nuget": "nuget",
        "rubygems": "gem",
        "crates.io": "cargo",
        "packagist": "composer",
    }
    purl_eco = eco_to_purl.get(ecosystem.lower(), ecosystem.lower())

    # Use package name normalization if available
    pkg_name = _normalize_package_name(tech, ecosystem)

    # Guard: validate package name is a clean identifier (not a sentence)
    import re as _re

    if not _re.match(r"^[a-zA-Z0-9@/_.-]+$", pkg_name) or len(pkg_name) > 60:
        logger.debug(
            "VulnerableCode: pkg_name '%s' doesn't look like a valid package, skipping",
            pkg_name[:60],
        )
        return []

    purl = f"pkg:{purl_eco}/{pkg_name}"

    url = f"https://public.vulnerablecode.io/api/v3/packages/?purl={purl}"
    try:
        resp = await client.get(url, timeout=15.0)
        resp.raise_for_status()
        data = resp.json()

        results = []
        # API returns paginated list of packages with vulnerabilities
        packages = data if isinstance(data, list) else data.get("results", data.get("objects", []))
        if not isinstance(packages, list):
            return []

        for pkg in packages:
            vulns = pkg.get("vulnerabilities", [])
            for vuln in vulns:
                cve_id = (
                    vuln.get("vulnerability_id", "") or vuln.get("aliases", [{}])[0]
                    if isinstance(vuln.get("aliases"), list)
                    else ""
                )
                if isinstance(vuln.get("aliases"), list):
                    for alias in vuln["aliases"]:
                        if isinstance(alias, str) and alias.startswith("CVE-"):
                            cve_id = alias
                            break

                if not cve_id:
                    continue

                cvss_score = 0.0
                severity = ""
                # Try to extract CVSS
                cvss = vuln.get("cvss_score") or vuln.get("cvss")
                if isinstance(cvss, (int, float)):
                    cvss_score = float(cvss)
                elif isinstance(cvss, dict):
                    cvss_score = cvss.get("score", 0.0) or 0.0

                severity_str = vuln.get("severity", "")
                if isinstance(severity_str, str):
                    severity = severity_str.upper()

                has_exploit = False
                summary = vuln.get("summary", "") or vuln.get("description", "")
                if not isinstance(summary, str):
                    summary = str(summary) if summary else ""

                results.append(
                    {
                        "cve_id": cve_id,
                        "source": "VulnerableCode",
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "has_exploit": has_exploit,
                        "description": summary[:300],
                    }
                )
        return results
    except Exception as exc:
        logger.warning("VulnerableCode query failed for '%s': %s", tech, exc)
        return []


async def _query_npm_advisory(client: Any, tech: str, version: str) -> list[dict[str, Any]]:
    """Query npm bulk advisory endpoint for npm packages."""
    ecosystem = _guess_ecosystem(tech)
    if not ecosystem or ecosystem.lower() != "npm":
        return []

    pkg_name = _normalize_package_name(tech, "npm")
    if not version:
        # npm bulk advisory needs a version; skip if not provided
        return []

    url = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"
    payload = {pkg_name: [version]}

    try:
        resp = await client.post(url, json=payload, timeout=15.0)
        resp.raise_for_status()
        data = resp.json()

        results = []
        # Response: {"package_name": [advisory, ...]}
        advisories = data.get(pkg_name, [])
        if not isinstance(advisories, list):
            return []

        for adv in advisories:
            cve_id = adv.get("cve", "") or ""
            if not cve_id:
                # Try to find CVE in findings
                findings = adv.get("findings", [])
                for f in findings:
                    cve = f.get("cve", "")
                    if cve and cve.startswith("CVE-"):
                        cve_id = cve
                        break

            if not cve_id:
                continue

            cvss_score = 0.0
            severity = ""
            cvss_data = adv.get("cvss", {})
            if isinstance(cvss_data, dict):
                cvss_score = cvss_data.get("score", 0.0) or 0.0
            severity_str = adv.get("severity", "")
            if isinstance(severity_str, str):
                severity = severity_str.upper()

            has_exploit = False
            url_ref = adv.get("url", "")
            if isinstance(url_ref, str) and (
                "exploit" in url_ref.lower() or "poc" in url_ref.lower()
            ):
                has_exploit = True

            title = adv.get("title", "") or adv.get("overview", "")
            if not isinstance(title, str):
                title = ""

            results.append(
                {
                    "cve_id": cve_id,
                    "source": "npm_advisory",
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "has_exploit": has_exploit,
                    "description": title[:300],
                    "vulnerable_version_range": adv.get("vulnerable_versions", ""),
                }
            )
        return results
    except Exception as exc:
        logger.warning("npm advisory query failed for '%s': %s", tech, exc)
        return []


async def _query_epss_batch(cve_ids: list[str]) -> dict[str, dict[str, float]]:
    """Batch-query EPSS for a list of CVE IDs.

    Returns dict mapping CVE ID -> {"epss_score": float, "epss_percentile": float}.
    """
    if not cve_ids:
        return {}

    import httpx

    # EPSS API supports comma-separated CVE IDs
    cve_param = ",".join(cve_ids[:1000])  # safety limit
    url = f"https://api.first.org/data/v1/epss?cve={cve_param}"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()

        epss_map: dict[str, dict[str, float]] = {}
        for entry in data.get("data", []):
            cve = entry.get("cve", "")
            epss_score = entry.get("epss", "0")
            epss_pct = entry.get("percentile", "0")
            try:
                epss_score = float(epss_score)
            except (ValueError, TypeError):
                epss_score = 0.0
            try:
                epss_pct = float(epss_pct)
            except (ValueError, TypeError):
                epss_pct = 0.0
            if cve:
                epss_map[cve] = {"epss_score": epss_score, "epss_percentile": epss_pct}
        return epss_map
    except Exception as exc:
        logger.warning("EPSS batch query failed for %d CVE IDs: %s", len(cve_ids), exc)
        return {}


def _enrich_with_epss(
    vulns: list[dict[str, Any]],
    epss_map: dict[str, dict[str, float]],
) -> None:
    """Mutate vuln dicts in-place to add epss_score/epss_percentile."""
    for v in vulns:
        cve_id = v.get("cve_id", "")
        epss = epss_map.get(cve_id)
        if epss:
            v["epss_score"] = epss["epss_score"]
            v["epss_percentile"] = epss["epss_percentile"]


async def query_threats(
    fingerprints: list[dict[str, str]],
    db: ThreatIntelDB | None = None,
    *,
    local_only: bool = True,
) -> dict[str, Any]:
    """Query threats for a list of technology fingerprints.

    Uses local DB first. When local_only=True (default), never queries
    online sources — returns local results only, zero API cost.

    Args:
        fingerprints: List of {"technology": "next.js", "version": "14.2.0"}
        db: Optional ThreatIntelDB instance. Creates one if not provided.
        local_only: If True (default), skip online fallback entirely.

    Returns:
        Dict with per-technology results, scores, and metadata.
    """
    if not fingerprints:
        return {"success": False, "error": "No fingerprints provided"}

    own_db = db is None
    if own_db:
        db = ThreatIntelDB()

    try:
        return await _query_impl(fingerprints, db, local_only=local_only)
    finally:
        if own_db:
            db.close()


async def _query_impl(
    fingerprints: list[dict[str, str]],
    db: ThreatIntelDB,
    *,
    local_only: bool = True,
) -> dict[str, Any]:
    """Core implementation."""
    start = time.time()
    results = []
    needs_online: list[dict[str, str]] = []

    # Phase 1: Query local DB
    for fp in fingerprints:
        tech = fp.get("technology", "").strip()
        version = fp.get("version", "").strip()
        if not tech:
            results.append({"technology": tech, "version": version, "error": "Empty technology"})
            continue

        ecosystem = _normalize_ecosystem(tech)
        pkg_name = _normalize_package_name(tech, ecosystem or "")

        # Query local DB
        local_results = []
        if ecosystem:
            local_results = db.query_by_package(ecosystem, pkg_name, version)

        if local_results:
            # Get EPSS scores
            cve_ids = [r["cve_id"] for r in local_results]
            epss_scores = db.get_epss_scores(cve_ids)

            # Enrich with EPSS
            for r in local_results:
                epss = epss_scores.get(r["cve_id"], {})
                r["epss_score"] = epss.get("epss_score")
                r["epss_percentile"] = epss.get("epss_percentile")
                r["source"] = "LOCAL_DB"

            # Score and sort
            kev_cves = set(db.query_kev_cves())
            for r in local_results:
                # SCA confidence flagging per ACM SCA paper findings:
                # version-range matching is unreliable across databases
                if ecosystem is None:
                    r["sca_confidence"] = "low"
                elif r.get("version_match") == "vulnerable":
                    r["sca_confidence"] = "high"
                elif r.get("version_match") == "unknown" or not r.get("version_match"):
                    r["sca_confidence"] = "medium"
                else:
                    r["sca_confidence"] = "medium"

                r["priority_score"] = _score_local_vulnerability(r, kev_cves)
            local_results.sort(key=lambda r: r.get("priority_score", 0), reverse=True)

            # Aggregate SCA confidence for the technology-level result
            confidences = {r.get("sca_confidence", "medium") for r in local_results}
            if "high" in confidences and "low" not in confidences and "medium" not in confidences:
                tech_sca_confidence = "high"
            elif "low" in confidences and "high" not in confidences:
                tech_sca_confidence = "low"
            else:
                tech_sca_confidence = "mixed"

            results.append(
                {
                    "technology": tech,
                    "version": version,
                    "ecosystem": ecosystem,
                    "sca_confidence": tech_sca_confidence,
                    "total_vulnerabilities": len(local_results),
                    "source": "LOCAL_DB",
                    "vulnerabilities": local_results[:50],
                }
            )
        else:
            # No local results — mark for online query
            needs_online.append(fp)
            sca_conf = "low" if ecosystem is None else "medium"
            results.append(
                {
                    "technology": tech,
                    "version": version,
                    "ecosystem": ecosystem,
                    "sca_confidence": sca_conf,
                    "total_vulnerabilities": 0,
                    "source": "PENDING_ONLINE",
                    "vulnerabilities": [],
                }
            )

    # Phase 2: Online fallback for fingerprints with 0 local results
    # Only if local_only=False. When local_only=True (default), skip online APIs.
    if needs_online and not local_only:
        logger.info("Local DB miss for %d fingerprints, querying online", len(needs_online))
        online_results = await _query_online(needs_online, db)

        # Merge online results back into results list
        online_by_tech = {r["technology"]: r for r in online_results}
        for i, r in enumerate(results):
            if r.get("source") == "PENDING_ONLINE":
                tech = r["technology"]
                if tech in online_by_tech:
                    results[i] = online_by_tech[tech]
                    results[i]["source"] = "ONLINE_CACHED"

    duration = time.time() - start
    total_vulns = sum(r.get("total_vulnerabilities", 0) for r in results)

    return {
        "success": True,
        "technologies_queried": len(fingerprints),
        "total_vulnerabilities": total_vulns,
        "local_hits": sum(1 for r in results if r.get("source") == "LOCAL_DB"),
        "online_fallbacks": sum(1 for r in results if r.get("source") == "ONLINE_CACHED"),
        "duration": duration,
        "results": results,
    }


async def _query_online(
    fingerprints: list[dict[str, str]],
    db: ThreatIntelDB,
) -> list[dict[str, Any]]:
    """Query online sources for fingerprints not found in local DB.

    Queries: NVD, OSV, GHSA, CIRCL, VulnerableCode, npm advisory (if npm).
    Then batch-enriches all CVE results with EPSS scores.
    Stores results locally.
    """
    import httpx

    gh_token = _get_github_token()
    headers = {"User-Agent": "Mozilla/5.0 (compatible; security-research)"}
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"

    results = []

    async with httpx.AsyncClient(follow_redirects=True, headers=headers) as client:
        for fp in fingerprints:
            tech = fp.get("technology", "").strip()
            version = fp.get("version", "").strip()
            # Phase 1D: slugify before any online call so the agent's
            # free-form fingerprint text doesn't produce 200+ char URLs.
            slug = slugify_tech(tech)

            try:
                # Import online query functions
                from prometheus.tools.threat_intel.tool import _query_ghsa, _query_nvd, _query_osv

                # Query all sources in parallel (7 sources). Use the
                # slug for online calls; the full text is preserved in
                # the fingerprint for the local BM25 lookup.
                nvd_task = _query_nvd(client, slug, version)
                osv_task = _query_osv(client, slug, version)
                ghsa_task = _query_ghsa(client, slug, version)
                circl_task = _query_circl(client, slug, version)
                vc_task = _query_vulnerablecode(client, slug, version)
                npm_task = _query_npm_advisory(client, slug, version)

                results_all = await asyncio.gather(
                    nvd_task,
                    osv_task,
                    ghsa_task,
                    circl_task,
                    vc_task,
                    npm_task,
                    return_exceptions=True,
                )

                nvd = results_all[0] if isinstance(results_all[0], list) else []
                osv = results_all[1] if isinstance(results_all[1], list) else []
                ghsa = results_all[2] if isinstance(results_all[2], list) else []
                circl = results_all[3] if isinstance(results_all[3], list) else []
                vc = results_all[4] if isinstance(results_all[4], list) else []
                npm = results_all[5] if isinstance(results_all[5], list) else []

                all_results = nvd + osv + ghsa + circl + vc + npm

                # Deduplicate by CVE ID
                seen = set()
                deduped = []
                for r in all_results:
                    cve_id = r.get("cve_id", "")
                    if cve_id and cve_id not in seen:
                        seen.add(cve_id)
                        deduped.append(r)

                # EPSS enrichment: batch-query all CVE IDs
                cve_ids = [r["cve_id"] for r in deduped if r.get("cve_id")]
                if cve_ids:
                    epss_map = await _query_epss_batch(cve_ids)
                    _enrich_with_epss(deduped, epss_map)

                    # Persist EPSS scores to local DB
                    for cve_id, epss_data in epss_map.items():
                        try:
                            db.upsert_epss(
                                cve_id=cve_id,
                                epss_score=epss_data["epss_score"],
                                epss_percentile=epss_data["epss_percentile"],
                            )
                        except Exception:
                            pass  # non-critical
                    db.commit()

                # Store in local DB
                ecosystem = _normalize_ecosystem(tech)
                pkg_name = _normalize_package_name(tech, ecosystem or "")

                for r in deduped:
                    cve_id = r.get("cve_id", "")
                    if not cve_id:
                        continue

                    db.upsert_cve(
                        cve_id=cve_id,
                        description=r.get("description", ""),
                        severity=r.get("severity", ""),
                        cvss_score=r.get("cvss_score", 0.0),
                        has_exploit=r.get("has_exploit", False),
                        published_at=r.get("published", ""),
                        sources=[r.get("source", "ONLINE")],
                    )

                    if ecosystem and pkg_name:
                        db.upsert_package(
                            cve_id=cve_id,
                            ecosystem=ecosystem,
                            package_name=pkg_name,
                            vulnerable_version_range=r.get("vulnerable_version_range", ""),
                        )

                db.commit()

                # Score results
                kev_cves = set(db.query_kev_cves())
                for r in deduped:
                    # SCA confidence per vulnerability
                    if ecosystem is None:
                        r["sca_confidence"] = "low"
                    elif r.get("version_match") == "vulnerable":
                        r["sca_confidence"] = "high"
                    else:
                        r["sca_confidence"] = "medium"

                    r["priority_score"] = _score_local_vulnerability(
                        {
                            "cve_id": r.get("cve_id", ""),
                            "cisa_kev": r.get("cve_id", "") in kev_cves,
                            "has_exploit": r.get("has_exploit", False),
                            "severity": r.get("severity", ""),
                            "cvss_score": r.get("cvss_score", 0.0),
                            "epss_score": r.get("epss_score"),
                            "version_match": r.get("version_match", "unknown"),
                        },
                        kev_cves,
                    )
                deduped.sort(key=lambda r: r.get("priority_score", 0), reverse=True)

                # Aggregate SCA confidence for the technology-level result
                confidences = {r.get("sca_confidence", "medium") for r in deduped}
                if confidences == {"high"}:
                    tech_sca_confidence = "high"
                elif confidences == {"low"}:
                    tech_sca_confidence = "low"
                else:
                    tech_sca_confidence = "mixed"

                results.append(
                    {
                        "technology": tech,
                        "version": version,
                        "ecosystem": ecosystem,
                        "sca_confidence": tech_sca_confidence,
                        "total_vulnerabilities": len(deduped),
                        "source": "ONLINE",
                        "nvd_count": len(nvd),
                        "osv_count": len(osv),
                        "ghsa_count": len(ghsa),
                        "circl_count": len(circl),
                        "vulnerablecode_count": len(vc),
                        "npm_advisory_count": len(npm),
                        "vulnerabilities": deduped[:50],
                    }
                )

            except Exception as exc:
                logger.exception("Online query failed for %s: %s", tech, exc)
                results.append(
                    {
                        "technology": tech,
                        "version": version,
                        "error": str(exc),
                        "total_vulnerabilities": 0,
                        "source": "ERROR",
                        "vulnerabilities": [],
                    }
                )

    return results


def _score_local_vulnerability(
    vuln: dict[str, Any],
    kev_cves: set[str],
) -> int:
    """Score a vulnerability from the local DB.

    Scoring:
    - In CISA KEV: +100
    - Has public exploit: +50
    - EPSS score >= 0.9: +60
    - EPSS score >= 0.7: +40
    - EPSS score >= 0.5: +20
    - CRITICAL severity: +30
    - HIGH severity: +20
    - CVSS >= 9.0: +10
    """
    score = 0

    cve_id = vuln.get("cve_id", "")
    if cve_id in kev_cves or vuln.get("cisa_kev"):
        score += 100

    if vuln.get("has_exploit"):
        score += 50

    epss = vuln.get("epss_score")
    if epss is not None and isinstance(epss, (int, float)):
        if epss >= 0.9:
            score += 60
        elif epss >= 0.7:
            score += 40
        elif epss >= 0.5:
            score += 20

    severity = (vuln.get("severity") or "").upper()
    if severity == "CRITICAL":
        score += 30
    elif severity == "HIGH":
        score += 20

    cvss = vuln.get("cvss_score", 0)
    if isinstance(cvss, (int, float)) and cvss >= 9.0:
        score += 10

    # SCA version-match confidence adjustment (ACM SCA paper findings)
    version_match = (vuln.get("version_match") or "").lower()
    if version_match == "vulnerable":
        score += 5  # confirmed match — boost priority
    elif version_match == "not_affected":
        score -= 5  # still include, but lower priority

    return score


async def inject_threat_intel(
    target_url: str,
    fingerprints: list[dict[str, str]],
) -> str:
    """Query threat intel and format for injection into agent task.

    Called from runner.py after fingerprinting, before agent starts.
    Returns a formatted string to prepend to the root agent task.
    """
    result = await query_threats(fingerprints)

    if not result.get("success"):
        return ""

    total = result.get("total_vulnerabilities", 0)
    if total == 0:
        return ""

    lines = [
        "=" * 60,
        "PRE-LOADED THREAT INTELLIGENCE (from local DB + online sources)",
        "=" * 60,
        f"Technologies queried: {result['technologies_queried']}",
        f"Total known vulnerabilities: {total}",
        f"Local DB hits: {result.get('local_hits', 0)}",
        f"Online fallbacks: {result.get('online_fallbacks', 0)}",
        "",
    ]

    for tech_result in result.get("results", []):
        vulns = tech_result.get("vulnerabilities", [])
        if not vulns:
            continue

        tech = tech_result.get("technology", "?")
        version = tech_result.get("version", "?")
        sca_conf = tech_result.get("sca_confidence", "unknown")
        conf_note = ""
        if sca_conf == "low":
            conf_note = " [LOW CONFIDENCE — no ecosystem match, manually verify]"
        elif sca_conf in ("medium", "mixed"):
            conf_note = " [Version ranges not all confirmed — test regardless]"
        lines.append(f"--- {tech} {version} ({len(vulns)} vulns){conf_note} ---")

        # Show top 10 highest-scored vulns
        for v in vulns[:10]:
            cve_id = v.get("cve_id", "?")
            sev = v.get("severity", "?")
            cvss = v.get("cvss_score", 0)
            epss = v.get("epss_score")
            exploit = " [EXPLOIT AVAILABLE]" if v.get("has_exploit") else ""
            kev = " [IN CISA KEV]" if v.get("cisa_kev") or v.get("in_cisa_kev") else ""
            epss_str = f" EPSS={epss:.2f}" if epss is not None else ""

            lines.append(f"  {cve_id} [{sev}] CVSS={cvss}{epss_str}{exploit}{kev}")
            desc = (v.get("description") or "")[:120]
            if desc:
                lines.append(f"    {desc}")
        if len(vulns) > 10:
            lines.append(f"  ... and {len(vulns) - 10} more")
        lines.append("")

    lines.append("=" * 60)
    lines.append(
        "TEST THESE VULNERABILITIES FIRST — they are known to exist in the target's technology stack."
    )
    lines.append(
        "Prioritize: CISA KEV entries > EPSS > 0.7 > CRITICAL > HIGH > exploits available."
    )
    lines.append("=" * 60)
    lines.append("")

    return "\n".join(lines)
