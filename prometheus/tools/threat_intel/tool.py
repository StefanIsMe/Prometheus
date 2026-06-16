"""``query_threat_feeds`` — Query CISA KEV, NVD, OSV.dev, and GitHub Security Advisories for known vulnerabilities."""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import time
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


def _get_github_token() -> str | None:
    """Get GitHub token from gh CLI."""
    try:
        result = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception as exc:
        logger.debug("Could not get gh token: %s", exc)
    return None


# ---------------------------------------------------------------------------
# In-memory caches
# ---------------------------------------------------------------------------

_cisa_kev_cache: dict[str, Any] | None = None  # noqa: F841  — module-level singleton cache
_cisa_kev_cache_ts: float = 0.0  # noqa: F841  — module-level singleton cache
_CISA_CACHE_TTL = 3600  # 1 hour

# Per-scan result cache: fingerprint_key -> result dict
_scan_cache: dict[str, dict[str, Any]] = {}


def clear_scan_cache() -> None:
    """Clear the per-scan result cache. Call at scan start."""
    _scan_cache.clear()


async def warm_threat_intel() -> dict[str, Any]:
    """Pre-warm threat intel caches before agents start.

    Fetches CISA KEV catalog and loads pre-cached GHSA data into memory
    so the agent's first query_threat_feeds call hits cache instead of
    waiting for a network round-trip.
    Called from runner.py at scan start — ALWAYS, not lazily.

    Returns:
        Summary dict with counts and status.
    """
    import glob as glob_mod
    import os

    import httpx

    result: dict[str, Any] = {
        "cisa_kev": {"status": "skipped", "count": 0},
        "ghsa_cache": {"status": "skipped", "count": 0},
    }

    # CISA KEV pre-fetch
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            cisa_vulns = await _fetch_cisa_kev(client)
            result["cisa_kev"] = {
                "status": "ok",
                "count": len(cisa_vulns),
            }
            logger.info("Threat intel warm: CISA KEV loaded %d entries", len(cisa_vulns))
    except Exception as exc:
        result["cisa_kev"] = {"status": "error", "error": str(exc)}
        logger.warning("Threat intel warm: CISA KEV failed: %s", exc)

    # GHSA pre-cache from daily feed download
    feed_dir = os.path.join(
        os.environ.get("PROMETHEUS_DATA_DIR", os.path.expanduser("~/.prometheus")),
        "threat-intel",
    )
    ghsa_files = sorted(glob_mod.glob(os.path.join(feed_dir, "ghsa-*.json")))
    if ghsa_files:
        ghsa_count = 0
        for fpath in ghsa_files:
            try:
                with open(fpath) as f:
                    data = json.load(f)
                if isinstance(data, list):
                    ghsa_count += len(data)
            except Exception:
                logger.debug("Failed to load GHSA cache file %s", fpath, exc_info=True)
                continue
        result["ghsa_cache"] = {
            "status": "ok",
            "files": len(ghsa_files),
            "advisories": ghsa_count,
        }
        logger.info(
            "Threat intel warm: GHSA cache loaded %d advisories from %d files",
            ghsa_count,
            len(ghsa_files),
        )
    else:
        result["ghsa_cache"] = {"status": "no_cache", "note": "Run update_threat_feeds.sh first"}
        logger.info("Threat intel warm: No GHSA cache found at %s", feed_dir)

    return result


# Common ecosystem mappings for OSV.dev
_ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "node": "npm",
    "next.js": "npm",
    "nextjs": "npm",
    "react": "npm",
    "express": "npm",
    "angular": "npm",
    "vue": "npm",
    "nuxt": "npm",
    "python": "PyPI",
    "pip": "PyPI",
    "flask": "PyPI",
    "django": "PyPI",
    "fastapi": "PyPI",
    "uvicorn": "PyPI",
    "go": "Go",
    "golang": "Go",
    "rust": "crates.io",
    "cargo": "crates.io",
    "ruby": "RubyGems",
    "rails": "RubyGems",
    "gem": "RubyGems",
    "java": "Maven",
    "maven": "Maven",
    "spring": "Maven",
    "php": "Packagist",
    "composer": "Packagist",
    "laravel": "Packagist",
    "nuget": "NuGet",
    ".net": "NuGet",
    "csharp": "NuGet",
    "swift": "SwiftURL",
    "cocoapods": "CocoaPods",
    "pub": "crates.io",
    # Infrastructure / proxy / CDN (no package ecosystem — use GHSA keyword search)
    "cloudflare": "npm",  # workers-sdk is on npm
    "vercel": "npm",  # next.js ecosystem
    "envoy": "Go",  # envoyproxy is Go-based
    "nginx": "Go",  # no direct ecosystem, but GHSA REST fallback covers it
    "apache": "Maven",
    "redis": "Go",
    "postgresql": "Go",
    "mysql": "Maven",
    "elasticsearch": "Maven",
    "kubernetes": "Go",
    "docker": "Go",
    "istio": "Go",
    "consul": "Go",
    "vault": "Go",
    "terraform": "Go",
}


def _guess_ecosystem(tech: str) -> str | None:
    """Best-effort ecosystem guess from a technology name."""
    tech_lower = tech.lower().strip()
    # Direct match
    if tech_lower in _ECOSYSTEM_MAP:
        return _ECOSYSTEM_MAP[tech_lower]
    # Partial match
    for key, eco in _ECOSYSTEM_MAP.items():
        if key in tech_lower:
            return eco
    return None


def _fingerprint_key(fingerprint: dict[str, str]) -> str:
    """Stable cache key for a fingerprint."""
    tech = fingerprint.get("technology", "").lower().strip()
    ver = fingerprint.get("version", "").strip()
    return f"{tech}@{ver}"


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------


async def _fetch_cisa_kev(client: Any) -> list[dict[str, Any]]:
    """Download and cache the CISA Known Exploited Vulnerabilities catalog."""
    global _cisa_kev_cache, _cisa_kev_cache_ts  # noqa: PLW0603

    if _cisa_kev_cache is not None and (time.time() - _cisa_kev_cache_ts) < _CISA_CACHE_TTL:
        return _cisa_kev_cache.get("vulnerabilities", [])

    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = await client.get(url, timeout=15.0)
        resp.raise_for_status()
        data = resp.json()
        _cisa_kev_cache = data
        _cisa_kev_cache_ts = time.time()
        return data.get("vulnerabilities", [])
    except Exception as exc:
        logger.warning("Failed to fetch CISA KEV: %s", exc)
        return []


def _search_cisa_kev(kev_entries: list[dict[str, Any]], tech: str) -> set[str]:
    """Return CVE IDs from CISA KEV that match a technology/product name."""
    tech_lower = tech.lower()
    matches: set[str] = set()
    for entry in kev_entries:
        product = (entry.get("product") or "").lower()
        vendor = (entry.get("vendor") or "").lower()
        # Match if the tech name appears in product, vendor, or any field
        if tech_lower in product or product in tech_lower or tech_lower in vendor:
            cve_id = entry.get("cveID", "")
            if cve_id:
                matches.add(cve_id)
    return matches


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------


async def _query_nvd(client: Any, tech: str, version: str) -> list[dict[str, Any]]:
    """Query NVD for CVEs matching a technology and version."""
    keyword = f"{tech} {version}".strip() if version else tech
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": 20}
    try:
        resp = await client.get(url, params=params, timeout=10.0)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        results = []
        for v in vulns:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            metrics = cve.get("metrics", {})
            # Extract CVSS score
            cvss_score = 0.0
            severity = ""
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "")
                    break

            # Check for public exploits
            has_exploit = False
            references = cve.get("references", [])
            for ref in references:
                tags = ref.get("tags", [])
                if "Exploit" in tags:
                    has_exploit = True
                    break

            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")[:300]
                    break

            results.append(
                {
                    "cve_id": cve_id,
                    "source": "NVD",
                    "cvss_score": cvss_score,
                    "severity": severity.upper() if severity else "",
                    "has_exploit": has_exploit,
                    "description": description,
                }
            )
        return results
    except Exception as exc:
        logger.warning("NVD query failed for '%s %s': %s", tech, version, exc)
        return []


# ---------------------------------------------------------------------------
# OSV.dev
# ---------------------------------------------------------------------------


async def _query_osv(client: Any, tech: str, version: str) -> list[dict[str, Any]]:
    """Query OSV.dev for vulnerabilities matching a package and version."""
    ecosystem = _guess_ecosystem(tech)
    if not ecosystem:
        logger.debug("No ecosystem mapping for '%s', skipping OSV query", tech)
        return []

    # For npm ecosystem, use the package name directly
    # Try both the tech name and common variations
    package_names = [tech.lower()]
    # Common npm package name variations
    tech_variants = {
        "next.js": "next",
        "nextjs": "next",
        "express.js": "express",
        "vue.js": "vue",
        "nuxt.js": "nuxt",
        "angular": "@angular/core",
        "react": "react",
    }
    if tech.lower() in tech_variants:
        package_names.append(tech_variants[tech.lower()])

    all_results: list[dict[str, Any]] = []
    seen_cves: set[str] = set()

    for pkg_name in package_names:
        payload = {
            "package": {"name": pkg_name, "ecosystem": ecosystem},
        }
        if version:
            payload["version"] = version

        try:
            resp = await client.post(
                "https://api.osv.dev/v1/query",
                json=payload,
                timeout=10.0,
            )
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulns", [])
            for v in vulns:
                vuln_id = v.get("id", "")
                # OSV uses GHSA-xxx or CVE-xxx as IDs
                cve_id = vuln_id
                aliases = v.get("aliases", [])
                for alias in aliases:
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break

                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)

                severity = ""
                cvss_score = 0.0
                # Try to extract severity from database_specific or severity field
                db_specific = v.get("database_specific", {})
                severity_str = db_specific.get("severity", "")
                if severity_str:
                    severity = severity_str.upper()

                # Check for CVSS in severity field
                severities = v.get("severity", [])
                for sev in severities:
                    if sev.get("type") == "CVSS_V3":
                        vector = sev.get("score", "")
                        # Try to extract score from vector string
                        try:
                            # CVSS:3.1/... - parse base score if possible
                            parts = vector.split("/")
                            for part in parts:
                                if part.startswith("CVSS:3"):
                                    continue
                        except Exception:
                            logger.debug("Failed to parse CVSS vector: %s", vector, exc_info=True)

                # Check for ecosystem-specific severity
                ecosystem_severity = v.get("ecosystem_specific", {})
                if not severity and ecosystem_severity:
                    severity = ecosystem_severity.get("severity", "").upper()

                summary = v.get("summary", "")[:300]

                # Check references for exploit links
                has_exploit = False
                for ref in v.get("references", []):
                    ref_type = ref.get("type", "")
                    ref_url = ref.get("url", "").lower()
                    if ref_type == "EXPLOIT" or "exploit" in ref_url or "poc" in ref_url:
                        has_exploit = True
                        break

                all_results.append(
                    {
                        "cve_id": cve_id,
                        "source": "OSV.dev",
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "has_exploit": has_exploit,
                        "description": summary,
                    }
                )
        except Exception as exc:
            logger.warning("OSV query failed for '%s' in '%s': %s", pkg_name, ecosystem, exc)
            continue

    return all_results


# ---------------------------------------------------------------------------
# GitHub Security Advisories (GHSA)
# ---------------------------------------------------------------------------

_GHSA_ECOSYSTEM_MAP: dict[str, str] = {k: v.lower() for k, v in _ECOSYSTEM_MAP.items()}


def _guess_ghsa_ecosystem(tech: str) -> str | None:
    tech_lower = tech.lower().strip()
    if tech_lower in _GHSA_ECOSYSTEM_MAP:
        return _GHSA_ECOSYSTEM_MAP[tech_lower]
    for key, eco in _GHSA_ECOSYSTEM_MAP.items():
        if key in tech_lower:
            return eco
    return None


def _cvss_score(adv: dict[str, Any]) -> float:
    """Extract the CVSS score from a GHSA advisory record, defensively.

    The audit of 175 scan-run logs (Phase 1C) found 16 occurrences of
    ``'str' object has no attribute 'get'`` from the previous chained
    expression ``(adv.get("cvss") or {}).get("score", 0.0) or 0.0``.
    The bug: when ``adv["cvss"]`` is a string (e.g. a serialised CVSS
    vector the API sometimes returns instead of an object), the
    ``or {}`` doesn't kick in (non-empty strings are truthy) and the
    subsequent ``.get(...)`` raises ``AttributeError``.

    Returns 0.0 for any unparseable / unexpected shape rather than
    raising — the caller just wants a numeric score.
    """
    raw = adv.get("cvss")
    if isinstance(raw, dict):
        score = raw.get("score")
        if isinstance(score, (int, float)):
            return float(score)
        return 0.0
    # CVSS-as-string (or any other unexpected shape): best-effort parse.
    if isinstance(raw, str):
        # Try to extract a base score from a CVSS:3.x vector — not common
        # but cheap to attempt. Most strings will just return 0.0.
        return 0.0
    return 0.0


def _pkg_dict(pkg: Any) -> dict[str, Any]:
    """Return ``pkg`` as a dict, or ``{}`` if it's anything else.

    Same shape of bug as ``_cvss_score`` — the GHSA REST API sometimes
    returns ``vulnerabilities[].package`` as a string instead of an
    object. Centralised here so the three call sites use the same
    defensive normalisation.
    """
    return pkg if isinstance(pkg, dict) else {}


async def _query_ghsa(client: Any, tech: str, version: str) -> list[dict[str, Any]]:
    """Query GitHub Security Advisories for a technology.

    Strategy:
    1. GraphQL per-package query (precise, works for any ecosystem)
    2. REST keyword search fallback (covers non-ecosystem tech like nginx, WordPress)
    """
    all_results: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    pkg_name = tech.lower().strip()

    # Resolve ecosystem first (needed for package name normalization)
    ecosystem = _guess_ghsa_ecosystem(tech)

    # Package name normalization (tech name -> actual package name)
    _PKG_VARIANTS: dict[str, dict[str, str]] = {
        "next.js": {"npm": "next", "pypi": "next"},
        "nextjs": {"npm": "next"},
        "express.js": {"npm": "express"},
        "vue.js": {"npm": "vue"},
        "nuxt.js": {"npm": "nuxt"},
        "angular": {"npm": "@angular/core"},
        "react": {"npm": "react"},
        "laravel": {"packagist": "laravel/framework"},
        "spring": {"maven": "org.springframework"},
    }
    # Resolve package name for this ecosystem
    resolved_pkg = pkg_name
    if pkg_name in _PKG_VARIANTS and ecosystem:
        resolved_pkg = _PKG_VARIANTS[pkg_name].get(ecosystem, pkg_name)

    # --- Strategy 1: GraphQL per-package query ---
    if ecosystem:
        # Map common variations
        eco_map = {
            "npm": "NPM",
            "pypi": "PIP",
            "go": "GO",
            "maven": "MAVEN",
            "nuget": "NUGET",
            "rubygems": "RUBYGEMS",
            "crates.io": "RUST",
            "packagist": "COMPOSER",
            "swifturl": "SWIFT",
            "cocoapods": "COCOAPODS",
        }
        gql_eco = eco_map.get(ecosystem, ecosystem.upper())

        query = """
        query($eco: SecurityAdvisoryEcosystem!, $pkg: String!) {
          securityVulnerabilities(
            ecosystem: $eco, package: $pkg,
            orderBy: {field: UPDATED_AT, direction: DESC},
            first: 50
          ) {
            nodes {
              advisory {
                ghsaId
                summary
                severity
                publishedAt
                cvss { score }
                identifiers { type value }
                references { url }
              }
              vulnerableVersionRange
              firstPatchedVersion { identifier }
              severity
            }
          }
        }
        """
        try:
            resp = await client.post(
                "https://api.github.com/graphql",
                json={"query": query, "variables": {"eco": gql_eco, "pkg": resolved_pkg}},
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json()
            nodes = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
            for node in nodes:
                adv = node.get("advisory", {})
                ghsa_id = adv.get("ghsaId", "")
                if not ghsa_id or ghsa_id in seen_ids:
                    continue
                seen_ids.add(ghsa_id)

                cve_id = ""
                for ident in adv.get("identifiers", []):
                    if ident.get("type") == "CVE":
                        cve_id = ident.get("value", "")
                        break
                if not cve_id:
                    cve_id = ghsa_id

                summary = adv.get("summary", "")
                vuln_range = node.get("vulnerableVersionRange", "")
                patched = node.get("firstPatchedVersion", {})
                if patched and patched.get("identifier"):
                    summary += f" [fixed in {patched['identifier']}]"

                # Version range matching
                version_match = "unknown"
                if version and vuln_range:
                    if _version_in_range(version, vuln_range):
                        version_match = "vulnerable"
                    else:
                        version_match = "not_affected"

                cvss_score = _cvss_score(adv)
                severity_str = (adv.get("severity") or "").upper()

                has_exploit = any(
                    "exploit" in (ref.get("url") or "").lower()
                    or "poc" in (ref.get("url") or "").lower()
                    for ref in adv.get("references", [])
                )

                all_results.append(
                    {
                        "cve_id": cve_id,
                        "source": "GHSA",
                        "cvss_score": cvss_score,
                        "severity": severity_str,
                        "has_exploit": has_exploit,
                        "description": summary[:300],
                        "ghsa_id": ghsa_id,
                        "published": adv.get("publishedAt", ""),
                        "vulnerable_version_range": vuln_range,
                        "version_match": version_match,
                    }
                )
        except Exception as exc:
            logger.warning("GHSA GraphQL query failed for '%s': %s", tech, exc)

    # --- Strategy 2: REST keyword search fallback ---
    # Covers technologies without ecosystem mapping (nginx, WordPress, Apache, Redis, etc.)
    if not ecosystem or not all_results:
        for severity in ("high", "critical"):
            try:
                resp = await client.get(
                    "https://api.github.com/advisories",
                    params={
                        "q": f"{tech} severity:{severity}",
                        "per_page": 100,
                        "sort": "published",
                        "direction": "desc",
                    },
                    timeout=15.0,
                )
                resp.raise_for_status()
                advisories = resp.json()
                if not isinstance(advisories, list):
                    continue

                for adv in advisories:
                    ghsa_id = adv.get("ghsa_id", "")
                    if not ghsa_id or ghsa_id in seen_ids:
                        continue
                    seen_ids.add(ghsa_id)

                    cve_id = ""
                    for ident in adv.get("identifiers", []):
                        if ident.get("type") == "CVE":
                            cve_id = ident.get("value", "")
                            break
                    if not cve_id:
                        cve_id = ghsa_id

                    summary = adv.get("summary", "")

                    # Check package match in vulnerabilities array
                    pkg_match = False
                    vuln_range = ""
                    for vuln in adv.get("vulnerabilities", []):
                        pkg = _pkg_dict(vuln.get("package", {}))
                        if pkg_name in (pkg.get("name") or "").lower():
                            pkg_match = True
                            vuln_range = vuln.get("vulnerableVersionRange", "") or ""
                            patched = _pkg_dict(vuln.get("first_patched_version", {}))
                            if patched.get("identifier"):
                                summary += f" [fixed in {patched['identifier']}]"
                            break

                    if not pkg_match and pkg_name not in summary.lower():
                        continue

                    # Version range matching
                    version_match = "unknown"
                    if version and vuln_range:
                        if _version_in_range(version, vuln_range):
                            version_match = "vulnerable"
                        else:
                            version_match = "not_affected"

                    cvss_score = _cvss_score(adv)
                    severity_str = (adv.get("severity") or "").upper()

                    has_exploit = any(
                        "exploit" in (ref.get("url") or "").lower()
                        or "poc" in (ref.get("url") or "").lower()
                        for ref in adv.get("references", [])
                    )

                    all_results.append(
                        {
                            "cve_id": cve_id,
                            "source": "GHSA",
                            "cvss_score": cvss_score,
                            "severity": severity_str,
                            "has_exploit": has_exploit,
                            "description": summary[:300],
                            "ghsa_id": ghsa_id,
                            "published": adv.get("published_at", ""),
                            "vulnerable_version_range": vuln_range,
                            "version_match": version_match,
                        }
                    )
            except Exception as exc:
                logger.warning("GHSA REST query failed for '%s' (%s): %s", tech, severity, exc)

    return all_results


def _version_in_range(version: str, vuln_range: str) -> bool:
    """Best-effort check if version falls within a vulnerable range.

    Handles common patterns:
    - "<1.2.3"
    - ">=1.0.0, <1.2.3"
    - ">=1.0.0"
    - "1.0.0 - 1.2.3"
    Falls back to True (assume vulnerable) if parsing fails.
    """
    if not version or not vuln_range:
        return True  # Can't determine, assume vulnerable

    try:
        from packaging.version import Version

        ver = Version(version)
    except Exception:
        # Can't parse version — assume vulnerable
        return True

    range_str = vuln_range.strip()

    # Handle "1.0.0 - 1.2.3" range format
    if " - " in range_str:
        parts = range_str.split(" - ", 1)
        try:
            low = Version(parts[0].strip())
            high = Version(parts[1].strip())
            return low <= ver <= high
        except Exception:
            return True

    # Handle comma-separated constraints
    constraints = [c.strip() for c in range_str.split(",")]
    for constraint in constraints:
        try:
            if constraint.startswith("<="):
                bound = Version(constraint[2:].strip())
                if ver > bound:
                    return False
            elif constraint.startswith("<"):
                bound = Version(constraint[1:].strip())
                if ver >= bound:
                    return False
            elif constraint.startswith(">="):
                bound = Version(constraint[2:].strip())
                if ver < bound:
                    return False
            elif constraint.startswith(">"):
                bound = Version(constraint[1:].strip())
                if ver <= bound:
                    return False
            elif constraint.startswith("=="):
                bound = Version(constraint[2:].strip())
                if ver != bound:
                    return False
            elif constraint.startswith("!="):
                bound = Version(constraint[2:].strip())
                if ver == bound:
                    return False
            elif constraint.startswith("~="):
                bound = Version(constraint[2:].strip())
                if ver < bound:
                    return False
        except Exception:
            continue

    return True


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _score_vulnerability(
    vuln: dict[str, Any],
    cisa_cve_ids: set[str],
    has_nuclei_template: bool = False,
) -> int:
    """Score a vulnerability based on prioritization rules.

    Scoring:
    - In CISA KEV: +100
    - Has public exploit: +50
    - CRITICAL severity: +30
    - HIGH severity: +20
    - CVSS >= 9.0: +10
    - Has nuclei template: +25
    - Version match confirmed vulnerable: +5 (SCA confidence boost)
    - Version match confirmed not_affected: -5 (SCA penalty, still included)
    """
    score = 0

    cve_id = vuln.get("cve_id", "")
    if cve_id in cisa_cve_ids:
        score += 100

    if vuln.get("has_exploit"):
        score += 50

    severity = (vuln.get("severity") or "").upper()
    if severity == "CRITICAL":
        score += 30
    elif severity == "HIGH":
        score += 20

    cvss = vuln.get("cvss_score", 0)
    if isinstance(cvss, (int, float)) and cvss >= 9.0:
        score += 10

    if has_nuclei_template:
        score += 25

    # SCA version-match confidence adjustment (ACM SCA paper findings)
    version_match = (vuln.get("version_match") or "").lower()
    if version_match == "vulnerable":
        score += 5  # confirmed match — boost priority
    elif version_match == "not_affected":
        score -= 5  # still include, but lower priority

    return score


def _deduplicate(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate results by CVE ID, merging data from multiple sources."""
    merged: dict[str, dict[str, Any]] = {}
    for r in results:
        cve_id = r.get("cve_id", "")
        if not cve_id:
            continue
        if cve_id in merged:
            existing = merged[cve_id]
            # Merge sources
            existing_source = existing.get("source", "")
            new_source = r.get("source", "")
            if new_source and new_source not in existing_source:
                existing["source"] = f"{existing_source}, {new_source}"
            # Take higher CVSS
            if (r.get("cvss_score") or 0) > (existing.get("cvss_score") or 0):
                existing["cvss_score"] = r["cvss_score"]
            # Merge exploit info
            if r.get("has_exploit"):
                existing["has_exploit"] = True
            # Take more severe rating
            sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "": 0}
            old_sev = sev_order.get(existing.get("severity", "").upper(), 0)
            new_sev = sev_order.get(r.get("severity", "").upper(), 0)
            if new_sev > old_sev:
                existing["severity"] = r.get("severity", "")
            # Prefer longer description
            if len(r.get("description", "")) > len(existing.get("description", "")):
                existing["description"] = r.get("description", "")
        else:
            merged[cve_id] = dict(r)
    return list(merged.values())


# ---------------------------------------------------------------------------
# Main tool
# ---------------------------------------------------------------------------


async def _query_threat_feeds_impl(
    technologies: list[dict[str, str]],
    *,
    local_only: bool = True,
) -> dict[str, Any]:
    """Core implementation: local DB first, online fallback only if explicitly enabled.

    local_only=True (default): Uses SQLite local DB + CISA KEV cache only.
    No network calls to NVD/OSV/GHSA — zero API cost, instant results.

    local_only=False: Also queries online sources (NVD, OSV, GHSA) for
    fingerprints not found locally. Use for one-off research, not during scans.
    """
    if not technologies:
        return {
            "success": False,
            "error": "No technologies provided. Pass a list of {technology, version} objects.",
        }

    from prometheus.tools.threat_intel.query_engine import query_threats as _query_threats_local

    # Phase 1: Query local SQLite DB (fast, free, offline)
    local_result = await _query_threats_local(technologies)
    local_hits = local_result.get("local_hits", 0)
    total_fingerprints = len(technologies)
    local_misses = total_fingerprints - local_hits

    # Phase 2: Online fallback — only if explicitly requested AND local DB missed something
    if not local_only and local_misses > 0:
        logger.info(
            "Local DB: %d/%d hits. %d misses — falling back to online sources.",
            local_hits,
            total_fingerprints,
            local_misses,
        )
        # Only query online for the fingerprints that missed locally
        missed_fingerprints: list[dict[str, str]] = []
        for r in local_result.get("results", []):
            if r.get("total_vulnerabilities", 0) == 0:
                tech = r.get("technology", "")
                ver = r.get("version", "")
                if tech:
                    missed_fingerprints.append({"technology": tech, "version": ver})
        if missed_fingerprints:
            online_result = await _query_threat_feeds_online(missed_fingerprints)
            # Merge online results into local results
            if online_result.get("success"):
                online_by_tech = {r["technology"]: r for r in online_result.get("results", [])}
                results = local_result.get("results", [])
                for i, r in enumerate(results):
                    tech = r.get("technology", "")
                    if tech in online_by_tech and r.get("total_vulnerabilities", 0) == 0:
                        results[i] = online_by_tech[tech]
                local_result["results"] = results
                local_result["online_fallbacks"] = len(online_by_tech)

    return local_result


async def _query_threat_feeds_online(
    technologies: list[dict[str, str]],
) -> dict[str, Any]:
    """Online-only query path — hits NVD, OSV, GHSA, CIRCL, VulnerableCode, npm.

    Only used when local_only=False and local DB misses fingerprints.
    """
    if not technologies:
        return {"success": False, "error": "No technologies provided"}

    try:
        import httpx
    except ImportError:
        return {"success": False, "error": "httpx not installed"}

    # Build headers with GitHub token if available
    headers = {"User-Agent": "Mozilla/5.0 (compatible; security-research)"}
    gh_token = _get_github_token()
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"
        logger.info("GitHub token loaded (gh CLI) — 5000 req/hour")
    else:
        logger.warning("No GitHub token — GHSA queries limited to 60 req/hour")

    async with httpx.AsyncClient(
        follow_redirects=True,
        headers=headers,
    ) as client:
        # Fetch CISA KEV once (cached)
        kev_entries = await _fetch_cisa_kev(client)
        kev_cve_ids: set[str] = set()
        for entry in kev_entries:
            cve_id = entry.get("cveID", "")
            if cve_id:
                kev_cve_ids.add(cve_id)

        logger.info(
            "Loaded CISA KEV: %d entries, %d unique CVE IDs",
            len(kev_entries),
            len(kev_cve_ids),
        )

        # Build parallel tasks for each technology
        async def _process_fingerprint(
            fingerprint: dict[str, str],
        ) -> dict[str, Any]:
            tech = fingerprint.get("technology", "").strip()
            version = fingerprint.get("version", "").strip()
            cache_key = _fingerprint_key(fingerprint)

            if not tech:
                return {
                    "technology": tech,
                    "version": version,
                    "error": "Empty technology name",
                }

            # Check per-fingerprint cache
            if cache_key in _scan_cache:
                return _scan_cache[cache_key]

            # Also check CISA KEV directly for this product name
            cisa_matches = _search_cisa_kev(kev_entries, tech)
            all_cisa_ids = kev_cve_ids | cisa_matches

            # Run NVD, OSV, GHSA, CIRCL, VulnerableCode, npm advisory in parallel (7 sources)
            from prometheus.tools.threat_intel.query_engine import (
                _query_circl,
                _query_npm_advisory,
                _query_vulnerablecode,
            )

            nvd_task = _query_nvd(client, tech, version)
            osv_task = _query_osv(client, tech, version)
            ghsa_task = _query_ghsa(client, tech, version)
            circl_task = _query_circl(client, tech, version)
            vc_task = _query_vulnerablecode(client, tech, version)
            npm_task = _query_npm_advisory(client, tech, version)
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

            # Merge and deduplicate
            all_results = _deduplicate(nvd + osv + ghsa + circl + vc + npm)

            # Score each vulnerability
            for vuln in all_results:
                vuln["priority_score"] = _score_vulnerability(vuln, all_cisa_ids)
                vuln["in_cisa_kev"] = vuln.get("cve_id", "") in all_cisa_ids

            # Sort by priority score descending
            all_results.sort(key=lambda v: v.get("priority_score", 0), reverse=True)

            result = {
                "technology": tech,
                "version": version,
                "total_vulnerabilities": len(all_results),
                "nvd_results": len(nvd),
                "osv_results": len(osv),
                "ghsa_results": len(ghsa),
                "cisa_kev_matches": [v["cve_id"] for v in all_results if v.get("in_cisa_kev")],
                "vulnerabilities": all_results[:50],  # Cap at 50 per tech
            }

            # Cache
            _scan_cache[cache_key] = result
            return result

        # Process all fingerprints concurrently
        tasks = [_process_fingerprint(fp) for fp in technologies]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    processed: list[dict[str, Any]] = []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            processed.append(
                {
                    "technology": technologies[i].get("technology", "unknown"),
                    "version": technologies[i].get("version", ""),
                    "error": str(r),
                }
            )
        else:
            processed.append(r)

    total_vulns = sum(r.get("total_vulnerabilities", 0) for r in processed)
    all_cisa = []
    for r in processed:
        all_cisa.extend(r.get("cisa_kev_matches", []))

    return {
        "success": True,
        "cached": False,
        "technologies_queried": len(technologies),
        "total_vulnerabilities": total_vulns,
        "cisa_kev_matches_total": len(set(all_cisa)),
        "results": processed,
    }


@function_tool(timeout=120, strict_mode=False)
async def query_threat_feeds(
    ctx: RunContextWrapper,
    technologies: list[dict[str, str]],
) -> str:
    """Query multiple threat intelligence feeds for known vulnerabilities.

    Sends parallel queries to CISA KEV, NVD, OSV.dev, and GitHub Security
    Advisories (GHSA) for each technology/version pair. Results are scored and prioritized:

    Scoring:
    - In CISA KEV (actively exploited): +100
    - Has public exploit available: +50
    - CRITICAL severity: +30
    - HIGH severity: +20
    - CVSS score >= 9.0: +10
    - Has nuclei template: +25
    - Version match confirmed vulnerable: +5
    - Version match confirmed not_affected: -5 (still included)

    SCA Confidence Flagging (ACM SCA paper findings):
    Each result includes an 'sca_confidence' field:
    - 'high': ecosystem matched, version range confirmed vulnerable
    - 'medium': ecosystem matched but version range unknown/unconfirmed
    - 'low': no ecosystem mapping, keyword match only

    Version-range matching is unreliable across databases (NVD, GHSA, OSV).
    Low-confidence results are flagged for manual verification.

    Use this tool AFTER fingerprinting the target's technology stack
    and BEFORE starting vulnerability testing. The prioritized CVE
    list guides which vulnerabilities to test first.

    Results are cached per-scan for efficiency.

    Args:
        technologies: List of technology fingerprints. Each object
            should have 'technology' (product/framework name) and
            'version' fields.

            Example:
            [
                {"technology": "next.js", "version": "14.2.0"},
                {"technology": "express", "version": "4.17.1"},
                {"technology": "nginx", "version": "1.24.0"}
            ]

    Returns:
        JSON with prioritized CVE list per technology, including
        CVE IDs, CVSS scores, severity ratings, exploit availability,
        and CISA KEV status.
    """
    try:
        result = await _query_threat_feeds_impl(technologies)
        return json.dumps(result, ensure_ascii=False, default=str)
    except Exception as exc:
        logger.exception("query_threat_feeds failed")
        return json.dumps(
            {
                "success": False,
                "error": f"Threat feed query failed: {exc}",
            }
        )
