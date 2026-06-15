"""Feed ingestion — pulls vulnerability data from multiple online sources into the local DB."""

from __future__ import annotations

import csv
import gzip
import io
import logging
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx


if TYPE_CHECKING:
    from prometheus.tools.threat_intel.local_db import ThreatIntelDB


logger = logging.getLogger(__name__)

# Ecosystem mapping (lowercase) for GHSA/OSV
ECOSYSTEM_MAP = {
    "npm": "npm",
    "node": "npm",
    "next.js": "npm",
    "nextjs": "npm",
    "react": "npm",
    "express": "npm",
    "angular": "npm",
    "vue": "npm",
    "nuxt": "npm",
    "python": "pypi",
    "pip": "pypi",
    "flask": "pypi",
    "django": "pypi",
    "fastapi": "pypi",
    "uvicorn": "pypi",
    "go": "go",
    "golang": "go",
    "rust": "crates.io",
    "cargo": "crates.io",
    "ruby": "rubygems",
    "rails": "rubygems",
    "gem": "rubygems",
    "java": "maven",
    "maven": "maven",
    "spring": "maven",
    "php": "packagist",
    "composer": "packagist",
    "laravel": "packagist",
    "nuget": "nuget",
    ".net": "nuget",
    "csharp": "nuget",
    "swift": "swift",
    "cocoapods": "cocoapods",
    "pub": "pub",
    "dart": "pub",
    # Infrastructure / proxy / CDN
    "cloudflare": "npm",
    "vercel": "npm",
    "envoy": "go",
    "nginx": "go",
    "apache": "maven",
    "redis": "go",
    "postgresql": "go",
    "mysql": "maven",
    "elasticsearch": "maven",
    "kubernetes": "go",
    "docker": "go",
    "istio": "go",
    "consul": "go",
    "vault": "go",
    "terraform": "go",
}


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
    except Exception:
        pass
    return None


def _classify_ref(url: str) -> str:
    """Classify a reference URL by type."""
    url_lower = url.lower()
    if any(k in url_lower for k in ("exploit", "exploit-db.com", "metasploit")):
        return "exploit"
    if "poc" in url_lower or "proof-of-concept" in url_lower:
        return "poc"
    if any(k in url_lower for k in ("patch", "commit", "fix", "pull/", "merge-request")):
        return "patch"
    if any(k in url_lower for k in ("advisory", "security", "bulletin", "announce")):
        return "advisory"
    return "reference"


# ---------------------------------------------------------------------------
# EPSS (Exploit Prediction Scoring System)
# ---------------------------------------------------------------------------


def ingest_epss(db: ThreatIntelDB) -> dict[str, Any]:
    """Download EPSS bulk CSV and update CVE scores."""
    start = time.time()
    url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    try:
        with httpx.Client(timeout=120.0, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()

        # Decompress gzip
        raw = gzip.decompress(resp.content)
        text = raw.decode("utf-8")

        # Parse CSV (skip comment lines starting with # and header row)
        reader = csv.reader(io.StringIO(text))
        count = 0
        batch = []
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            # Skip header row (first column is "CVE" or starts with a letter)
            if row[0] and not row[0][0].isdigit() and not row[0].startswith("CVE-"):
                continue
            if len(row) >= 3:
                cve_id = row[0].strip()
                try:
                    epss_score = float(row[1])
                    epss_percentile = float(row[2])
                except (ValueError, IndexError):
                    continue
                if cve_id.startswith("CVE-"):
                    batch.append((cve_id, epss_score, epss_percentile))
                    count += 1

        # Batch update — only update CVEs that already exist in our DB
        for cve_id, score, percentile in batch:
            db._conn.execute(
                "UPDATE cve SET epss_score = ?, epss_percentile = ? WHERE cve_id = ?",
                (score, percentile, cve_id),
            )
        db.commit()

        duration = time.time() - start
        db.update_feed_status("epss", "ok", count, duration_seconds=duration)
        logger.info("EPSS: updated %d CVE scores in %.1fs", count, duration)
        return {"status": "ok", "count": count, "duration": duration}

    except Exception as exc:
        duration = time.time() - start
        db.update_feed_status("epss", "error", error_message=str(exc), duration_seconds=duration)
        logger.exception("EPSS ingestion failed: %s", exc)
        return {"status": "error", "error": str(exc), "duration": duration}


# ---------------------------------------------------------------------------
# CISA KEV (Known Exploited Vulnerabilities)
# ---------------------------------------------------------------------------


def ingest_cisa_kev(db: ThreatIntelDB) -> dict[str, Any]:
    """Download full CISA KEV catalog."""
    start = time.time()
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()

        vulns = data.get("vulnerabilities", [])
        count = 0
        for v in vulns:
            cve_id = v.get("cveID", "")
            if not cve_id:
                continue
            db.upsert_cve(
                cve_id=cve_id,
                description=v.get("shortDescription", ""),
                severity="CRITICAL",  # All KEV entries are critical
                cisa_kev=True,
                has_exploit=True,  # All KEV are actively exploited
                published_at=v.get("dateAdded", ""),
                sources=["CISA_KEV"],
                raw_data=v,
            )
            db.upsert_package(
                cve_id=cve_id,
                ecosystem="",
                package_name=v.get("product", "").lower(),
            )
            count += 1
        db.commit()

        duration = time.time() - start
        db.update_feed_status("cisa_kev", "ok", count, duration_seconds=duration)
        logger.info("CISA KEV: ingested %d entries in %.1fs", count, duration)
        return {"status": "ok", "count": count, "duration": duration}

    except Exception as exc:
        duration = time.time() - start
        db.update_feed_status(
            "cisa_kev", "error", error_message=str(exc), duration_seconds=duration
        )
        logger.exception("CISA KEV ingestion failed: %s", exc)
        return {"status": "error", "error": str(exc), "duration": duration}


# ---------------------------------------------------------------------------
# NVD (National Vulnerability Database)
# ---------------------------------------------------------------------------


def ingest_nvd_recent(db: ThreatIntelDB, days: int = 7) -> dict[str, Any]:
    """Fetch recent high+critical CVEs from NVD."""
    start = time.time()
    count = 0
    try:
        from datetime import timedelta

        end = datetime.now(UTC)
        start_date = end - timedelta(days=days)
        fmt = "%Y-%m-%dT%H:%M:%S.000"

        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            for severity in ("HIGH", "CRITICAL"):
                params = {
                    "pubStartDate": start_date.strftime(fmt),
                    "pubEndDate": end.strftime(fmt),
                    "cvssV3Severity": severity,
                    "resultsPerPage": 200,
                }
                resp = client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()

                for v in data.get("vulnerabilities", []):
                    cve = v.get("cve", {})
                    cve_id = cve.get("id", "")
                    if not cve_id:
                        continue

                    # Extract CVSS
                    cvss_score = 0.0
                    sev = ""
                    metrics = cve.get("metrics", {})
                    for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        ml = metrics.get(mk, [])
                        if ml:
                            cd = ml[0].get("cvssData", {})
                            cvss_score = cd.get("baseScore", 0.0)
                            sev = cd.get("baseSeverity", "")
                            break

                    # Extract exploit refs
                    has_exploit = False
                    for ref in cve.get("references", []):
                        if "Exploit" in ref.get("tags", []):
                            has_exploit = True
                            break

                    desc = ""
                    for d in cve.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = d.get("value", "")[:500]
                            break

                    db.upsert_cve(
                        cve_id=cve_id,
                        description=desc,
                        severity=sev,
                        cvss_score=cvss_score,
                        has_exploit=has_exploit,
                        published_at=cve.get("published", ""),
                        sources=["NVD"],
                        raw_data=cve,
                    )
                    # Store references
                    for ref in cve.get("references", []):
                        url = ref.get("url", "")
                        if url:
                            db.upsert_reference(cve_id, url, _classify_ref(url))
                    count += 1

        db.commit()
        duration = time.time() - start
        db.update_feed_status("nvd_recent", "ok", count, duration_seconds=duration)
        logger.info("NVD recent (%d days): ingested %d CVEs in %.1fs", days, count, duration)
        return {"status": "ok", "count": count, "duration": duration}

    except Exception as exc:
        duration = time.time() - start
        db.update_feed_status(
            "nvd_recent", "error", error_message=str(exc), duration_seconds=duration
        )
        logger.exception("NVD recent ingestion failed: %s", exc)
        return {"status": "error", "error": str(exc), "duration": duration}


# ---------------------------------------------------------------------------
# GHSA (GitHub Security Advisories)
# ---------------------------------------------------------------------------


def ingest_ghsa_bulk(db: ThreatIntelDB) -> dict[str, Any]:
    """Fetch advisories per ecosystem from GitHub REST API."""
    start = time.time()
    count = 0
    token = _get_github_token()
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "prometheus-threat-intel"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    ecosystems = ["npm", "pip", "go", "maven", "nuget", "rubygems", "rust", "composer"]

    try:
        with httpx.Client(timeout=20.0, follow_redirects=True, headers=headers) as client:
            for eco in ecosystems:
                for severity in ("high", "critical"):
                    try:
                        resp = client.get(
                            "https://api.github.com/advisories",
                            params={
                                "ecosystem": eco,
                                "severity": severity,
                                "per_page": 100,
                                "sort": "published",
                                "direction": "desc",
                            },
                        )
                        resp.raise_for_status()
                        advisories = resp.json()
                        if not isinstance(advisories, list):
                            logger.warning(
                                "GHSA %s/%s returned non-list: %s",
                                eco,
                                severity,
                                type(advisories).__name__,
                            )
                            continue

                        for adv in advisories:
                            ghsa_id = adv.get("ghsa_id", "")
                            cve_id = ""
                            for ident in adv.get("identifiers", []):
                                if ident.get("type") == "CVE":
                                    cve_id = ident.get("value", "")
                                    break
                            if not cve_id:
                                cve_id = ghsa_id

                            cvss_data = adv.get("cvss", {})
                            cvss_score = (cvss_data or {}).get("score", 0.0) or 0.0
                            sev = (adv.get("severity") or "").upper()

                            has_exploit = any(
                                (
                                    "exploit" in (ref.get("url") or "").lower()
                                    if isinstance(ref, dict)
                                    else "exploit" in ref.lower()
                                )
                                or (
                                    "poc" in (ref.get("url") or "").lower()
                                    if isinstance(ref, dict)
                                    else "poc" in ref.lower()
                                )
                                for ref in adv.get("references", [])
                            )

                            db.upsert_cve(
                                cve_id=cve_id,
                                description=adv.get("summary", "")[:500],
                                severity=sev,
                                cvss_score=cvss_score,
                                has_exploit=has_exploit,
                                published_at=adv.get("published_at", ""),
                                sources=["GHSA"],
                            )

                            # Store affected packages
                            for vuln in adv.get("vulnerabilities", []):
                                pkg = vuln.get("package", {})
                                pkg_name = pkg.get("name", "") if isinstance(pkg, dict) else ""
                                if pkg_name:
                                    patched = vuln.get("first_patched_version", "")
                                    # REST API returns string, not dict
                                    patched_str = patched if isinstance(patched, str) else ""
                                    db.upsert_package(
                                        cve_id=cve_id,
                                        ecosystem=eco,
                                        package_name=pkg_name.lower(),
                                        vulnerable_version_range=vuln.get(
                                            "vulnerableVersionRange", ""
                                        ),
                                        patched_version=patched_str,
                                    )

                            # Store references
                            for ref in adv.get("references", []):
                                url = (
                                    ref.get("url", "")
                                    if isinstance(ref, dict)
                                    else (ref if isinstance(ref, str) else "")
                                )
                                if url:
                                    db.upsert_reference(cve_id, url, _classify_ref(url))

                            count += 1

                    except Exception as exc:
                        logger.warning("GHSA %s/%s failed: %s", eco, severity, exc)
                        continue

        db.commit()
        duration = time.time() - start
        db.update_feed_status("ghsa_bulk", "ok", count, duration_seconds=duration)
        logger.info("GHSA bulk: ingested %d advisories in %.1fs", count, duration)
        return {"status": "ok", "count": count, "duration": duration}

    except Exception as exc:
        duration = time.time() - start
        db.update_feed_status(
            "ghsa_bulk", "error", error_message=str(exc), duration_seconds=duration
        )
        logger.exception("GHSA bulk ingestion failed: %s", exc)
        return {"status": "error", "error": str(exc), "duration": duration}


# ---------------------------------------------------------------------------
# Shodan CVEDB
# ---------------------------------------------------------------------------


def ingest_shodan_recent(db: ThreatIntelDB, days: int = 7) -> dict[str, Any]:
    """Fetch the 1000 most recent CVEs from Shodan CVEDB (https://cvedb.shodan.io/cves)."""
    start = time.time()
    count = 0
    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            # Shodan CVEDB /cves returns the 1000 most recent CVEs
            resp = client.get("https://cvedb.shodan.io/cves")
            resp.raise_for_status()
            data = resp.json()

            cves = data if isinstance(data, list) else data.get("cves", [])
            for item in cves:
                cve_id = item.get("cve_id") or item.get("id", "")
                if not cve_id or not cve_id.startswith("CVE-"):
                    continue

                cvss = item.get("cvss", 0.0) or 0.0
                sev = item.get("severity", "")
                if not sev and cvss >= 9.0:
                    sev = "CRITICAL"
                elif not sev and cvss >= 7.0:
                    sev = "HIGH"

                db.upsert_cve(
                    cve_id=cve_id,
                    description=item.get("summary", "")[:500],
                    severity=sev.upper(),
                    cvss_score=cvss,
                    published_at=item.get("published", ""),
                    sources=["SHODAN"],
                )

                # Store references
                for ref in item.get("references", []):
                    if isinstance(ref, str):
                        db.upsert_reference(cve_id, ref, _classify_ref(ref))

                count += 1

        db.commit()
        duration = time.time() - start
        db.update_feed_status("shodan_recent", "ok", count, duration_seconds=duration)
        logger.info("Shodan CVEDB: ingested %d recent CVEs in %.1fs", count, duration)
        return {"status": "ok", "count": count, "duration": duration}

    except Exception as exc:
        duration = time.time() - start
        db.update_feed_status(
            "shodan_recent", "error", error_message=str(exc), duration_seconds=duration
        )
        logger.exception("Shodan CVEDB ingestion failed: %s", exc)
        return {"status": "error", "error": str(exc), "duration": duration}


# ---------------------------------------------------------------------------
# CIRCL Vulnerability-Lookup
# ---------------------------------------------------------------------------


def ingest_circl_recent(db: ThreatIntelDB) -> dict[str, Any]:
    """Fetch recent CVEs from CIRCL Vulnerability-Lookup (CVE 5.0 format)."""
    start = time.time()
    count = 0
    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            resp = client.get("https://vulnerability.circl.lu/api/vulnerability/recent")
            resp.raise_for_status()
            data = resp.json()

            items = data if isinstance(data, list) else data.get("vulnerabilities", [])
            for item in items:
                # CVE 5.0 format: cveMetadata.cveId
                meta = item.get("cveMetadata") or {}
                cve_id = meta.get("cveId", "")
                if not cve_id or not cve_id.startswith("CVE-"):
                    continue

                # Extract description from containers.cna.descriptions
                containers = item.get("containers") or {}
                cna = containers.get("cna") or {}
                description = ""
                for desc in cna.get("descriptions") or []:
                    if isinstance(desc, dict) and desc.get("lang") == "en":
                        description = desc.get("value", "")[:500]
                        break
                if not description:
                    for desc in cna.get("descriptions") or []:
                        if isinstance(desc, dict):
                            description = desc.get("value", "")[:500]
                            break

                # Extract CVSS from metrics
                cvss = 0.0
                sev = ""
                for metric in cna.get("metrics") or []:
                    if not isinstance(metric, dict):
                        continue
                    # Try CVSS v4.0, then v3.1, then v3.0
                    for version_key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                        cvss_data = metric.get(version_key)
                        if isinstance(cvss_data, dict):
                            cvss = float(cvss_data.get("baseScore", 0.0) or 0.0)
                            sev = str(cvss_data.get("baseSeverity", "") or "")
                            break
                    if cvss > 0:
                        break

                db.upsert_cve(
                    cve_id=cve_id,
                    description=description,
                    severity=sev.upper() if sev else "",
                    cvss_score=cvss,
                    published_at=meta.get("datePublished", ""),
                    sources=["CIRCL"],
                )

                # Extract references from containers.cna.references
                for ref in cna.get("references") or []:
                    if isinstance(ref, dict):
                        ref_url = ref.get("url", "")
                        if ref_url:
                            db.upsert_reference(cve_id, ref_url, _classify_ref(ref_url))

                count += 1

        db.commit()
        duration = time.time() - start
        db.update_feed_status("circl_recent", "ok", count, duration_seconds=duration)
        logger.info("CIRCL: ingested %d recent CVEs in %.1fs", count, duration)
        return {"status": "ok", "count": count, "duration": duration}

    except Exception as exc:
        duration = time.time() - start
        db.update_feed_status(
            "circl_recent", "error", error_message=str(exc), duration_seconds=duration
        )
        logger.exception("CIRCL ingestion failed: %s", exc)
        return {"status": "error", "error": str(exc), "duration": duration}


# ---------------------------------------------------------------------------
# CISA Advisories RSS
# ---------------------------------------------------------------------------


def ingest_cisa_advisories(db: ThreatIntelDB) -> dict[str, Any]:
    """Parse CISA cybersecurity advisories RSS feed."""
    start = time.time()
    count = 0
    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            resp = client.get("https://www.cisa.gov/cybersecurity-advisories/all.xml")
            resp.raise_for_status()
            xml_text = resp.text

        # Simple XML parsing (no lxml dependency)
        import re

        # Extract CVE IDs from advisory titles and descriptions
        cve_pattern = re.compile(r"(CVE-\d{4}-\d{4,})")
        cves = set(cve_pattern.findall(xml_text))

        for cve_id in cves:
            db.upsert_cve(
                cve_id=cve_id,
                description="Referenced in CISA cybersecurity advisory",
                sources=["CISA_ADVISORY"],
            )
            count += 1
        db.commit()

        duration = time.time() - start
        db.update_feed_status("cisa_advisories", "ok", count, duration_seconds=duration)
        logger.info("CISA Advisories: found %d CVE references in %.1fs", count, duration)
        return {"status": "ok", "count": count, "duration": duration}

    except Exception as exc:
        duration = time.time() - start
        db.update_feed_status(
            "cisa_advisories", "error", error_message=str(exc), duration_seconds=duration
        )
        logger.exception("CISA Advisories ingestion failed: %s", exc)
        return {"status": "error", "error": str(exc), "duration": duration}


# ---------------------------------------------------------------------------
# Exploit-DB (Git clone for offline search)
# ---------------------------------------------------------------------------

EXPLOITDB_PATH = str(
    Path(os.environ.get("PROMETHEUS_DATA_DIR", str(Path.home() / ".prometheus"))) / "exploitdb"
)


def ingest_exploitdb(db: ThreatIntelDB) -> dict[str, Any]:
    """Clone/pull Exploit-DB git repo and index CVE mappings."""
    import os

    start = time.time()
    count = 0

    try:
        # Clone or pull
        if os.path.isdir(os.path.join(EXPLOITDB_PATH, ".git")):
            subprocess.run(
                ["git", "-C", EXPLOITDB_PATH, "pull", "--quiet"],
                capture_output=True,
                timeout=120,
            )
        else:
            os.makedirs(os.path.dirname(EXPLOITDB_PATH), exist_ok=True)
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth=1",
                    "--quiet",
                    "https://gitlab.com/exploit-database/exploitdb.git",
                    EXPLOITDB_PATH,
                ],
                capture_output=True,
                timeout=300,
            )

        # Parse the CSV files_exploits.csv and files_shellcodes.csv
        for csv_name in ("files_exploits.csv", "files_shellcodes.csv"):
            csv_path = os.path.join(EXPLOITDB_PATH, csv_name)
            if not os.path.isfile(csv_path):
                continue
            try:
                with open(csv_path, encoding="utf-8", errors="replace") as f:
                    reader = csv.reader(f)
                    header = next(reader, None)
                    if not header:
                        continue
                    # Find column indices
                    try:
                        id_idx = header.index("id")
                        desc_idx = header.index("description")
                        cve_idx = header.index("codes") if "codes" in header else -1
                    except ValueError:
                        continue

                    for row in reader:
                        if len(row) <= max(id_idx, desc_idx):
                            continue
                        edb_id = row[id_idx]
                        desc = row[desc_idx]
                        cve_str = row[cve_idx] if cve_idx >= 0 and len(row) > cve_idx else ""

                        # Extract CVE IDs from codes column
                        import re

                        cves = re.findall(r"(CVE-\d{4}-\d{4,})", cve_str)
                        for cve_id in cves:
                            db.upsert_cve(
                                cve_id=cve_id,
                                description=desc[:500],
                                has_exploit=True,
                                sources=["EXPLOIT_DB"],
                            )
                            db.upsert_reference(
                                cve_id,
                                f"https://www.exploit-db.com/exploits/{edb_id}",
                                "exploit",
                            )
                            count += 1
            except Exception as exc:
                logger.warning("Exploit-DB CSV parse failed for %s: %s", csv_name, exc)

        db.commit()
        duration = time.time() - start
        db.update_feed_status("exploitdb", "ok", count, duration_seconds=duration)
        logger.info("Exploit-DB: indexed %d CVE-exploit mappings in %.1fs", count, duration)
        return {"status": "ok", "count": count, "duration": duration}

    except Exception as exc:
        duration = time.time() - start
        db.update_feed_status(
            "exploitdb", "error", error_message=str(exc), duration_seconds=duration
        )
        logger.exception("Exploit-DB ingestion failed: %s", exc)
        return {"status": "error", "error": str(exc), "duration": duration}


# ---------------------------------------------------------------------------
# Wordfence Intelligence (WordPress)
# ---------------------------------------------------------------------------


def ingest_wordfence(db: ThreatIntelDB) -> dict[str, Any]:
    """Fetch WordPress vulnerabilities from Wordfence Intelligence API."""
    import os

    start = time.time()
    count = 0

    api_key = os.environ.get("WORDFENCE_API_KEY", "")
    if not api_key:
        logger.info("Wordfence: no API key (set WORDFENCE_API_KEY), skipping")
        db.update_feed_status("wordfence", "skipped", error_message="No API key")
        return {"status": "skipped", "error": "No WORDFENCE_API_KEY set"}

    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            # Wordfence API v1
            resp = client.get(
                "https://www.wordfence.com/api/intelligence/v1/vulnerabilities",
                headers={"Authorization": f"Bearer {api_key}"},
                params={"per_page": 100},
            )
            resp.raise_for_status()
            data = resp.json()

            vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
            for v in vulns:
                cve_id = v.get("cve") or ""
                if not cve_id:
                    continue

                sev = (v.get("severity") or "").upper()
                cvss = v.get("cvss_score", 0.0) or 0.0

                db.upsert_cve(
                    cve_id=cve_id,
                    description=v.get("title", "")[:500],
                    severity=sev,
                    cvss_score=cvss,
                    published_at=v.get("disclosure_date", ""),
                    sources=["WORDFENCE"],
                )

                # WordPress plugin/theme/core
                software = v.get("software", {})
                if isinstance(software, dict):
                    for sw_type in ("plugins", "themes", "core"):
                        for sw in software.get(sw_type, []):
                            if isinstance(sw, dict):
                                slug = sw.get("slug", "")
                                if slug:
                                    db.upsert_package(
                                        cve_id=cve_id,
                                        ecosystem="wordpress",
                                        package_name=slug.lower(),
                                        vulnerable_version_range=sw.get("affected_versions", ""),
                                        patched_version=sw.get("patched_version", ""),
                                    )

                count += 1

        db.commit()
        duration = time.time() - start
        db.update_feed_status("wordfence", "ok", count, duration_seconds=duration)
        logger.info("Wordfence: ingested %d WordPress vulns in %.1fs", count, duration)
        return {"status": "ok", "count": count, "duration": duration}

    except Exception as exc:
        duration = time.time() - start
        db.update_feed_status(
            "wordfence", "error", error_message=str(exc), duration_seconds=duration
        )
        logger.exception("Wordfence ingestion failed: %s", exc)
        return {"status": "error", "error": str(exc), "duration": duration}


# ---------------------------------------------------------------------------
# Vulners (exploit aggregation)
# ---------------------------------------------------------------------------


def ingest_vulners_recent(db: ThreatIntelDB) -> dict[str, Any]:
    """Fetch recent vulnerabilities from Vulners API."""
    import os

    start = time.time()
    count = 0

    api_key = os.environ.get("VULNERS_API_KEY", "")
    if not api_key:
        logger.info("Vulners: no API key (set VULNERS_API_KEY), skipping")
        db.update_feed_status("vulners", "skipped", error_message="No API key")
        return {"status": "skipped", "error": "No VULNERS_API_KEY set"}

    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            # Search for recent high-severity CVEs
            resp = client.post(
                "https://vulners.com/api/v3/search/lucene/",
                json={
                    "query": "type:cve AND published:[now-7d TO now] AND cvss.score:[7 TO 10]",
                    "size": 200,
                },
                headers={"X-Api-Key": api_key},
            )
            resp.raise_for_status()
            data = resp.json()

            results = data.get("data", {}).get("search", [])
            for item in results:
                source = item.get("_source", {})
                cve_id = source.get("id", "")
                if not cve_id or not cve_id.startswith("CVE-"):
                    continue

                cvss = source.get("cvss", {}).get("score", 0.0) or 0.0
                sev = source.get("cvss", {}).get("severity", "").upper()

                has_exploit = False
                for ref in source.get("references", []):
                    if "exploit" in ref.lower() or "poc" in ref.lower():
                        has_exploit = True
                        break

                db.upsert_cve(
                    cve_id=cve_id,
                    description=source.get("description", "")[:500],
                    severity=sev,
                    cvss_score=cvss,
                    has_exploit=has_exploit,
                    published_at=source.get("published", ""),
                    sources=["VULNERS"],
                )

                # Store references
                for ref in source.get("references", []):
                    if ref.startswith("http"):
                        db.upsert_reference(cve_id, ref, _classify_ref(ref))

                count += 1

        db.commit()
        duration = time.time() - start
        db.update_feed_status("vulners", "ok", count, duration_seconds=duration)
        logger.info("Vulners: ingested %d CVEs in %.1fs", count, duration)
        return {"status": "ok", "count": count, "duration": duration}

    except Exception as exc:
        duration = time.time() - start
        db.update_feed_status("vulners", "error", error_message=str(exc), duration_seconds=duration)
        logger.exception("Vulners ingestion failed: %s", exc)
        return {"status": "error", "error": str(exc), "duration": duration}


# ---------------------------------------------------------------------------
# Master orchestrator
# ---------------------------------------------------------------------------


def ingest_all(db: ThreatIntelDB, min_intervals: dict[str, int] | None = None) -> dict[str, Any]:
    """Run all feed ingesters and return summary.

    Skips feeds that were updated recently based on *min_intervals*
    (seconds). Default intervals: small/fast feeds every hour, large
    feeds every 6-24 hours.
    """
    start = time.time()
    results = {}
    total_records = 0
    errors = []

    # Default minimum intervals per feed (seconds)
    if min_intervals is None:
        min_intervals = {
            "cisa_kev": 7200,  # 2h — small, fast
            "nvd_recent": 3600,  # 1h — small (7 days)
            "ghsa_bulk": 21600,  # 6h — medium
            "epss": 86400,  # 24h — large (338K records)
            "shodan_recent": 3600,  # 1h — small (1000 CVEs)
            "circl_recent": 3600,  # 1h — small (~30 CVEs)
            "cisa_advisories": 7200,  # 2h — small
            "exploitdb": 86400,  # 24h — large (30K mappings)
            "wordfence": 21600,  # 6h — requires API key
            "vulners": 21600,  # 6h — requires API key
        }

    # Read feed_status to find recently-updated feeds
    recent_feeds: set[str] = set()
    try:
        for name, interval in min_intervals.items():
            if name in db.get_feed_freshness(max_age_seconds=interval):
                recent_feeds.add(name)
                logger.debug(
                    "Skipping %s — updated within last %ds",
                    name,
                    interval,
                )
    except Exception:
        pass  # feed_status table might not exist yet

    # Order matters: CISA KEV first (marks has_exploit), then EPSS (enriches scores)
    feed_functions = [
        ("cisa_kev", ingest_cisa_kev),
        ("nvd_recent", lambda db: ingest_nvd_recent(db, days=7)),
        ("ghsa_bulk", ingest_ghsa_bulk),
        ("epss", ingest_epss),
        ("shodan_recent", ingest_shodan_recent),
        ("circl_recent", ingest_circl_recent),
        ("cisa_advisories", ingest_cisa_advisories),
        ("exploitdb", ingest_exploitdb),
        ("wordfence", ingest_wordfence),
        ("vulners", ingest_vulners_recent),
    ]

    total_records = 0
    errors = []

    for name, func in feed_functions:
        if name in recent_feeds:
            logger.debug("Skipping %s — recently updated", name)
            continue
        logger.info("Ingesting %s...", name)
        try:
            result = func(db)
            results[name] = result
            if result.get("status") == "ok":
                total_records += result.get("count", 0)
            elif result.get("status") == "error":
                errors.append(f"{name}: {result.get('error', 'unknown')}")
        except Exception as exc:
            results[name] = {"status": "error", "error": str(exc)}
            errors.append(f"{name}: {exc}")
            logger.exception("Feed %s crashed: %s", name, exc)

    duration = time.time() - start
    summary = {
        "total_records": total_records,
        "total_duration": duration,
        "feeds": results,
        "errors": errors,
        "db_stats": db.get_stats(),
    }

    logger.info(
        "Threat intel refresh complete: %d records in %.1fs, %d errors",
        total_records,
        duration,
        len(errors),
    )
    return summary
