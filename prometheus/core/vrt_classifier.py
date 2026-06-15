"""Bugcrowd Vulnerability Rating Taxonomy (VRT) classifier.

Fetches the official VRT JSON from GitHub, caches it locally,
and provides fuzzy matching to classify findings into the correct
VRT category + priority level.

Priority mapping:
  P1 = Critical (9.0-10.0 CVSS)
  P2 = Severe   (7.0-8.9 CVSS)
  P3 = Moderate  (4.0-6.9 CVSS)
  P4 = Low       (0.1-3.9 CVSS)
  P5 = Informational (0.0 CVSS)
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

_VRT_URL = "https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/master/vulnerability-rating-taxonomy.json"
_CACHE_PATH = Path.home() / ".prometheus" / "cache" / "bugcrowd_vrt.json"
_CACHE_MAX_AGE = 86400 * 7  # 7 days

_instance: VRTClassifier | None = None
_instance_lock = threading.Lock()

# Priority to CVSS range mapping
PRIORITY_CVSS = {
    1: (9.0, 10.0, "critical"),
    2: (7.0, 8.9, "high"),
    3: (4.0, 6.9, "medium"),
    4: (0.1, 3.9, "low"),
    5: (0.0, 0.0, "informational"),
}

# CWE to common VRT category mappings (most reliable signal)
_CWE_VRT_HINTS: dict[str, list[str]] = {
    "CWE-79": ["cross_site_scripting_xss", "xss", "improper_neutralization_of_script"],
    "CWE-80": ["cross_site_scripting_xss", "xss"],
    "CWE-89": ["sql_injection", "sqli"],
    "CWE-90": ["ldap_injection"],
    "CWE-91": ["xml_external_entity_attack_xxe", "xxe"],
    "CWE-94": ["remote_code_execution", "rce", "code_injection"],
    "CWE-95": ["remote_code_execution", "rce"],
    "CWE-78": ["remote_code_execution", "rce", "os_command_injection"],
    "CWE-200": ["sensitive_information_disclosure", "information_disclosure"],
    "CWE-209": [
        "sensitive_information_disclosure",
        "information_disclosure_through_error_messages",
    ],
    "CWE-284": [
        "insecure_direct_object_references",
        "modify_view_sensitive_information_iterable",
        "view_sensitive_information_iterable",
    ],
    "CWE-285": ["broken_access_control", "improper_authorization"],
    "CWE-287": ["broken_authentication", "improper_authentication"],
    "CWE-288": ["broken_authentication", "authentication_bypass"],
    "CWE-306": ["broken_authentication", "missing_authentication"],
    "CWE-352": ["cross_site_request_forgery_csrf", "csrf"],
    "CWE-359": ["sensitive_information_disclosure", "pii_exposure"],
    "CWE-400": ["denial_of_service_dos", "application_level_denial_of_service"],
    "CWE-434": ["unrestricted_file_upload", "file_upload"],
    "CWE-502": ["remote_code_execution", "deserialization"],
    "CWE-601": ["get_based", "open_redirect"],
    "CWE-611": ["xml_external_entity_attack_xxe", "xxe"],
    "CWE-918": [
        "internal_high_impact",
        "internal_scan_and_or_medium_impact",
        "server_side_request_forgery_ssrf",
    ],
    "CWE-862": [
        "insecure_direct_object_references",
        "modify_view_sensitive_information_iterable",
        "broken_access_control",
    ],
    "CWE-863": [
        "insecure_direct_object_references",
        "modify_view_sensitive_information_iterable",
        "broken_access_control",
    ],
    "CWE-917": ["server_side_request_forgery_ssrf", "ssrf", "expression_language_injection"],
    "CWE-1021": ["clickjacking", "improper_restriction_of_rendered_ui"],
}

# Title keyword to VRT hints
_TITLE_KEYWORDS: dict[str, list[str]] = {
    "xss": ["cross_site_scripting_xss", "universal_uxss"],
    "cross-site scripting": ["cross_site_scripting_xss", "universal_uxss"],
    "reflected": ["cross_site_scripting_xss", "universal_uxss"],
    "stored": ["cross_site_scripting_xss", "universal_uxss"],
    "dom": ["cross_site_scripting_xss", "universal_uxss"],
    "sqli": ["sql_injection"],
    "sql injection": ["sql_injection"],
    "ssrf": [
        "internal_high_impact",
        "internal_scan_and_or_medium_impact",
        "external_dns_query_only",
    ],
    "csrf": ["cross_site_request_forgery_csrf", "application_wide"],
    "cross-site request": ["cross_site_request_forgery_csrf", "application_wide"],
    "idor": [
        "insecure_direct_object_references",
        "modify_view_sensitive_information_iterable",
        "modify_view_sensitive_information_complex",
    ],
    "rce": ["remote_code_execution"],
    "remote code": ["remote_code_execution"],
    "command injection": ["remote_code_execution", "os_command_injection"],
    "file upload": ["unrestricted_file_upload"],
    "open redirect": ["get_based", "open_redirect"],
    "clickjack": ["sensitive_action", "clickjacking"],
    "cors": ["unsafe_cross_origin_resource_sharing"],
    "account enumeration": ["non_brute_force", "username_email_enumeration"],
    "username enumeration": ["non_brute_force", "username_email_enumeration"],
    "xxe": ["xml_external_entity_attack_xxe"],
    "deserialization": ["deserialization", "remote_code_execution"],
    "information disclosure": ["sensitive_information_disclosure"],
    "info disclosure": ["sensitive_information_disclosure"],
    "sensitive data": ["sensitive_information_disclosure"],
    "api key": ["sensitive_information_disclosure", "key_leak"],
    "token leak": ["sensitive_information_disclosure", "key_leak"],
    "secret leak": ["sensitive_information_disclosure", "key_leak"],
    "missing header": ["security_misconfiguration", "missing_http_headers"],
    "directory traversal": ["path_traversal", "directory_traversal"],
    "path traversal": ["path_traversal", "directory_traversal"],
    "lfi": ["path_traversal", "local_file_inclusion"],
    "race condition": ["race_condition"],
    "broken auth": ["broken_authentication"],
    "auth bypass": ["broken_authentication", "authentication_bypass"],
    "privilege escalation": ["broken_access_control", "privilege_escalation"],
    "account takeover": ["broken_authentication", "account_takeover"],
    "prompt injection": ["prompt_injection"],
    "dns rebinding": ["dns_rebinding"],
    "subdomain takeover": ["subdomain_takeover"],
    "host header": ["host_header_injection"],
    "http smuggling": ["request_smuggling"],
    "request smuggling": ["request_smuggling"],
    "prototype pollution": ["prototype_pollution"],
    "jwt": ["json_web_token_abuse", "jwt"],
    "session fixation": ["session_fixation"],
    "cookie": ["insecure_cookie_configuration"],
    "captcha": ["captcha_bypass"],
    "rate limit": ["insufficient_rate_limiting"],
    "brute force": ["insufficient_rate_limiting"],
    "password reset": ["broken_authentication_and_session_management"],
    "broken access": ["broken_access_control"],
    "mass assignment": ["mass_assignment"],
    "business logic": ["business_logic_errors"],
    "graphql": ["graphql_api_vulnerabilities"],
    "websocket": ["websocket_abuse"],
}


class VRTClassifier:
    """Classifies findings against the Bugcrowd VRT taxonomy."""

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []
        self._loaded = False
        self._lock = threading.Lock()

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            self._load_vrt()
            self._loaded = True

    def _load_vrt(self) -> None:
        """Load VRT from cache or fetch from GitHub."""
        if _CACHE_PATH.exists():
            age = time.time() - _CACHE_PATH.stat().st_mtime
            if age < _CACHE_MAX_AGE:
                try:
                    data = json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
                    self._entries = self._flatten(data["content"])
                    logger.info("Loaded %d VRT entries from cache", len(self._entries))
                    return
                except (json.JSONDecodeError, KeyError, OSError):
                    logger.debug("Cache invalid, fetching fresh VRT")

        self._fetch_and_cache()

    def _fetch_and_cache(self) -> None:
        """Fetch VRT from GitHub and cache it."""
        try:
            req = Request(_VRT_URL, headers={"User-Agent": "prometheus-vrt/1.0"})
            with urlopen(req, timeout=30) as resp:
                raw = resp.read()
            data = json.loads(raw)
            self._entries = self._flatten(data["content"])

            _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            _CACHE_PATH.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            logger.info("Fetched and cached %d VRT entries", len(self._entries))
        except Exception:
            logger.exception("Failed to fetch VRT from GitHub")
            # Try stale cache as fallback
            if _CACHE_PATH.exists():
                try:
                    data = json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
                    self._entries = self._flatten(data["content"])
                    logger.info("Using stale cache (%d entries)", len(self._entries))
                except Exception:
                    logger.exception("Stale cache also failed")

    def _flatten(self, items: list[dict[str, Any]], path: str = "") -> list[dict[str, Any]]:
        """Flatten the nested VRT tree into a searchable list."""
        results: list[dict[str, Any]] = []
        for item in items:
            current = f"{path} > {item['name']}" if path else item["name"]
            entry: dict[str, Any] = {
                "id": item["id"],
                "name": item["name"],
                "path": current,
                "type": item.get("type", "unknown"),
            }
            if "priority" in item:
                entry["priority"] = item["priority"]
                results.append(entry)
            if "children" in item:
                results.extend(self._flatten(item["children"], current))
        return results

    def classify(
        self,
        title: str = "",
        description: str = "",
        cwe: str = "",
        endpoint: str = "",
    ) -> dict[str, Any]:
        """Classify a finding into the best VRT category.

        Returns:
            {
                "vrt_category": "Category > Subcategory > Variant",
                "vrt_id": "variant_id",
                "priority": 1-5,
                "priority_label": "critical|high|medium|low|informational",
                "cvss_range": "9.0-10.0",
                "confidence": 0.0-1.0,
                "match_method": "cwe|keyword|fuzzy",
            }
        """
        self._ensure_loaded()

        if not self._entries:
            return self._fallback(cwe)

        # Try CWE match first (most reliable)
        if cwe:
            result = self._match_by_cwe(cwe)
            if result:
                return result

        # Try title keyword match
        combined_text = f"{title} {description}".lower()
        result = self._match_by_keywords(title.lower(), combined_text)
        if result:
            return result

        # Fuzzy match on combined text
        result = self._fuzzy_match(combined_text)
        if result:
            return result

        # Nothing matched
        return self._fallback(cwe)

    def _match_by_cwe(self, cwe: str) -> dict[str, Any] | None:
        """Match by CWE ID using the known mappings."""
        cwe_upper = cwe.upper().strip()
        hints = _CWE_VRT_HINTS.get(cwe_upper)
        if not hints:
            return None

        # Collect all matches, then pick the best one
        candidates: list[tuple[dict[str, Any], float]] = []

        for hint in hints:
            hint_lower = hint.lower()
            # Exact ID match (highest confidence)
            for entry in self._entries:
                if hint_lower == entry["id"].lower():
                    candidates.append((entry, 0.95))
            # ID contains hint
            for entry in self._entries:
                if hint_lower in entry["id"].lower() and (entry, 0.9) not in candidates:
                    candidates.append((entry, 0.9))
            # Name contains hint
            for entry in self._entries:
                if hint_lower in entry["name"].lower():
                    candidates.append((entry, 0.85))
            # Broader: match on path
            for entry in self._entries:
                entry_norm = entry["path"].lower().replace(" ", "_").replace("-", "_")
                if hint_lower in entry_norm:
                    candidates.append((entry, 0.7))

        if not candidates:
            return None

        # Prefer entries NOT under "AI Application Security" for standard CWEs
        # (unless the CWE is inherently AI-related)
        ai_cwes = set()  # add AI-specific CWEs here if needed
        non_ai = [
            (e, s)
            for e, s in candidates
            if not e["path"].startswith("AI Application") or cwe_upper in ai_cwes
        ]
        if non_ai:
            candidates = non_ai

        # Pick the highest confidence match
        best_entry, best_score = max(candidates, key=lambda x: x[1])
        return self._build_result(best_entry, best_score, "cwe")

    def _match_by_keywords(self, title_lower: str, combined_lower: str) -> dict[str, Any] | None:
        """Match by title keywords."""
        # Check title keywords (exact substring match)
        for keyword, hints in _TITLE_KEYWORDS.items():
            if keyword in title_lower:
                for hint in hints:
                    hint_lower = hint.lower()
                    for entry in self._entries:
                        if hint_lower in entry["id"].lower():
                            return self._build_result(entry, 0.8, "keyword")
                    # Broader match
                    for entry in self._entries:
                        entry_norm = entry["path"].lower().replace(" ", "_").replace("-", "_")
                        if hint_lower in entry_norm:
                            return self._build_result(entry, 0.65, "keyword")

        return None

    def _fuzzy_match(self, text: str) -> dict[str, Any] | None:
        """Last-resort fuzzy matching using token overlap."""
        text_tokens = set(re.findall(r"[a-z_]+", text))
        if not text_tokens:
            return None

        best_score = 0.0
        best_entry = None

        for entry in self._entries:
            entry_tokens = set(re.findall(r"[a-z_]+", entry["id"] + " " + entry["name"].lower()))
            if not entry_tokens:
                continue
            overlap = len(text_tokens & entry_tokens)
            if overlap == 0:
                continue
            # Jaccard-like score weighted by entry token count
            score = overlap / (len(entry_tokens) + 1)
            if score > best_score:
                best_score = score
                best_entry = entry

        if best_entry and best_score >= 0.15:
            return self._build_result(best_entry, min(best_score, 0.6), "fuzzy")

        return None

    def _build_result(
        self, entry: dict[str, Any], confidence: float, method: str
    ) -> dict[str, Any]:
        priority = entry.get("priority")
        if not isinstance(priority, int) or priority < 1 or priority > 5:
            priority = 3  # default to medium if missing/invalid
        cvss_range, label = self._priority_to_cvss(priority)
        return {
            "vrt_category": entry["path"],
            "vrt_id": entry["id"],
            "priority": priority,
            "priority_label": label,
            "cvss_range": cvss_range,
            "confidence": confidence,
            "match_method": method,
        }

    def _fallback(self, cwe: str) -> dict[str, Any]:
        return {
            "vrt_category": "Unknown",
            "vrt_id": "unknown",
            "priority": 3,
            "priority_label": "medium",
            "cvss_range": "4.0-6.9",
            "confidence": 0.0,
            "match_method": "fallback",
        }

    @staticmethod
    def _priority_to_cvss(priority: int) -> tuple[str, str]:
        lo, hi, label = PRIORITY_CVSS.get(priority, (4.0, 6.9, "medium"))
        return f"{lo}-{hi}", label

    def get_all_entries(self) -> list[dict[str, Any]]:
        """Return all VRT entries (for browsing)."""
        self._ensure_loaded()
        return list(self._entries)

    def search(self, query: str) -> list[dict[str, Any]]:
        """Search VRT entries by keyword."""
        self._ensure_loaded()
        query_lower = query.lower()
        results = []
        for entry in self._entries:
            if (
                query_lower in entry["id"].lower()
                or query_lower in entry["name"].lower()
                or query_lower in entry["path"].lower()
            ):
                results.append(
                    {
                        "path": entry["path"],
                        "id": entry["id"],
                        "priority": entry.get("priority"),
                    }
                )
        return results[:20]  # limit results


def get_vrt_classifier() -> VRTClassifier:
    """Get the singleton VRT classifier."""
    global _instance
    if _instance is not None:
        return _instance
    with _instance_lock:
        if _instance is not None:
            return _instance
        _instance = VRTClassifier()
        return _instance
