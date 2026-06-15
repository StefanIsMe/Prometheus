"""Threat model — STRIDE / OWASP / MASVS / CWE categorization for an engagement.

Pre-analysis step that narrows the finding search space. Returns a
:data:`ThreatModel` dataclass with target_kind, ranked STRIDE categories,
OWASP Top 10 / MASVS / CWE categories, and 3-5 hypotheses to test first.

For v1, the threat model is a *structured prompt template* + a *fallback
heuristic* when no LLM is available. The LLM call itself is performed by
the runner (see Change 1.1 wiring) so this module stays
import-and-test friendly.
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

logger = logging.getLogger(__name__)


# STRIDE categories — Microsoft threat modeling taxonomy.
STRIDE_CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)


# Lightweight OWASP Top 10 (2021) + MASVS v2 + CWE memory-safety baselines.
OWASP_2021 = (
    "A01:2021-Broken Access Control",
    "A02:2021-Cryptographic Failures",
    "A03:2021-Injection",
    "A04:2021-Insecure Design",
    "A05:2021-Security Misconfiguration",
    "A06:2021-Vulnerable and Outdated Components",
    "A07:2021-Identification and Authentication Failures",
    "A08:2021-Software and Data Integrity Failures",
    "A09:2021-Security Logging and Monitoring Failures",
    "A10:2021-Server-Side Request Forgery",
)

MASVS_V2 = (
    "MASVS-STORAGE-1",
    "MASVS-STORAGE-2",
    "MASVS-CRYPTO-1",
    "MASVS-AUTH-1",
    "MASVS-AUTH-2",
    "MASVS-AUTH-3",
    "MASVS-NETWORK-1",
    "MASVS-NETWORK-2",
    "MASVS-PLATFORM-1",
    "MASVS-PLATFORM-2",
    "MASVS-CODE-1",
    "MASVS-CODE-2",
    "MASVS-RESILIENCE-1",
)

CWE_MEMORY_SAFETY = (
    "CWE-119",  # buffer overflow
    "CWE-120",  # classic buffer overflow
    "CWE-125",  # out-of-bounds read
    "CWE-787",  # out-of-bounds write
    "CWE-416",  # use-after-free
    "CWE-476",  # NULL pointer deref
    "CWE-190",  # integer overflow
)


@dataclass
class ThreatModel:
    """A target-scoped threat model output."""

    target_kind: str  # "web-api" | "spa" | "native-binary" | "mobile" | "unknown"
    stride_ranked: list[str] = field(default_factory=list)
    owasp_ranked: list[str] = field(default_factory=list)
    masvs_ranked: list[str] = field(default_factory=list)
    cwe_ranked: list[str] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def top_categories(self, n: int = 5) -> dict[str, list[str]]:
        return {
            "stride": self.stride_ranked[:n],
            "owasp": self.owasp_ranked[:n],
            "masvs": self.masvs_ranked[:n],
            "cwe": self.cwe_ranked[:n],
        }


# ----------------------------------------------------------------------
# Heuristic target classification
# ----------------------------------------------------------------------
_NATIVE_HINTS = re.compile(
    r"\b(cpp|c\+\+|c-|native|elf|macho|pe\b|exe|dll|so\b|dylib|kernel|driver|"
    r"firmware|iot|embedded)\b",
    re.IGNORECASE,
)
_SPA_HINTS = re.compile(
    r"\b(react|next\.?js|vue|angular|svelte|nuxt|gatsby|spa|single[- ]page|"
    r"create-react-app|webpack|vite|parcel)\b",
    re.IGNORECASE,
)
_MOBILE_HINTS = re.compile(
    r"\b(ios|android|swift|kotlin|flutter|react[- ]native|expo|cordova|ionic|"
    r"xamarin|mobile)\b",
    re.IGNORECASE,
)
_WEB_API_HINTS = re.compile(
    r"\b(rest|graphql|grpc|api|openapi|swagger|fastapi|flask|express|"
    r"spring|rails|django|gin|echo|fiber|actix|axios|fetch)\b",
    re.IGNORECASE,
)


def _classify_target(tech_stack: Iterable[str], user_instructions: str) -> str:
    text = " ".join(list(tech_stack) + [user_instructions or ""])
    # Check mobile FIRST because "react-native" / "native" hints overlap.
    if _MOBILE_HINTS.search(text):
        return "mobile"
    if _NATIVE_HINTS.search(text) and not _WEB_API_HINTS.search(text):
        return "native-binary"
    if _SPA_HINTS.search(text):
        return "spa"
    if _WEB_API_HINTS.search(text) or text:
        return "web-api"
    return "unknown"


# ----------------------------------------------------------------------
# Heuristic ranking
# ----------------------------------------------------------------------
def _default_web_api_model() -> ThreatModel:
    return ThreatModel(
        target_kind="web-api",
        stride_ranked=[
            "Spoofing",
            "Tampering",
            "Elevation of Privilege",
            "Information Disclosure",
            "Repudiation",
            "Denial of Service",
        ],
        owasp_ranked=[
            "A01:2021-Broken Access Control",
            "A03:2021-Injection",
            "A07:2021-Identification and Authentication Failures",
            "A05:2021-Security Misconfiguration",
            "A10:2021-Server-Side Request Forgery",
            "A02:2021-Cryptographic Failures",
        ],
        masvs_ranked=[
            "MASVS-AUTH-1",
            "MASVS-AUTH-2",
            "MASVS-AUTH-3",
            "MASVS-NETWORK-1",
            "MASVS-CODE-1",
        ],
        cwe_ranked=[
            "CWE-639",  # authz bypass via direct object reference
            "CWE-89",  # SQLi
            "CWE-918",  # SSRF
        ],
        hypotheses=[
            "IDOR / broken function-level authorization on user-scoped endpoints",
            "Server-side request forgery on URL-bearing parameters",
            "Authentication bypass via header manipulation or token confusion",
            "Cross-origin misconfiguration allowing credentialed cross-site reads",
            "Sensitive data leakage in error messages or response bodies",
        ],
        notes=["Heuristic model — no LLM call performed."],
    )


def _default_spa_model() -> ThreatModel:
    m = _default_web_api_model()
    m.target_kind = "spa"
    m.hypotheses = [
        "JS-bundle secrets (API keys, internal endpoints) exposed to attackers",
        "Open redirect on OAuth callback used for authorization-code theft",
        "DOM-based XSS via unescaped URL fragments or postMessage handlers",
        "Insecure direct object reference on /api/* paths harvested from JS bundles",
        "Sourcemap exposure revealing source code and unredacted secrets",
    ] + m.hypotheses
    m.notes = ["SPA-classified threat model; JS-bundle recon recommended."]
    return m


def _default_native_model() -> ThreatModel:
    return ThreatModel(
        target_kind="native-binary",
        stride_ranked=[
            "Tampering",
            "Elevation of Privilege",
            "Spoofing",
            "Information Disclosure",
            "Denial of Service",
            "Repudiation",
        ],
        owasp_ranked=[],
        masvs_ranked=[],
        cwe_ranked=[
            "CWE-119",
            "CWE-120",
            "CWE-125",
            "CWE-787",
            "CWE-416",
            "CWE-476",
            "CWE-190",
        ],
        hypotheses=[
            "Stack/heap buffer overflow via attacker-controlled input length",
            "Use-after-free in object lifecycle code paths",
            "Integer overflow in size/offset calculations",
            "Format string vulnerability in user-controlled format args",
            "Command injection in subprocess construction without escaping",
        ],
        notes=["Native-binary model; CWE memory-safety baseline prioritized."],
    )


def _default_mobile_model() -> ThreatModel:
    m = _default_web_api_model()
    m.target_kind = "mobile"
    m.masvs_ranked = list(MASVS_V2)
    m.hypotheses = [
        "Insecure local storage of auth tokens (MASVS-STORAGE-1/2)",
        "Missing certificate pinning (MASVS-NETWORK-1)",
        "WebView JavaScript bridge exposing privileged methods (MASVS-PLATFORM-1)",
        "Insufficient biometric / device-binding authentication (MASVS-AUTH-1/3)",
        "Reverse-engineering risk via unstripped debug symbols",
    ] + m.hypotheses
    m.notes = ["Mobile-classified model; MASVS coverage prioritized."]
    return m


def build_threat_model(
    tech_stack: Iterable[str] | None = None,
    user_instructions: str = "",
) -> ThreatModel:
    """Build a heuristic threat model without an LLM.

    The runner (Change 1.1) is expected to call an LLM to refine this
    model once the heuristic picks the target kind.
    """
    tech_stack = list(tech_stack or [])
    kind = _classify_target(tech_stack, user_instructions)
    tech_stack = list(tech_stack)
    if kind == "native-binary":
        m = _default_native_model()
    elif kind == "mobile":
        m = _default_mobile_model()
    elif kind == "spa":
        m = _default_spa_model()
    else:
        m = _default_web_api_model()
    m.tech_stack = tech_stack
    return m


# ----------------------------------------------------------------------
# Prompt template
# ----------------------------------------------------------------------
THREAT_MODEL_PROMPT = """You are a senior threat modeler. Given the following engagement,
produce a structured threat model that the bug-bounty agent will use to
narrow its search space. Return ONLY valid JSON with this shape:

{{
  "target_kind": "web-api" | "spa" | "native-binary" | "mobile" | "unknown",
  "stride_ranked": [..up to 6 STRIDE categories, most important first..],
  "owasp_ranked":  [..up to 6 OWASP Top 10 2021 categories, most important first..],
  "masvs_ranked":  [..up to 6 MASVS v2 controls, most important first..],
  "cwe_ranked":    [..up to 6 CWE IDs, most important first..],
  "hypotheses":    [..3-5 concrete testable hypotheses..],
  "notes":         [..optional caveats or assumptions..]
}}

Engagement:
- Targets: {targets}
- Tech stack: {tech_stack}
- User instructions: {user_instructions}
- Heuristic seed: {heuristic_json}
"""


def render_threat_model_prompt(
    targets: list[str],
    tech_stack: list[str],
    user_instructions: str,
    heuristic: ThreatModel,
) -> str:
    """Render the LLM prompt with the heuristic seed baked in."""
    import json

    return THREAT_MODEL_PROMPT.format(
        targets=", ".join(targets) or "<unspecified>",
        tech_stack=", ".join(tech_stack) or "<unspecified>",
        user_instructions=user_instructions or "<none>",
        heuristic_json=json.dumps(heuristic.to_dict(), indent=2, sort_keys=True),
    )


__all__ = [
    "CWE_MEMORY_SAFETY",
    "MASVS_V2",
    "OWASP_2021",
    "STRIDE_CATEGORIES",
    "ThreatModel",
    "build_threat_model",
    "render_threat_model_prompt",
]
