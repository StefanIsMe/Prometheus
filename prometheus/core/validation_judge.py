"""Post-scan Validation Judge for prometheus findings.

Evaluates whether findings represent real, exploitable vulnerabilities or
speculative/observational issues.  Designed to run after the initial gating
logic in the reporting tool to give an additional layer of confidence
scoring and HackerOne-aligned outcome prediction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ValidationVerdict:
    """Result of validating a single finding against type-specific criteria.

    Attributes:
        finding_title: Title of the evaluated finding.
        verdict: One of 'validated', 'speculative', 'false_positive'.
        reason: Human-readable explanation of the verdict.
        missing: For speculative findings, describes what evidence would
            elevate the verdict to 'validated'.  Empty string otherwise.
        confidence: 0.0-1.0 confidence in the verdict itself.
        h1_likely_outcome: Predicted HackerOne triage outcome —
            'accepted' (real bounty), 'informational' (acknowledged but
            low/no bounty), or 'na' (not applicable / closed).
        criteria_met: List of criteria the finding satisfied.
        criteria_failed: List of criteria the finding failed.
    """

    finding_title: str
    verdict: str  # 'validated' | 'speculative' | 'false_positive'
    reason: str
    missing: str
    confidence: float
    h1_likely_outcome: str  # 'accepted' | 'informational' | 'na'
    criteria_met: list[str] = field(default_factory=list)
    criteria_failed: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Per-type validation criteria
# ---------------------------------------------------------------------------

VALIDATION_CRITERIA: dict[str, dict[str, dict[str, Any]]] = {
    "ssr_hostname_leak": {
        "validated": {
            "keywords": [
                "used.*internal.*hostname.*access",
                "accessed.*internal.*service.*via",
                "ssrf.*to.*internal.*hostname",
                "internal.*service.*data.*exfiltrat",
                "railway.*internal.*accessed.*data",
                "internal.*hostname.*unauthorized.*access",
            ],
            "description": (
                "Used leaked internal hostname to access internal service and extract data"
            ),
        },
        "speculative": {
            "keywords": [
                "internal.*hostname.*found",
                "railway.*internal.*hostname",
                "ssr.*data.*leak",
                "nuxt.*data.*leak",
                "next.*data.*leak",
                "angular.*data.*leak",
                "_nuxt_data.*leak",
                "_ssr_data.*leak",
                "internal.*server.*address",
                "private.*ip.*disclosure",
                "hostname.*in.*response",
                "server.*address.*in.*response",
            ],
            "negation_keywords": [
                "used.*to.*access",
                "accessed.*internal.*service",
                "exfiltrated",
                "unauthorized.*access",
                "data.*breach",
                "sensitive.*data.*exposed",
            ],
            "description": (
                "Internal hostname/IP discovered in SSR response but not used for exploitation. "
                "This is reconnaissance, not a vulnerability. To be reportable, the finding must "
                "demonstrate using the hostname to access an internal service and extract data."
            ),
        },
        "false_positive": {
            "keywords": [
                "public.*api",
                "public.*endpoint",
                "intentionally.*exposed",
                "cloud.*platform.*expected",
                "infrastructure.*normal",
            ],
            "description": ("Internal addressing is expected cloud infrastructure behavior"),
        },
    },
    "fingerprinting": {
        "validated": {
            "keywords": [
                "used.*version.*exploit",
                "cve.*exploit.*confirmed",
                "version.*specific.*attack.*successful",
                "outdated.*component.*exploited",
            ],
            "description": ("Used discovered version information to exploit a known vulnerability"),
        },
        "speculative": {
            "keywords": [
                "version.*disclosure",
                "banner.*disclosure",
                "fingerprint.*found",
                "technology.*identified",
                "framework.*version.*detected",
                "server.*header.*reveals",
                "x-powered-by.*header",
                "nginx.*version",
                "apache.*version",
                "express.*version",
                "next.*version",
                "nuxt.*version",
                "angular.*version",
                "react.*version",
                "vue.*version",
                "django.*version",
                "laravel.*version",
                "rails.*version",
            ],
            "negation_keywords": [
                "cve.*exploit",
                "used.*to.*attack",
                "vulnerability.*confirmed",
                "outdated.*exploit",
                "version.*specific.*exploit",
            ],
            "description": (
                "Version/banner disclosure is reconnaissance. To be reportable, the finding must "
                "demonstrate exploiting a specific CVE or vulnerability in that version."
            ),
        },
        "false_positive": {
            "keywords": [
                "public.*information",
                "documentation.*available",
                "changelog.*public",
                "version.*public",
            ],
            "description": ("Version information is publicly available in documentation"),
        },
    },
    "missing_header": {
        "validated": {
            "keywords": [
                "clickjack.*sensitive.*action",
                "iframe.*exploit.*confirmed",
                "xss.*via.*missing.*csp",
                "csrf.*via.*missing.*header",
            ],
            "description": ("Demonstrated concrete attack enabled by missing header"),
        },
        "speculative": {
            "keywords": [
                "missing.*header",
                "missing.*policy",
                "missing.*csp",
                "missing.*x-frame",
                "missing.*hsts",
                "missing.*content-type",
                "missing.*referrer-policy",
                "missing.*permissions-policy",
                "header.*not.*set",
                "header.*absent",
                "header.*missing",
                "weak.*csp",
                "weak.*hsts",
                "insecure.*header",
            ],
            "negation_keywords": [
                "clickjack.*exploit",
                "iframe.*attack",
                "xss.*injection",
                "csrf.*exploit",
                "demonstrated.*attack",
            ],
            "description": (
                "Missing security header without demonstrated impact. This is informational only. "
                "To be reportable, demonstrate the concrete attack the missing header enables."
            ),
        },
        "false_positive": {
            "keywords": [
                "public.*page",
                "non.*sensitive",
                "static.*content",
                "no.*sensitive.*action",
            ],
            "description": ("Missing header on non-sensitive page with no exploitable action"),
        },
    },
    "cors": {
        "validated": {
            "keywords": [
                "read.*response",
                "response.*body",
                "exfil",
                "stole.*token",
                "extracted.*data",
                "cross.origin.*read",
                "accessed.*data",
                "document\\\\.cookie",
                "fetch.*response",
                "xhr.*response",
                "csrf.*performed",
                "state.changing",
                "unauthorized.*action",
                # Origin reflected + credentials enabled = browser allows reading
                "allow.credentials.*true.*origin.*reflect",
                "origin.*reflect.*allow.credentials.*true",
                "credentials.*true.*reflected",
                "reflected.*credentials.*true",
                # Response body actually returned with evil origin (MUST have body evidence)
                "response.*length.*bytes",
                "body.*length.*bytes",
                "response.*readable.*evil",
                "body.*readable.*evil",
                # Combined pattern: origin in ACAO + body evidence
                "origin.*reflected.*response.*body",
                "response.*body.*origin.*reflected",
                # Email enumeration via reflected origin (proves data returned)
                "email.*enumerat.*origin.*reflect",
                "isEmailAvailable.*origin",
            ],
            "description": (
                "PoC shows JS reading response body cross-origin, OR "
                "origin reflected with credentials enabled (browser allows reading), OR "
                "demonstrated CSRF on state-changing endpoint"
            ),
        },
        "speculative": {
            "keywords": [
                "preflight",
                "access-control-allow-origin",
                "reflects.*origin",
                "cors.*header",
                "origin.*reflected",
            ],
            "negation_keywords": [
                "read.*response",
                "response.*body",
                "exfil",
                "extracted",
                "stole",
                "cross.origin.*read",
                "allow.credentials.*true.*origin.*reflect",
                "origin.*reflect.*allow.credentials.*true",
                "credentials.*true.*reflected",
                "response.*length.*bytes",
                "body.*length.*bytes",
                "email.*enumerat.*origin.*reflect",
            ],
            "description": "Only preflight headers shown, no actual response tested",
        },
        "false_positive": {
            "keywords": [
                "public.*api",
                "no.*sensitive",
                "public.*endpoint",
                "aca[c-o].*\\\\*",
                "without.*aca[c-o]",
            ],
            "description": ("ACAO: * without ACAC, or public API with no sensitive data"),
        },
    },
    "sqli": {
        "validated": {
            "keywords": [
                "table.*name",
                "extracted.*record",
                "dumped.*database",
                "credentials.*extracted",
                "data.*exfiltrat",
                "union.*select",
                "information_schema",
                "pg_sleep",
                "benchmark\\(",
                "sleep\\(.*\\)",
                "rows.*returned",
                "column.*name",
            ],
            "description": (
                "Data extracted (table names, records, credentials), not just error messages"
            ),
        },
        "speculative": {
            "keywords": [
                "sql.*error",
                "syntax.*error",
                "mysql.*error",
                "postgres.*error",
                "sqlite.*error",
                "ora-\\d+",
                "unclosed.*quotation",
                "unterminated.*string",
            ],
            "negation_keywords": [
                "extracted",
                "dumped",
                "table.*name",
                "record",
                "credential",
            ],
            "description": "Error-based detection without data extraction",
        },
        "false_positive": {
            "keywords": [
                "generic.*500",
                "unrelated.*syntax",
                "not.*injection",
                "false.*positive",
                "server.*error.*unrelated",
            ],
            "description": "Generic 500 errors, syntax errors unrelated to injection",
        },
    },
    "idor": {
        "validated": {
            "keywords": [
                "other.*user.*data",
                "another.*user",
                "cross.*user.*access",
                "changed.*id.*and.*got",
                "replaced.*id.*received",
                "different.*user.*profile",
                "accessed.*account.*of",
                "id.*swap",
                "sequential.*id.*accessed",
            ],
            "description": "Accessed another user's data by changing ID",
        },
        "speculative": {
            "keywords": [
                "sequential.*id",
                "predictable.*id",
                "increment.*id",
                "id.*pattern",
                "guessable.*id",
            ],
            "negation_keywords": [
                "other.*user.*data",
                "another.*user",
                "cross.*user",
                "different.*user",
                "accessed.*account.*of",
            ],
            "description": "Sequential IDs without confirmed cross-user access",
        },
        "false_positive": {
            "keywords": [
                "403.*other.*user",
                "404.*other.*user",
                "access.*denied",
                "id.*ignored",
                "returns.*own.*data",
                "own.*profile.*returned",
                "unauthorized.*access",
            ],
            "description": ("Got 403/404 on other user's ID, or ID ignored (returns own data)"),
        },
    },
    "xss": {
        "validated": {
            "keywords": [
                "script.*execut",
                "alert\\(",
                "document\\.cookie",
                "document\\.domain",
                "dom.*manipulat",
                "payload.*execut",
                "injected.*script",
                "xss.*fires",
                "reflected.*execut",
                "stored.*execut",
                "onerror.*=",
                "onload.*=",
                "javascript:",
                "eval\\(",
                "innerHTML",
            ],
            "description": (
                "Script executes in browser context (document.cookie, alert, DOM manipulation)"
            ),
        },
        "speculative": {
            "keywords": [
                "payload.*reflect",
                "reflected.*payload",
                "input.*echoed",
                "reflected.*in.*response",
                "unsanitized.*input",
                "user.*input.*render",
            ],
            "negation_keywords": [
                "execut",
                "alert\\(",
                "document\\.cookie",
                "fires",
                "triggered",
                "pop-up",
                "popup",
            ],
            "description": "Payload reflected but not confirmed execution",
        },
        "false_positive": {
            "keywords": [
                "html.*encod",
                "output.*encod",
                "csp.*block",
                "content.security.*block",
                "inline.*script.*block",
                "sanitiz.*output",
                "escaped.*output",
            ],
            "description": "HTML-encoded output, CSP blocks inline scripts",
        },
    },
    "ssrf": {
        "validated": {
            "keywords": [
                "169\\.254\\.169\\.254",
                "metadata.*endpoint",
                "localhost.*access",
                "internal.*service.*access",
                "127\\.0\\.0\\.1.*reached",
                "internal.*hostname.*resolved",
                "cloud.*metadata",
                "aws.*metadata",
                "gcp.*metadata",
                "azure.*metadata",
            ],
            "description": (
                "Accessed internal service (169.254.169.254, localhost, internal hostname)"
            ),
        },
        "speculative": {
            "keywords": [
                "user.*controlled.*url",
                "url.*parameter",
                "fetch.*url",
                "redirect.*to.*internal",
                "url.*input",
            ],
            "negation_keywords": [
                "169\\.254",
                "metadata",
                "localhost.*access",
                "internal.*reached",
                "127\\.0\\.0\\.1.*access",
            ],
            "description": "User-controlled URL without confirmed internal access",
        },
        "false_positive": {
            "keywords": [
                "blocks.*internal.*ip",
                "url.*validation.*present",
                "allowlist.*enforced",
                "ssrf.*filter",
                "ip.*blocklist",
                "dns.*rebind.*prevent",
            ],
            "description": "Server blocks all internal IPs, URL validation present",
        },
    },
    "csrf": {
        "validated": {
            "keywords": [
                "state.changing.*cross.origin",
                "action.*performed.*cross",
                "forged.*request.*succeeded",
                "csrf.*exploit",
                "cross.origin.*request.*modified",
                "without.*token.*action",
                "account.*modified.*cross.origin",
            ],
            "description": "State-changing action performed cross-origin without token",
        },
        "speculative": {
            "keywords": [
                "missing.*csrf.*token",
                "no.*csrf.*token",
                "csrf.*token.*absent",
                "anti.*forgery.*missing",
            ],
            "negation_keywords": [
                "cross.origin.*succeed",
                "action.*performed",
                "exploit",
                "modified.*data",
                "created.*account",
            ],
            "description": "Missing CSRF token but action not tested cross-origin",
        },
        "false_positive": {
            "keywords": [
                "get.*only",
                "non.*sensitive",
                "read.*only",
                "idempotent.*action",
                "no.*state.*change",
            ],
            "description": "GET-only endpoints, non-sensitive actions",
        },
    },
    "info_disclosure": {
        "validated": {
            "keywords": [
                "used.*to.*access",
                "called.*api.*with.*key",
                "authenticated.*with.*found",
                "retrieved.*data.*using",
                "accessed.*service.*with",
                "unauthorized.*access.*achieved",
                "exfiltrated.*using",
                "logged.*in.*with.*found",
            ],
            "description": ("Credential/key used to access unauthorized data or service"),
        },
        "speculative": {
            "keywords": [
                "found.*key",
                "found.*token",
                "found.*secret",
                "found.*credential",
                "exposed.*key",
                "leaked.*key",
                "hardcoded.*key",
                "hardcoded.*token",
                "hardcoded.*secret",
                "contains.*api.*key",
                "contains.*token",
            ],
            "negation_keywords": [
                "used.*to.*access",
                "called.*api",
                "authenticated.*with",
                "retrieved.*data",
                "accessed.*service",
                "exfiltrated",
            ],
            "description": "Key/credential found but not tested",
        },
        "false_positive": {
            "keywords": [
                "oauth.*client.*id",
                "public.*credential",
                "firebase.*api.*key.*by.*design",
                "client.*id.*public",
                "non.*secret",
                "by.*design.*public",
                "default.*credential.*public",
            ],
            "description": ("Public credentials (OAuth client IDs, Firebase API keys by design)"),
        },
    },
    "auth_bypass": {
        "validated": {
            "keywords": [
                "accessed.*protected.*resource",
                "bypassed.*auth",
                "admin.*panel.*access",
                "unauthorized.*data.*access",
                "escalated.*privilege",
                "accessed.*without.*credential",
                "jwt.*forged",
                "token.*forged",
                "session.*hijack",
            ],
            "description": "Accessed protected resource without valid credentials",
        },
        "speculative": {
            "keywords": [
                "auth.*check.*missing",
                "no.*auth.*check",
                "authentication.*absent",
                "missing.*authorization",
                "no.*access.*control",
            ],
            "negation_keywords": [
                "accessed.*data",
                "bypassed",
                "admin.*panel",
                "escalated",
                "forged",
                "hijack",
            ],
            "description": "Auth check missing but not tested with actual data access",
        },
        "false_positive": {
            "keywords": [
                "public.*endpoint",
                "appears.*protected.*but",
                "actually.*public",
                "intentionally.*public",
                "publicly.*accessible.*by.*design",
            ],
            "description": "Public endpoints that appear protected but aren't",
        },
    },
    "rce": {
        "validated": {
            "keywords": [
                "command.*executed",
                "arbitrary.*command",
                "shell.*obtained",
                "reverse.*shell",
                "whoami.*returned",
                "id.*returned",
                "exec\\(.*result",
                "system\\(.*result",
                "subprocess.*output",
                "command.*injection.*success",
                "popen.*output",
            ],
            "description": "Arbitrary command executed on server",
        },
        "speculative": {
            "keywords": [
                "command.*injection.*point",
                "inject.*into.*command",
                "user.*input.*in.*command",
                "os.*command.*parameter",
                "exec.*parameter.*controllable",
            ],
            "negation_keywords": [
                "executed",
                "returned.*output",
                "shell.*obtained",
                "whoami",
                "result.*of.*command",
                "command.*output",
            ],
            "description": "Command injection point without confirmed execution",
        },
        "false_positive": {
            "keywords": [
                "error.*message.*not.*output",
                "looks.*like.*command.*but",
                "not.*actual.*command",
                "false.*positive.*rce",
                "error.*string.*not.*injection",
            ],
            "description": "Error messages that look like command output but aren't",
        },
    },
    "ssti": {
        "validated": {
            "keywords": [
                "\\{\\{.*\\*.*\\}\\}.*=.*49",
                "template.*evaluated",
                "expression.*evaluated",
                "7\\*7.*=.*49",
                "\\{\\{.*\\}\\}.*rendered",
                "jinja.*exploit",
                "twig.*exploit",
                "freemarker.*exploit",
                "server.*side.*template.*inject.*confirmed",
            ],
            "description": "Template expressions evaluated (e.g., {{7*7}} = 49)",
        },
        "speculative": {
            "keywords": [
                "user.*input.*in.*template",
                "template.*context",
                "template.*injection.*possible",
                "render.*user.*input",
            ],
            "negation_keywords": [
                "evaluated",
                "=.*49",
                "exploit.*confirmed",
                "expression.*result",
            ],
            "description": "User input in template context without confirmed evaluation",
        },
        "false_positive": {
            "keywords": [
                "html.*template.*literal",
                "client.*side.*template",
                "not.*server.*side",
                "string.*interpolation",
                "es6.*template.*literal",
            ],
            "description": "HTML template literal, not server-side evaluation",
        },
    },
    "xxe": {
        "validated": {
            "keywords": [
                "internal.*file.*read",
                "etc.*passwd.*read",
                "file://.*read",
                "ssrf.*via.*xml",
                "xxe.*exploit",
                "external.*entity.*resolv",
                "xml.*injection.*confirmed",
                "billion.*laugh",
                "parameter.*entity.*expanded",
            ],
            "description": "Internal file read or SSRF via XML injection",
        },
        "speculative": {
            "keywords": [
                "xml.*parser.*accept.*external",
                "external.*entity.*accept",
                "xxe.*possible",
                "xml.*entity.*injection.*possible",
                "dtd.*accepted",
            ],
            "negation_keywords": [
                "file.*read",
                "etc.*passwd",
                "ssrf.*confirm",
                "exploit",
                "resolved.*entity",
                "expanded",
            ],
            "description": ("XML parser accepts external entities without confirmed exploitation"),
        },
        "false_positive": {
            "keywords": [
                "xml.*parser.*reject.*external",
                "external.*entity.*reject",
                "xxe.*blocked",
                "xml.*parser.*secure",
                "dtd.*disallow",
            ],
            "description": "XML parser rejects external entities",
        },
    },
    "lfi": {
        "validated": {
            "keywords": [
                "etc.*passwd.*read",
                "file.*content.*retrieved",
                "internal.*file.*read",
                "path.*traversal.*confirmed",
                "directory.*listing",
                "source.*code.*read",
                "lfi.*exploit.*confirmed",
                "/etc/shadow",
            ],
            "description": "Read internal file (e.g., /etc/passwd)",
        },
        "speculative": {
            "keywords": [
                "path.*traversal.*possible",
                "traversal.*sequence.*accept",
                "user.*input.*in.*path",
                "file.*path.*controllable",
                "\\./\\.\\./.*accepted",
            ],
            "negation_keywords": [
                "etc.*passwd",
                "file.*content.*read",
                "source.*code",
                "directory.*listing",
                "confirmed.*read",
            ],
            "description": "Path traversal without confirmed file read",
        },
        "false_positive": {
            "keywords": [
                "waf.*block.*traversal",
                "traversal.*blocked",
                "path.*sanitiz",
                "directory.*traversal.*prevent",
                "\\./\\.\\/*.*block",
            ],
            "description": "WAF blocks traversal sequences",
        },
    },
    "pkce_downgrade": {
        "validated": {
            "keywords": [
                # Require ACTUAL token exchange evidence, not metadata
                "token.*endpoint.*accept.*plain.*code_verifier.*returned.*token",
                "plain.*code_verifier.*exchanged.*for.*access_token",
                "pkce.*downgrade.*confirmed.*token.*received",
                "authorization.*code.*intercepted.*exchanged.*plain",
                "plain.*pkce.*token.*exchange.*successful",
                "access_token.*obtained.*via.*plain.*code_verifier",
            ],
            "description": (
                "PKCE downgrade confirmed: token endpoint accepted plain code_verifier "
                "and returned actual tokens. Full OAuth chain demonstrated."
            ),
        },
        "speculative": {
            "keywords": [
                "plain.*method.*in.*discovery",
                "code_challenge_methods_supported.*plain",
                "pkce.*metadata.*mismatch",
                "oauth.*misconfiguration",
                "plain.*pkce.*advertised",
                "insecure.*pkce.*method",
                "pkce.*not.*enforced",
                "missing.*pkce.*enforcement",
                "no.*code_challenge.*required",
                # These are metadata-only — informational, not reportable
                "plain.*method.*advertised",
                "code_challenge_methods.*plain",
                "pkce.*downgrade.*confirmed",
                "plain.*pkce.*accepted",
                "authorize.*accept.*plain",
                "discovery.*advertises.*plain",
                "metadata.*plain.*pkce",
                "oauth.*downgrade.*confirmed",
                "cve.2025.4144",
            ],
            "negation_keywords": [
                # Only actual token exchange negates speculative status
                "access_token.*obtained.*via.*plain",
                "plain.*verifier.*returned.*token",
                "token.*exchange.*confirmed.*plain.*method",
            ],
            "description": (
                "PKCE metadata mismatch or missing enforcement without confirmed "
                "token exchange exploitation. To be validated, demonstrate that the "
                "token endpoint accepts plain code_verifier AND returns actual tokens "
                "using a real authorization code from a completed user login flow. "
                "Metadata-only findings (discovery doc, authorize endpoint) are NOT reportable."
            ),
        },
        "false_positive": {
            "keywords": [
                "s256.*only",
                "plain.*rejected",
                "pkce.*enforced",
                "token.*reject.*plain",
                "invalid_request.*missing.*code_challenge",
                "plain.*not.*supported",
            ],
            "description": ("Server correctly rejects plain PKCE or enforces S256 only"),
        },
    },
    "oauth_misconfiguration": {
        "validated": {
            "keywords": [
                "token.*leak.*via.*redirect",
                "open.*redirect.*oauth",
                "authorization.*code.*intercept",
                "token.*theft.*via",
                "oauth.*account.*takeover",
                "jwt.*none.*algorithm",
                "jwt.*algorithm.*confusion",
                "refresh.*token.*reuse",
                "state.*parameter.*missing.*exploit",
                "csrf.*oauth.*confirmed",
            ],
            "description": (
                "OAuth misconfiguration exploited: token theft, account takeover, "
                "or authentication bypass via OAuth flow manipulation"
            ),
        },
        "speculative": {
            "keywords": [
                "oauth.*misconfiguration",
                "oauth.*weakness",
                "missing.*state.*parameter",
                "open.*redirect.*potential",
                "jwt.*weakness",
                "token.*storage.*insecure",
                "oauth.*config.*issue",
                "oidc.*misconfiguration",
            ],
            "negation_keywords": [
                "exploit.*confirmed",
                "token.*stolen",
                "account.*takeover",
                "bypass.*confirmed",
                "code.*intercepted",
            ],
            "description": (
                "OAuth configuration issue observed without confirmed exploitation. "
                "Demonstrate token theft, account takeover, or auth bypass to validate."
            ),
        },
        "false_positive": {
            "keywords": [
                "oauth.*working.*correctly",
                "standard.*oauth.*flow",
                "expected.*behavior",
                "oauth.*properly.*configured",
            ],
            "description": "OAuth flow working as designed",
        },
    },
}


# ---------------------------------------------------------------------------
# Theoretical / observation-only language patterns
# (mirrors the guards in the reporting tool)
# ---------------------------------------------------------------------------

_THEORETICAL_PATTERNS: list[str] = [
    "could allow",
    "could lead to",
    "could potentially",
    "might be possible",
    "may lead to",
    "may allow",
    "potentially vulnerable",
    "if an attacker were to",
    "an attacker could theoretically",
    "this could be exploited",
    "potential vulnerability",
]

_OBSERVATION_PATTERNS: list[str] = [
    "found that",
    "observed that",
    "noticed that",
    "it appears that",
    "it seems that",
    "discovered that",
    "analysis shows",
    "review reveals",
]

_EXPLOITATION_SIGNALS: list[str] = [
    "executed",
    "extracted",
    "exfiltrated",
    "accessed",
    "retrieved",
    "obtained",
    "stole",
    "bypassed",
    "achieved",
    "demonstrated",
    "confirmed",
    "successfully",
    "performed",
    "injected",
    "triggered",
    "obtained",
    "read.*response",
    "response.*body",
    "status.*200",
    "http/",
    "request.*sent",
    "curl ",
    "POST ",
    "GET ",
    "fetch(",
    "requests.",
]


# ---------------------------------------------------------------------------
# Type classification
# ---------------------------------------------------------------------------

_TYPE_KEYWORDS: dict[str, list[str]] = {
    "ssr_hostname_leak": [
        "ssr.*hostname",
        "internal.*hostname",
        "railway.*internal",
        "nuxt.*data.*leak",
        "next.*data.*leak",
        "angular.*data.*leak",
        "_nuxt_data",
        "_ssr_data",
        "ssr.*internal",
        "server.*address.*leak",
    ],
    "fingerprinting": [
        "version.*disclosure",
        "banner.*disclosure",
        "fingerprint",
        "technology.*identified",
        "framework.*version",
        "server.*header.*reveals",
    ],
    "missing_header": [
        "missing.*header",
        "missing.*policy",
        "missing.*csp",
        "missing.*x-frame",
        "missing.*hsts",
        "header.*not.*set",
        "header.*absent",
        "weak.*csp",
    ],
    "cors": ["cors", "cross-origin resource sharing", "access-control-allow-origin"],
    "sqli": [
        "sql injection",
        "sqli",
        "sql inject",
        "blind sql",
        "union select",
        "database injection",
    ],
    "idor": ["idor", "insecure direct object", "idor", "direct object reference"],
    "xss": [
        "xss",
        "cross-site scripting",
        "cross site scripting",
        "reflected xss",
        "stored xss",
        "dom xss",
        "dom-based xss",
    ],
    "ssrf": ["ssrf", "server-side request forgery", "server side request forgery"],
    "csrf": ["csrf", "cross-site request forgery", "cross site request forgery", "csrf token"],
    "info_disclosure": [
        "information disclosure",
        "info disclosure",
        "sensitive data exposure",
        "credential exposure",
        "api key exposure",
        "secret exposure",
        "token exposure",
        "data leak",
        "data leakage",
        "hardcoded credential",
        "hardcoded secret",
    ],
    "auth_bypass": [
        "authentication bypass",
        "auth bypass",
        "authorization bypass",
        "privilege escalation",
        "broken authentication",
        "broken authorization",
        "access control bypass",
    ],
    "rce": [
        "remote code execution",
        "rce",
        "command injection",
        "code injection",
        "arbitrary code execution",
        "os command injection",
    ],
    "ssti": [
        "server-side template injection",
        "ssti",
        "template injection",
        "server side template injection",
    ],
    "xxe": ["xxe", "xml external entity", "xml injection", "xml entity injection"],
    "lfi": [
        "local file inclusion",
        "lfi",
        "path traversal",
        "directory traversal",
        "file inclusion",
    ],
    "pkce_downgrade": [
        "pkce",
        "code_challenge",
        "code_verifier",
        "proof key for code exchange",
        "pkce downgrade",
        "plain pkce",
        "s256",
        "code_challenge_method",
    ],
    "oauth_misconfiguration": [
        "oauth",
        "oidc",
        "openid connect",
        "authorization code",
        "token endpoint",
        "authorize endpoint",
        "oauth misconfiguration",
        "jwt",
        "refresh token",
        "bearer token",
        "oauth flow",
        "oauth bypass",
    ],
}


def classify_finding_type(title: str, description: str) -> str:
    """Classify a finding into one of the known vulnerability types.

    Searches *title* and *description* for keywords associated with each
    type.  Returns the best-matching type name, or ``"unknown"`` when no
    keywords match.

    Args:
        title: Finding title.
        description: Finding description.

    Returns:
        A string key into :data:`VALIDATION_CRITERIA`, or ``"unknown"``.
    """
    combined = f"{title} {description}".lower()
    best_type = "unknown"
    best_score = 0

    for vuln_type, keywords in _TYPE_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in combined)
        if score > best_score:
            best_score = score
            best_type = vuln_type

    return best_type if best_score > 0 else "unknown"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_keywords(text: str, keywords: list[str]) -> list[str]:
    """Return which *keywords* match somewhere in *text*."""
    matches: list[str] = []
    for kw in keywords:
        if re.search(kw, text, re.IGNORECASE):
            matches.append(kw)
    return matches


def _has_exploitation_evidence(text: str) -> bool:
    """Check whether *text* contains signals of actual exploitation."""
    return any(re.search(p, text, re.IGNORECASE) for p in _EXPLOITATION_SIGNALS)


def _count_theoretical(text: str) -> int:
    """Count how many theoretical hedging phrases appear in *text*."""
    text_lower = text.lower()
    return sum(1 for p in _THEORETICAL_PATTERNS if p in text_lower)


def _has_observation_only(text: str) -> bool:
    """Check whether *text* only describes an observation without exploitation."""
    text_lower = text.lower()
    obs = any(p in text_lower for p in _OBSERVATION_PATTERNS)
    expl = _has_exploitation_evidence(text_lower)
    return obs and not expl


# ---------------------------------------------------------------------------
# Core validation
# ---------------------------------------------------------------------------


def validate_finding(finding: dict[str, Any]) -> ValidationVerdict:
    """Validate a single finding against type-specific criteria.

    The function:

    1. Classifies the finding type from title/description.
    2. Assembles all textual evidence (PoC, description, analysis).
    3. Checks the evidence against :data:`VALIDATION_CRITERIA` for that type.
    4. Detects theoretical/observation-only language that reduces confidence.
    5. Returns a :class:`ValidationVerdict` with verdict, reasoning, and
       HackerOne outcome prediction.

    Args:
        finding: A dict with at least ``title`` and ``description`` keys.
            Other recognised keys: ``poc_description``, ``poc_script_code``,
            ``technical_analysis``, ``impact``.

    Returns:
        A :class:`ValidationVerdict` for the finding.
    """
    title = str(finding.get("title") or "").strip()
    description = str(finding.get("description") or "").strip()
    poc_desc = str(finding.get("poc_description") or "").strip()
    poc_code = str(finding.get("poc_script_code") or "").strip()
    tech_analysis = str(finding.get("technical_analysis") or "").strip()
    impact = str(finding.get("impact") or "").strip()

    # Combine all evidence text for pattern matching
    all_evidence = f"{poc_desc} {poc_code} {tech_analysis} {description} {impact}"

    # Step 1 — classify type
    vuln_type = classify_finding_type(title, description)

    # Step 2 — if unknown type, apply generic heuristics
    if vuln_type == "unknown":
        return _validate_generic(title, description, all_evidence)

    criteria = VALIDATION_CRITERIA[vuln_type]

    # Step 3 — check each verdict tier
    # Start from strongest (validated) and fall through

    # --- validated ---
    val_crit = criteria.get("validated", {})
    val_matches = _check_keywords(all_evidence, val_crit.get("keywords", []))
    has_exploit = _has_exploitation_evidence(all_evidence)

    if val_matches and has_exploit:
        criteria_met = [val_crit.get("description", "Validated criteria met")]
        confidence = min(0.5 + len(val_matches) * 0.1, 0.95)
        # Boost confidence if PoC code is substantial
        if len(poc_code) > 100:
            confidence = min(confidence + 0.05, 0.95)
        return ValidationVerdict(
            finding_title=title,
            verdict="validated",
            reason=(
                f"Finding classified as '{vuln_type}' and validated: "
                + val_crit.get("description", "")
                + f" Matched criteria: {', '.join(val_matches[:5])}"
            ),
            missing="",
            confidence=confidence,
            h1_likely_outcome="accepted",
            criteria_met=criteria_met,
            criteria_failed=[],
        )

    # --- false_positive ---
    fp_crit = criteria.get("false_positive", {})
    fp_matches = _check_keywords(all_evidence, fp_crit.get("keywords", []))

    # Strong false-positive signal: FP keywords present AND no exploitation
    if fp_matches and not has_exploit:
        # Check if there are also speculative signals — if so, lean speculative
        spec_crit = criteria.get("speculative", {})
        spec_matches = _check_keywords(all_evidence, spec_crit.get("keywords", []))
        if spec_matches:
            # Ambiguous — lean speculative
            pass
        else:
            criteria_met = [fp_crit.get("description", "False-positive criteria met")]
            confidence = min(0.5 + len(fp_matches) * 0.1, 0.9)
            return ValidationVerdict(
                finding_title=title,
                verdict="false_positive",
                reason=(
                    f"Finding classified as '{vuln_type}' but appears to be a false positive: "
                    + fp_crit.get("description", "")
                    + f" Matched: {', '.join(fp_matches[:5])}"
                ),
                missing="",
                confidence=confidence,
                h1_likely_outcome="na",
                criteria_met=criteria_met,
                criteria_failed=[val_crit.get("description", "Validated criteria")],
            )

    # --- speculative (default for this type) ---
    spec_crit = criteria.get("speculative", {})
    spec_matches = _check_keywords(all_evidence, spec_crit.get("keywords", []))

    # Compute theoretical penalty
    theoretical_count = _count_theoretical(all_evidence)
    observation_only = _has_observation_only(all_evidence)

    missing_parts: list[str] = []
    if not has_exploit:
        missing_parts.append("demonstrated exploitation (show actual attack outcome)")
    if not val_matches:
        missing_parts.append(val_crit.get("description", "type-specific exploitation evidence"))
    if theoretical_count >= 2:
        missing_parts.append("concrete evidence replacing theoretical language")
    if observation_only:
        missing_parts.append("exploitation proof beyond observation")

    missing_text = "; ".join(missing_parts) if missing_parts else ""

    # Base confidence for speculative
    confidence = 0.3
    if spec_matches:
        confidence += len(spec_matches) * 0.05
    if has_exploit:
        confidence += 0.15
    if poc_code and len(poc_code) > 50:
        confidence += 0.05
    if theoretical_count >= 2:
        confidence -= 0.1
    if observation_only:
        confidence -= 0.1
    confidence = max(0.1, min(confidence, 0.75))

    # Decide h1 outcome
    h1_outcome = "informational" if confidence >= 0.5 or confidence >= 0.3 else "na"

    criteria_met_list: list[str] = []
    if spec_matches:
        criteria_met_list.append(spec_crit.get("description", "Speculative criteria"))
    criteria_failed_list: list[str] = [val_crit.get("description", "Validated criteria")]

    return ValidationVerdict(
        finding_title=title,
        verdict="speculative",
        reason=(
            f"Finding classified as '{vuln_type}' but evidence is speculative: "
            + (spec_crit.get("description", "Observation without confirmed exploitation"))
            + (f" Theoretical language count: {theoretical_count}." if theoretical_count else "")
            + (" Observation-only (no exploitation signal)." if observation_only else "")
        ),
        missing=missing_text,
        confidence=confidence,
        h1_likely_outcome=h1_outcome,
        criteria_met=criteria_met_list,
        criteria_failed=criteria_failed_list,
    )


def _validate_generic(
    title: str,
    description: str,
    all_evidence: str,
) -> ValidationVerdict:
    """Fallback validation when the finding type cannot be classified.

    Uses generic heuristics: exploitation evidence, theoretical language,
    and observation-only patterns.
    """
    has_exploit = _has_exploitation_evidence(all_evidence)
    theoretical_count = _count_theoretical(all_evidence)
    observation_only = _has_observation_only(all_evidence)

    if has_exploit and theoretical_count < 2:
        return ValidationVerdict(
            finding_title=title,
            verdict="validated",
            reason=(
                "Unknown finding type, but PoC contains exploitation evidence. "
                "Manual review recommended to confirm type-specific criteria."
            ),
            missing="",
            confidence=0.4,
            h1_likely_outcome="accepted",
            criteria_met=["Contains exploitation evidence"],
            criteria_failed=["Unknown type — no type-specific criteria applied"],
        )

    if observation_only or theoretical_count >= 2:
        missing_parts: list[str] = []
        if not has_exploit:
            missing_parts.append("demonstrated exploitation")
        if theoretical_count >= 2:
            missing_parts.append("concrete evidence replacing theoretical language")
        if observation_only:
            missing_parts.append("exploitation proof beyond observation")

        return ValidationVerdict(
            finding_title=title,
            verdict="speculative",
            reason=(
                "Unknown finding type with speculative evidence. "
                + (f"Theoretical phrases: {theoretical_count}. " if theoretical_count else "")
                + ("Observation-only." if observation_only else "")
            ),
            missing="; ".join(missing_parts),
            confidence=0.25,
            h1_likely_outcome="informational",
            criteria_met=[],
            criteria_failed=["Type-specific validation", "Exploitation evidence"],
        )

    return ValidationVerdict(
        finding_title=title,
        verdict="speculative",
        reason="Unknown finding type; insufficient evidence for classification.",
        missing="Type-specific exploitation evidence and demonstrated impact",
        confidence=0.2,
        h1_likely_outcome="na",
        criteria_met=[],
        criteria_failed=["Known type classification", "Exploitation evidence"],
    )


# ---------------------------------------------------------------------------
# Batch validation
# ---------------------------------------------------------------------------


def validate_findings_batch(findings: list[dict[str, Any]]) -> list[ValidationVerdict]:
    """Validate a batch of findings and return verdicts sorted by confidence.

    Higher-confidence verdicts appear first, making it easy to prioritise
    review of the most certain validations (or the most dubious findings).

    Args:
        findings: List of finding dicts (same schema as :func:`validate_finding`).

    Returns:
        A list of :class:`ValidationVerdict` objects, sorted descending by
        :attr:`ValidationVerdict.confidence`.
    """
    verdicts = [validate_finding(f) for f in findings]
    verdicts.sort(key=lambda v: v.confidence, reverse=True)
    return verdicts
