"""
Discovery Goal system for prometheus.

Tracks exploitation goals derived from vulnerability findings. Each goal
represents an active pursuit to validate and build a PoC for a discovered
finding. The ScanGoalManager persists goals to disk so they survive across
scan cycles.

Modeled on the Hermes goal system (hermes_cli/goals.py).
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# Valid enum-like sets
# ---------------------------------------------------------------------------

VALID_FINDING_TYPES: set[str] = {
    "cors",
    "sqli",
    "idor",
    "xss",
    "ssrf",
    "csrf",
    "info_disclosure",
    "auth_bypass",
    "rce",
    "lfi",
    "ssti",
    "xxe",
    "race_condition",
    "business_logic",
    "other",
}

VALID_STATUSES: set[str] = {"active", "validated", "dead_end", "abandoned"}

VALID_POC_STATUSES: set[str] = {"none", "partial", "working"}

# ---------------------------------------------------------------------------
# Per-finding-type exploitation criteria
# ---------------------------------------------------------------------------

EXPLOITATION_CRITERIA: dict[str, dict[str, Any]] = {
    "cors": {
        "valid_poc": (
            "Demonstrate cross-origin request that reads protected response "
            "body via reflected/allowed Origin header. The PoC MUST include "
            "actual response body data as evidence, not just header reflection."
        ),
        "dead_end_conditions": [
            "All origins are blocked or validated server-side",
            "Credentials/cookies are not used for auth on the endpoint",
            "Preflight requests fail",
            "Response is cacheable and not personalised",
        ],
        "continuation_prompts": [
            "CRITICAL: Test ACTUAL GET/POST requests, NOT just preflight/OPTIONS. Use curl -s (not -I) to capture response body.",
            "Send: curl -s -H 'Origin: https://evil.victim.com.attacker.com' <endpoint> and verify response body contains data.",
            "Verify Access-Control-Allow-Credentials: true is set on the ACTUAL response (not just preflight).",
            "Document the response body length and first 200 chars as evidence of readable cross-origin data.",
            "Test email enumeration: curl -s -H 'Origin: https://evil.com' -H 'Content-Type: application/json' -X POST -d '{\"customerEmail\":\"test@test.com\"}' <email-endpoint>",
            "Map the regex pattern: test multiple subdomain patterns (evil.victim.com.attacker.com, a.victim.com.b, etc.)",
            "Test rejected origins for comparison: curl -s -H 'Origin: https://evil.com' <endpoint> should NOT reflect.",
            "Try reflecting the Origin header with a null origin (file:// or sandboxed iframe).",
            "Test with subdomain wildcard: random.victim.com.",
            "Try using trusted subdomain payloads like attacker.victim.com.",
            "Try exploiting via WebSocket upgrade with cross-origin request.",
            "Check if Vary: Origin header is missing — cache poisoning angle.",
            "Test CORS preflight bypass by embedding in HTML form with Content-Type text/plain.",
        ],
    },
    "sqli": {
        "valid_poc": (
            "Extract arbitrary data from the database (e.g. version string, "
            "table contents) via injected SQL payload."
        ),
        "dead_end_conditions": [
            "Input is parameterised or uses prepared statements",
            "WAF blocks all injection vectors after extensive fuzzing",
            "Non-SQL database (NoSQL, LDAP, etc.)",
            "Error messages are fully suppressed and blind techniques fail",
        ],
        "continuation_prompts": [
            "Test classic single-quote and double-quote injection with error-based detection.",
            "Try blind boolean-based: AND 1=1 vs AND 1=2 and compare responses.",
            "Test time-based blind: SLEEP(5), pg_sleep(5), WAITFOR DELAY.",
            "Try UNION-based injection — enumerate column count with ORDER BY.",
            "Test second-order SQLi via stored values that get queried later.",
            "Try out-of-band exfiltration via DNS or HTTP (xp_dirtlaw, UTL_HTTP).",
            "Test HTTP parameter pollution to inject SQL in backend queries.",
            "Try NoSQL injection patterns: {$gt: ''}, {$ne: 1}.",
            "Test second-order via registration forms or profile update fields.",
        ],
    },
    "idor": {
        "valid_poc": (
            "Access or modify another user's resource by changing an "
            "identifier (user ID, order ID, etc.)."
        ),
        "dead_end_conditions": [
            "IDs are UUIDs and not sequential or guessable",
            "Server-side authorisation checks prevent cross-user access",
            "Identifiers are encrypted or signed with unknown key",
        ],
        "continuation_prompts": [
            "Enumerate sequential integer IDs on the endpoint.",
            "Try swapping user IDs between two accounts you control.",
            "Test with UUID prediction if timestamp-based UUIDs are used.",
            "Check indirect IDOR via file paths, hashes, or encoded IDs.",
            "Test via API endpoints — sometimes UI checks differ from API.",
            "Try changing ownership IDs in POST/PUT/PATCH request bodies.",
            "Test horizontal privilege escalation via role or group IDs.",
            "Check if GraphQL queries expose objects by ID without authz.",
        ],
    },
    "xss": {
        "valid_poc": (
            "Inject and execute arbitrary JavaScript in a victim's browser "
            "context (cookie theft, DOM manipulation, etc.)."
        ),
        "dead_end_conditions": [
            "All user input is HTML-encoded before rendering",
            "Content Security Policy blocks inline scripts without bypass",
            "Input length is severely restricted",
            "HTTPOnly flag prevents cookie access",
        ],
        "continuation_prompts": [
            "Test reflected XSS with basic payload: <script>alert(1)</script>.",
            "Try event handler injection: <img src=x onerror=alert(1)>.",
            "Test DOM-based XSS via URL fragments and document.location.",
            "Try SVG-based payloads: <svg onload=alert(1)>.",
            'Test attribute breakout: " onmouseover="alert(1).',
            "Try polyglot payloads that work across contexts.",
            "Test stored XSS via comment, profile, or message fields.",
            "Check for XSS via JSONP callback parameter injection.",
            "Try bypassing CSP using base-uri injection or allowed domains.",
            "Test mutation XSS using DOMParser quirks.",
        ],
    },
    "ssrf": {
        "valid_poc": (
            "Make the server fetch a resource from an attacker-controlled "
            "or internal network address (e.g. 169.254.169.254, localhost)."
        ),
        "dead_end_conditions": [
            "URL input is strictly validated against allowlist",
            "DNS resolution is pinned or restricted",
            "No outbound network access from the server",
        ],
        "continuation_prompts": [
            "Test basic SSRF: http://127.0.0.1 and http://localhost.",
            "Try cloud metadata: http://169.254.169.254/latest/meta-data/.",
            "Test URL schema abuse: file:///etc/passwd, gopher://, dict://.",
            "Try DNS rebinding to bypass allowlist validation.",
            "Test IPv6 variants: http://[::1], http://0000::1.",
            "Try decimal/octal IP encoding: http://2130706433 (127.0.0.1).",
            "Test redirect-based SSRF: use open redirect to hit internal.",
            "Try CRLF injection in URL to smuggle requests.",
            "Check if the service follows redirects — use 302 to internal.",
        ],
    },
    "csrf": {
        "valid_poc": (
            "Craft a cross-site request that performs a state-changing action "
            "on behalf of a victim user without their consent."
        ),
        "dead_end_conditions": [
            "CSRF tokens are properly validated on every request",
            "SameSite cookie attribute blocks cross-site sending",
            "Custom headers required that cannot be set cross-origin",
        ],
        "continuation_prompts": [
            "Test by removing the CSRF token parameter entirely.",
            "Try using an empty or expired CSRF token value.",
            "Test token fixation — reuse a token from a different session.",
            "Check if GET requests trigger state changes (no CSRF on GET).",
            "Try CSRF via subdomain takeover pointing to attacker domain.",
            "Test SameSite bypass via top-level navigation (Lax bypass).",
            "Check if JSON content type CSRF is possible via flash/html forms.",
            "Try method override: _method=POST via GET query string.",
        ],
    },
    "info_disclosure": {
        "valid_poc": (
            "Extract sensitive information (stack traces, source code, "
            "credentials, internal IPs, version numbers) not intended for public."
        ),
        "dead_end_conditions": [
            "Information is already public / intended to be accessible",
            "Disclosed info has no security relevance",
            "Page returns generic errors after all fuzzing",
        ],
        "continuation_prompts": [
            "Probe common sensitive paths: /.git/config, /server-status, /env.",
            "Check for verbose error messages with stack traces on invalid input.",
            "Test for directory listing on static asset paths.",
            "Look for .env, .DS_Store, backup files (.bak, .old, ~).",
            "Check HTTP response headers for server version info.",
            "Probe GraphQL introspection for schema disclosure.",
            "Test API documentation endpoints: /swagger, /api-docs, /openapi.json.",
            "Check for debug endpoints: /debug, /trace, /actuator.",
            "Look for exposed S3 buckets, Azure blobs via naming conventions.",
        ],
    },
    "auth_bypass": {
        "valid_poc": (
            "Access a protected resource or perform an authenticated action "
            "without valid credentials or authorisation."
        ),
        "dead_end_conditions": [
            "All auth checks are consistently enforced at middleware level",
            "MFA/tokens are mandatory and cannot be bypassed",
            "No logic flaws found after thorough testing",
        ],
        "continuation_prompts": [
            "Test by removing the Authorization header entirely.",
            "Try default credentials on login endpoints.",
            "Test JWT none algorithm attack on token-based auth.",
            "Try JWT signature stripping — remove signature part.",
            "Test password reset flow for token predictability.",
            "Check for authentication bypass via HTTP verb tampering.",
            "Try path traversal in auth-protected routes: /admin/../public.",
            "Test OAuth redirect_uri manipulation for token theft.",
            "Check for race conditions in login or registration flows.",
            "Try JWT key confusion (RS256 -> HS256 with public key).",
        ],
    },
    "rce": {
        "valid_poc": (
            "Execute arbitrary system commands on the server (e.g. id, "
            "whoami, ping, or writing a file)."
        ),
        "dead_end_conditions": [
            "Input is sandboxed or heavily sanitised",
            "No command injection surface is reachable",
            "Runtime has no access to system commands",
        ],
        "continuation_prompts": [
            "Test basic command injection: ;id, |id, `id`, $(id).",
            "Try OS command injection via backtick or $() substitution.",
            "Test for deserialization vulnerabilities (pickle, Java, PHP).",
            "Check for template injection (SSTI) as a path to RCE.",
            "Try file upload with executable extensions (.php, .jsp, .aspx).",
            "Test for eval() or exec() injection in dynamic code paths.",
            "Check for Log4Shell / JNDI injection if Java stack.",
            "Try race condition in file upload + execution.",
            "Test prototype pollution leading to command execution (Node.js).",
        ],
    },
    "ssti": {
        "valid_poc": (
            "Render a server-side template expression (e.g. {{7*7}} = 49, "
            "${7*7}) demonstrating template engine injection."
        ),
        "dead_end_conditions": [
            "Template engine is not used or input is not rendered",
            "Template sandbox is enforced and cannot be escaped",
            "No template syntax is evaluated",
        ],
        "continuation_prompts": [
            "Test basic SSTI payloads: {{7*7}}, ${7*7}, #{7*7}, <%=7*7%>.",
            "Try Jinja2 RCE: {{config}} then {{''.__class__.__mro__[1].__subclasses__()}}.",
            "Test Freemarker SSTI: <#assign ex='freemarker.template.utility.Execute'?new()>.",
            "Try Twig SSTI: {{_self.env.registerUndefinedFilterCallback('exec')}}.",
            "Test Mako template injection via ${self.module}.",
            "Check for blind SSTI via time-delay payloads (sleep, benchmark).",
            "Try sandbox escape techniques specific to detected template engine.",
        ],
    },
    "xxe": {
        "valid_poc": (
            "Extract file contents or trigger SSRF via XML external entity "
            "injection in XML/SOAP/DOCX parsing."
        ),
        "dead_end_conditions": [
            "XML parser disables external entity resolution",
            "Input is not parsed as XML",
            "DTD processing is disabled",
        ],
        "continuation_prompts": [
            "Test basic XXE: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>.",
            "Try blind XXE via out-of-band data exfiltration (external DTD).",
            "Test parameter entity injection for blind XXE.",
            "Try XXE via SVG image upload with embedded XML.",
            "Test XXE via XLSX/DOCX file upload (OOXML contains XML).",
            "Try XInclude attack for partial XML injection.",
            "Test for SSRF via XXE: SYSTEM 'http://internal-server/'.",
            "Check if SOAP endpoints accept XML with external entities.",
        ],
    },
    "lfi": {
        "valid_poc": (
            "Read arbitrary files from the server filesystem (e.g. "
            "/etc/passwd, application config, source code)."
        ),
        "dead_end_conditions": [
            "Path traversal is blocked at every layer",
            "File inclusion uses allowlisted paths only",
            "Null byte / encoding bypasses fail",
        ],
        "continuation_prompts": [
            "Test basic path traversal: ../../../etc/passwd.",
            "Try URL-encoded traversal: %2e%2e%2f%2e%2e%2f.",
            "Test double encoding: %252e%252e%252f.",
            "Try null byte injection: ../../../etc/passwd%00.",
            "Test PHP wrappers: php://filter/convert.base64-encode/resource=index.php.",
            "Try /proc/self/environ or /proc/self/fd/ for log injection.",
            "Test for log poisoning to escalate LFI to RCE.",
            "Check for SSRF via file:// protocol if URL-based inclusion.",
            "Try RFI with http:// URL if remote includes are enabled.",
        ],
    },
    "race_condition": {
        "valid_poc": (
            "Demonstrate a window of concurrent requests that produces "
            "an inconsistent or unintended state (double-spend, etc.)."
        ),
        "dead_end_conditions": [
            "Operations are properly serialised with locks",
            "Idempotency keys prevent replay",
            "No time-of-check-time-of-use window exists",
        ],
        "continuation_prompts": [
            "Send parallel requests to redeem/transfer/buy endpoints.",
            "Test concurrent password reset token use.",
            "Try race in file upload — multiple simultaneous uploads.",
            "Test TOCTOU in file operations (symlink race).",
            "Try concurrent session creation or privilege escalation.",
        ],
    },
    "business_logic": {
        "valid_poc": (
            "Demonstrate exploitation of flawed business logic (e.g. "
            "negative quantity, skipped payment step, price manipulation)."
        ),
        "dead_end_conditions": [
            "Server-side validation covers all edge cases",
            "State machine enforces correct workflow order",
        ],
        "continuation_prompts": [
            "Test negative or zero values for quantity/amount fields.",
            "Try skipping workflow steps (go directly to confirmation).",
            "Test currency/price manipulation in multi-step flows.",
            "Try applying discount codes multiple times or stacking.",
            "Test for race conditions in coupon redemption.",
            "Check if re-sending step 1 after step 2 causes duplication.",
        ],
    },
}

# Provide a generic fallback for unknown types
EXPLOITATION_CRITERIA.setdefault(
    "other",
    {
        "valid_poc": "Demonstrate a concrete security impact with reproducible steps.",
        "dead_end_conditions": [
            "Cannot reproduce after thorough testing",
            "No security impact can be demonstrated",
        ],
        "continuation_prompts": [
            "Gather more information about the target and endpoint.",
            "Try different input vectors and encoding techniques.",
            "Review similar vulnerability patterns for inspiration.",
        ],
    },
)

# ---------------------------------------------------------------------------
# Evidence keywords used by the heuristic judge
# ---------------------------------------------------------------------------

_GLOBAL_EVIDENCE_KEYWORDS = [
    "poc",
    "proof of concept",
    "exploit confirmed",
    "data extracted",
    "successfully exploited",
    "vulnerability confirmed",
    "payload executed",
]

# Per-type extra evidence keywords
_TYPE_EVIDENCE: dict[str, list[str]] = {
    "cors": [
        "access-control-allow-origin",
        "cross-origin",
        "origin reflected",
        "credentials.*true",
        "response.*body.*readable",
        "allow.credentials.*true.*reflected",
        "evil.*origin.*reflected",
        "email.*enumerat.*origin",
    ],
    "sqli": ["sql syntax", "mysql", "postgresql", "sqlite", "ora-", "query result", "union select"],
    "idor": ["unauthorized access", "other user", "another user's", "cross-user"],
    "xss": ["<script", "alert(", "document.cookie", "xss triggered", "javascript executed"],
    "ssrf": ["internal ip", "169.254", "metadata", "localhost", "127.0.0.1", "cloud metadata"],
    "csrf": ["forged request", "cross-site request", "csrf token bypassed"],
    "info_disclosure": [
        "stack trace",
        "source code",
        "database credentials",
        "internal ip",
        "version disclosed",
    ],
    "auth_bypass": [
        "authenticated as",
        "access granted",
        "token bypassed",
        "logged in",
        "admin access",
    ],
    "rce": ["command executed", "uid=", "whoami", "reverse shell", "code execution"],
    "lfi": ["root:x:", "file contents", "/etc/passwd", "source code leaked"],
    "ssti": ["49", "template rendered", "rce via template", "jinja2", "freemarker"],
    "xxe": ["external entity", "file read", "dtd", "xml parsed", "xxe triggered"],
}

# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------


@dataclass
class DiscoveryGoal:
    """A single exploitation goal derived from a vulnerability finding."""

    id: str
    finding_title: str
    finding_type: str
    endpoint: str
    status: str = "active"
    attempts: int = 0
    max_attempts: int = 10
    poc_status: str = "none"
    dead_end_reason: str = ""
    continuation_history: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    completed_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DiscoveryGoal:
        """Deserialise from a dict (e.g. loaded from JSON)."""
        return cls(**data)


# ---------------------------------------------------------------------------
# Goal manager
# ---------------------------------------------------------------------------


class ScanGoalManager:
    """Manages a set of :class:`DiscoveryGoal` objects for a scan run.

    Goals are persisted to ``discovery_goals.json`` inside *state_dir* so
    they survive across scan cycles / restarts.
    """

    def __init__(self, state_dir: Path) -> None:
        self._state_dir = state_dir
        self._goals: dict[str, DiscoveryGoal] = {}

    # -- CRUD ---------------------------------------------------------------

    def create_goal(self, finding: dict[str, Any]) -> DiscoveryGoal:
        """Create a new goal from a finding dict, auto-detecting the type.

        Args:
            finding: Must contain at least ``title`` and ``endpoint``.
                ``description`` is optional but helps classify the type.

        Returns:
            The newly created :class:`DiscoveryGoal`.
        """
        title = finding.get("title", "")
        description = finding.get("description", "")
        endpoint = finding.get("endpoint", finding.get("target", ""))
        finding_type = classify_finding_type(title, description)

        goal = DiscoveryGoal(
            id=str(uuid.uuid4()),
            finding_title=title,
            finding_type=finding_type,
            endpoint=endpoint,
            created_at=time.time(),
        )
        self._goals[goal.id] = goal
        self.persist()
        return goal

    def get_active_goal(self) -> DiscoveryGoal | None:
        """Return the first active goal, or ``None``."""
        for goal in self._goals.values():
            if goal.status == "active":
                return goal
        return None

    def complete_goal(
        self,
        goal_id: str,
        status: str,
        poc_status: str = "",
        dead_end_reason: str = "",
    ) -> None:
        """Mark a goal as complete with the given status.

        Args:
            goal_id: The goal's UUID.
            status: One of ``validated``, ``dead_end``, ``abandoned``.
            poc_status: ``partial`` or ``working`` (or empty to leave unchanged).
            dead_end_reason: Why the goal is a dead end (only for ``dead_end``).

        Raises:
            KeyError: If *goal_id* is not found.
            ValueError: If *status* is not a valid terminal status.
        """
        if status not in {"validated", "dead_end", "abandoned"}:
            raise ValueError(f"Invalid terminal status: {status!r}")

        goal = self._goals[goal_id]
        goal.status = status
        goal.completed_at = time.time()
        if poc_status:
            goal.poc_status = poc_status
        if dead_end_reason:
            goal.dead_end_reason = dead_end_reason
        self.persist()

    def get_all_goals(self) -> list[DiscoveryGoal]:
        """Return all goals (any status)."""
        return list(self._goals.values())

    def has_active_goals(self) -> bool:
        """Return ``True`` if at least one goal has ``status == 'active'``."""
        return any(g.status == "active" for g in self._goals.values())

    def get_goal_count_by_status(self) -> dict[str, int]:
        """Return a count of goals grouped by status."""
        counts: dict[str, int] = {}
        for goal in self._goals.values():
            counts[goal.status] = counts.get(goal.status, 0) + 1
        return counts

    # -- Persistence --------------------------------------------------------

    def persist(self) -> None:
        """Save all goals to ``state_dir/discovery_goals.json``."""
        path = self._state_dir / "discovery_goals.json"
        self._state_dir.mkdir(parents=True, exist_ok=True)
        data = [g.to_dict() for g in self._goals.values()]
        path.write_text(json.dumps(data, indent=2))

    def load(self) -> None:
        """Load goals from ``state_dir/discovery_goals.json`` if it exists."""
        path = self._state_dir / "discovery_goals.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            self._goals = {d["id"]: DiscoveryGoal.from_dict(d) for d in data}
        except (json.JSONDecodeError, KeyError):
            # Corrupted file — start fresh
            self._goals = {}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

# Compile patterns once at module level for classify_finding_type
_TYPE_PATTERNS: list[tuple[str, list[str]]] = [
    ("cors", ["cors", "cross-origin resource sharing", "access-control-allow-origin"]),
    (
        "sqli",
        ["sql injection", "sqli", "sql query", "blind sql", "union select", "error-based sql"],
    ),
    ("idor", ["idor", "insecure direct object", "horizontal privilege", "object reference"]),
    (
        "xss",
        ["xss", "cross-site scripting", "reflected xss", "stored xss", "dom-based xss", "dom xss"],
    ),
    ("ssrf", ["ssrf", "server-side request forgery", "server side request forgery"]),
    ("csrf", ["csrf", "cross-site request forgery", "cross site request forgery"]),
    (
        "info_disclosure",
        [
            "information disclosure",
            "info disclosure",
            "information exposure",
            "sensitive data",
            "verbose error",
            "stack trace",
            "directory listing",
            "source code disclosure",
            "version disclosure",
            "exposed",
            "credential",
            "api key",
            "secret key",
            "firebase key",
            "leaked",
            "hardcoded",
            "plaintext password",
        ],
    ),
    (
        "auth_bypass",
        [
            "authentication bypass",
            "auth bypass",
            "unauthenticated access",
            "broken authentication",
            "privilege escalation",
            "unauthorized access",
        ],
    ),
    (
        "rce",
        ["remote code execution", "rce", "command injection", "code injection", "arbitrary code"],
    ),
    (
        "lfi",
        ["local file inclusion", "lfi", "path traversal", "directory traversal", "file inclusion"],
    ),
    ("ssti", ["server-side template injection", "ssti", "template injection"]),
    ("xxe", ["xml external entity", "xxe", "xxe injection"]),
    ("race_condition", ["race condition", "toctou", "time-of-check", "concurrency"]),
    ("business_logic", ["business logic", "logic flaw", "logic vulnerability", "workflow bypass"]),
]


def classify_finding_type(title: str, description: str) -> str:
    """Infer the vulnerability type from a finding's title and description.

    Args:
        title: The finding title.
        description: The finding description.

    Returns:
        A finding_type string (one of the VALID_FINDING_TYPES values),
        defaulting to ``"other"`` if no pattern matches.
    """
    combined = f"{title} {description}".lower()
    for ftype, keywords in _TYPE_PATTERNS:
        for kw in keywords:
            if kw in combined:
                return ftype
    return "other"


def judge_scan_goal(goal: DiscoveryGoal, last_output: str) -> dict[str, Any]:
    """Heuristic judge: determine if a goal has been resolved from output text.

    This is a **placeholder** that uses keyword matching. A future version
    will call an LLM for nuanced judgement.

    Args:
        goal: The current discovery goal.
        last_output: The most recent output from an exploitation attempt.

    Returns:
        A dict with keys ``done`` (bool), ``reason`` (str),
        ``poc_status`` (str), and ``suggestion`` (str).
    """
    output_lower = last_output.lower()

    # Check global evidence keywords
    global_hit = any(kw in output_lower for kw in _GLOBAL_EVIDENCE_KEYWORDS)

    # Check type-specific evidence keywords
    type_keywords = _TYPE_EVIDENCE.get(goal.finding_type, [])
    type_hit = any(kw in output_lower for kw in type_keywords)

    if global_hit and type_hit:
        criteria = EXPLOITATION_CRITERIA.get(goal.finding_type, EXPLOITATION_CRITERIA["other"])
        return {
            "done": True,
            "reason": f"Exploitation evidence detected for {goal.finding_type}.",
            "poc_status": "working",
            "suggestion": f"Write up the PoC. Expected: {criteria['valid_poc']}",
        }

    if global_hit:
        return {
            "done": True,
            "reason": "General exploitation evidence found in output.",
            "poc_status": "partial",
            "suggestion": "Refine the PoC to be fully reproducible.",
        }

    # Check dead-end indicators from criteria
    criteria = EXPLOITATION_CRITERIA.get(goal.finding_type, EXPLOITATION_CRITERIA["other"])
    dead_end_keywords = [d.lower() for d in criteria.get("dead_end_conditions", [])]
    dead_end_hit = any(dk in output_lower for dk in dead_end_keywords)

    if dead_end_hit:
        return {
            "done": True,
            "reason": f"Dead-end condition matched for {goal.finding_type}.",
            "poc_status": goal.poc_status,
            "suggestion": "Consider marking this goal as a dead end and moving on.",
        }

    # Not done — suggest continuation
    return {
        "done": False,
        "reason": "No exploitation evidence found yet.",
        "poc_status": goal.poc_status,
        "suggestion": generate_continuation_prompt(goal),
    }


def generate_continuation_prompt(goal: DiscoveryGoal) -> str:
    """Generate the next exploitation prompt for a goal.

    Picks a continuation prompt from the criteria that hasn't been tried
    yet (not in the goal's continuation_history).

    Args:
        goal: The current discovery goal.

    Returns:
        A specific next-step prompt string.
    """
    criteria = EXPLOITATION_CRITERIA.get(goal.finding_type, EXPLOITATION_CRITERIA["other"])
    prompts = criteria.get("continuation_prompts", [])

    history_lower: set[str] = {h.lower() for h in goal.continuation_history}

    for prompt in prompts:
        if prompt.lower() not in history_lower:
            return prompt

    # All prompts exhausted — return a generic fallback
    return (
        f"Try a different angle for {goal.finding_type} on {goal.endpoint}. "
        "Consider combining techniques or testing edge cases not yet explored."
    )
