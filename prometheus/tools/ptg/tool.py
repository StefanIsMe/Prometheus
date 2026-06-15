"""Penetration Task Graph (PTG) — structured phase decomposition for scans.

Inspired by VulnBot (arXiv:2501.13411), the PTG enforces a disciplined
phase-based penetration testing workflow.  Each phase has explicit
dependencies, required tools, and completion criteria.  The agent can
query ``get_scan_progress`` at any time to see where it stands and what
blocks ``finish_scan``.

Phases
------
1. RECON              — subdomain enum, port scanning, service discovery
2. FINGERPRINT        — technology identification, version detection
3. THREAT_INTEL       — CVE research, threat feed queries
4. VULNERABILITY_SCAN — nuclei, manual testing
5. EXPLOITATION       — PoC development, validation
6. REPORTING          — findings documentation, executive report
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from agents import RunContextWrapper, function_tool

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Phase definition
# ---------------------------------------------------------------------------


@dataclass
class Phase:
    """A single penetration-testing phase."""

    name: str
    description: str
    dependencies: list[str]
    required_tools: set[str]
    completion_criteria: str
    status: str = "pending"  # pending | in_progress | completed | skipped
    started_at: float | None = None
    completed_at: float | None = None
    notes: list[str] = field(default_factory=list[str])
    tools_called: set[str] = field(default_factory=set[str])


# ---------------------------------------------------------------------------
# Default phase definitions
# ---------------------------------------------------------------------------


def _default_phases() -> dict[str, Phase]:
    """Return the canonical six-phase pentesting decomposition."""
    return {
        "RECON": Phase(
            name="RECON",
            description=(
                "Passive and active reconnaissance: subdomain enumeration, "
                "port scanning, service discovery, DNS lookups, WHOIS. "
                "Root agents satisfy this by spawning subagents (create_agent) "
                "or using exec_command directly. Prior knowledge from previous "
                "scans also counts as recon-complete."
            ),
            dependencies=[],
            required_tools={"exec_command", "create_agent"},
            completion_criteria=(
                "At least one recon tool (subfinder, nmap, amass, httpx -probe, "
                "dig, whois) has been executed via exec_command, OR a subagent "
                "has been spawned via create_agent, OR prior knowledge exists "
                "from previous scans."
            ),
        ),
        "FINGERPRINT": Phase(
            name="FINGERPRINT",
            description=(
                "Technology identification and version detection: web stack, "
                "frameworks, CMS, server software, WAF detection."
            ),
            dependencies=["RECON"],
            required_tools={"exec_command"},
            completion_criteria=(
                "A fingerprinting tool (httpx, whatweb, wappalyzer, nmap -sV) "
                "has been executed and technology data collected."
            ),
        ),
        "THREAT_INTEL": Phase(
            name="THREAT_INTEL",
            description=(
                "CVE research and threat intelligence: query vulnerability "
                "databases, search for known exploits, analyze attack surface. "
                "For each detected technology, search for recent CVEs and exploits."
            ),
            dependencies=["FINGERPRINT"],
            required_tools={"query_threat_feeds", "web_search"},
            completion_criteria=(
                "Both query_threat_feeds and web_search have been called at "
                "least once with target-specific technology queries. "
                "For each technology identified during FINGERPRINT, at least "
                "one web_search must be performed looking for CVEs or exploits."
            ),
        ),
        "VULNERABILITY_SCAN": Phase(
            name="VULNERABILITY_SCAN",
            description=(
                "Active vulnerability scanning: nuclei scans, manual testing "
                "guided by threat intel, authentication testing, input validation. "
                "For multi-target scans or deep mode, spawn sub-agents via create_agent "
                "to parallelize scanning across targets."
            ),
            dependencies=["THREAT_INTEL"],
            required_tools={"exec_command"},
            completion_criteria=(
                "Nuclei or another vulnerability scanner has been run against "
                "EACH target at least once. For any CRITICAL or HIGH CVE matching "
                "detected technologies, at least one validation attempt must be made. "
                "Use create_agent to spawn parallel scanners for multi-target scans."
            ),
        ),
        "EXPLOITATION": Phase(
            name="EXPLOITATION",
            description=(
                "Proof-of-concept development and exploitation: validate "
                "findings with working PoCs, assess real-world impact."
            ),
            dependencies=["VULNERABILITY_SCAN"],
            required_tools={"exec_command"},
            completion_criteria=(
                "At least one exploitation/PoC attempt has been made, or "
                "the phase is explicitly skipped (no exploitable vulns found)."
            ),
        ),
        "REPORTING": Phase(
            name="REPORTING",
            description=(
                "Findings documentation: create vulnerability reports, write "
                "executive summary, methodology, analysis, recommendations."
            ),
            dependencies=["EXPLOITATION"],
            required_tools={"create_vulnerability_report"},
            completion_criteria=(
                "At least one vulnerability report has been created, OR "
                "finish_scan has been called (even if zero vulns found)."
            ),
        ),
    }


# ---------------------------------------------------------------------------
# Recon / fingerprint tool patterns (substrings matched in exec_command)
# ---------------------------------------------------------------------------

_RECON_PATTERNS = [
    "subfinder",
    "amass",
    "nmap",
    "masscan",
    "dnsx",
    "httpx",
    "dig ",
    "whois",
    "shodan",
    "censys",
    "recon-ng",
    "theharvester",
    "recon",
    "sublist3r",
    "knockpy",
    "assetfinder",
]

_FINGERPRINT_PATTERNS = [
    "whatweb",
    "wappalyzer",
    "httpx",
    "wafw00f",
    "fingerprint",
    "nmap -sV",
    "nmap --version",
    "nikto",
]

_VULN_SCAN_PATTERNS = [
    "nuclei",
    "sqlmap",
    "nikto",
    "wapiti",
    "burp",
    "arachni",
    "openvas",
    "nessus",
    "OWASP",
    "ffuf",
    "gobuster",
    "dirsearch",
    "feroxbuster",
    "katana",
]

_EXPLOIT_PATTERNS = [
    "exploit",
    "poc",
    "proof-of-concept",
    "payload",
    "reverse_shell",
    "msfconsole",
    "metasploit",
    "msfvenom",
    "hydra",
    "medusa",
    "john",
    "hashcat",
    "crack",
    "brute",
]


def _matches_any(text: str, patterns: list[str]) -> bool:
    lower = text.lower()
    return any(p in lower for p in patterns)


# ---------------------------------------------------------------------------
# PentestingTaskGraph
# ---------------------------------------------------------------------------


class PentestingTaskGraph:
    """Stateful tracker that enforces structured phase decomposition.

    Instantiate one per scan.  The agent interacts with it via
    ``get_scan_progress`` (a function_tool).  The runner/factory calls
    ``record_tool_call`` after every tool invocation to auto-advance phases.
    """

    def __init__(self) -> None:
        self.phases = _default_phases()
        self._phase_order = [
            "RECON",
            "FINGERPRINT",
            "THREAT_INTEL",
            "VULNERABILITY_SCAN",
            "EXPLOITATION",
            "REPORTING",
        ]
        # Start the first phase immediately
        self._start_phase("RECON")
        logger.info("PTG initialized with %d phases", len(self.phases))

    # ---- phase lifecycle ---------------------------------------------------

    def _start_phase(self, name: str) -> None:
        phase = self.phases[name]
        if phase.status == "pending":
            phase.status = "in_progress"
            phase.started_at = time.time()
            logger.info("PTG phase '%s' started", name)

    # Skills that indicate a child agent is handling a specific PTG phase.
    # When create_agent spawns a child with these skills, the parent PTG
    # auto-completes the corresponding phase — even if tool calls happened
    # inside the child (which the parent PTG cannot observe).
    _PHASE_SKILL_MAP: dict[str, set[str]] = {
        "THREAT_INTEL": {"threat_intelligence", "threat_feeds"},
        "VULNERABILITY_SCAN": {
            "nuclei",
            "nikto",
            "sqlmap",
            "zaproxy",
            "arjun",
            "ffuf",
            "dirsearch",
            "katana",
            "semgrep",
        },
        "EXPLOITATION": {
            "sql_injection",
            "xss",
            "csrf",
            "ssrf",
            "cors_misconfiguration",
            "nosql_injection",
            "rce",
            "ssti",
            "xxe",
            "command_injection",
            "path_traversal_lfi_rfi",
            "idor",
            "open_redirect",
            "insecure_file_uploads",
            "subdomain_takeover",
            "race_conditions",
            "ldap_injection",
            "header_injection",
            "prototype_pollution",
            "authentication_jwt",
            "oauth_vulnerabilities",
            "graphql_attacks",
            "clickjacking",
            "cloud_credential_exploitation",
            "cloudflare_credentials",
            "business_logic",
            "broken_function_level_authorization",
            "rest_api_security",
            "mobile_api",
            "cryptographic_failures",
            "dns_network",
            "integrity_failures",
            "supply_chain",
            "ai_llm_attacks",
            "logging_monitoring_failures",
            "security_misconfiguration",
            "threat_modeling",
        },
    }

    def mark_phase_complete_by_skill_delegation(self, skills: list[str]) -> None:
        """Auto-complete PTG phases based on child agent skill delegation.

        When the root agent spawns a child with phase-specific skills,
        mark the matching phase(s) as complete. Also completes any prior
        phases that are still in-progress (handles parallel spawning).
        """
        # Find which phase(s) these skills target
        target_phase: str | None = None
        for phase_name, skill_set in self._PHASE_SKILL_MAP.items():
            if any(s in skill_set for s in skills):
                target_phase = phase_name
                break

        if target_phase is None:
            return  # Skills don't match any PTG phase

        # Cascade-complete: finish any in-progress prior phases by
        # setting their status directly (no _auto_start_next to avoid
        # runaway cascading). Then start+complete the target phase
        # (which DOES trigger _auto_start_next for the next phase).
        completed_any = False
        for pn in self._phase_order:
            phase = self.phases[pn]
            if pn == target_phase:
                # Target phase: force-start if pending, then complete
                if phase.status == "pending":
                    self._start_phase(pn)
                if phase.status == "in_progress":
                    phase.tools_called.add("create_agent")
                    phase.notes.append(
                        f"Auto-completed: delegated to child agent with skills {skills}"
                    )
                    self.mark_phase_complete(pn)
                    completed_any = True
                break  # Stop — don't cascade past target
            elif phase.status == "in_progress":
                # Prior phase still in progress: complete it directly
                # (no _auto_start_next to avoid skipping ahead)
                phase.status = "completed"
                phase.completed_at = time.time()
                phase.tools_called.add("create_agent")
                phase.notes.append(
                    f"Auto-completed: cascade from child delegation with skills {skills}"
                )
                logger.info("PTG phase '%s' auto-completed (cascade)", pn)
                completed_any = True
            # completed/skipped: continue to next phase

        if completed_any:
            logger.info("PTG phases auto-advanced from skill delegation: %s", skills)

    def mark_recon_from_prior_knowledge(self, knowledge_count: int) -> None:
        """Auto-complete RECON when prior knowledge from previous scans exists.

        The pre-scan fingerprint + knowledge hydration already provides recon
        data.  This avoids forcing the agent to re-scan targets it already
        knows about.
        """
        if knowledge_count > 0:
            recon = self.phases["RECON"]
            if recon.status == "in_progress":
                recon.tools_called.add("create_agent")  # satisfy the gate
                recon.notes.append(
                    f"Auto-completed: {knowledge_count} prior knowledge entries loaded from previous scans."
                )
                self.mark_phase_complete("RECON")
                logger.info(
                    "PTG RECON auto-completed from %d prior knowledge entries", knowledge_count
                )

    def mark_phase_complete(self, phase_name: str) -> None:
        """Explicitly mark a phase as completed."""
        phase = self.phases[phase_name]
        phase.status = "completed"
        phase.completed_at = time.time()
        logger.info("PTG phase '%s' completed", phase_name)
        self._auto_start_next()

    def mark_phase_skipped(self, phase_name: str) -> None:
        """Skip a phase (e.g. EXPLOITATION when no vulns found)."""
        phase = self.phases[phase_name]
        phase.status = "skipped"
        phase.completed_at = time.time()
        logger.info("PTG phase '%s' skipped", phase_name)
        self._auto_start_next()

    def add_note(self, phase_name: str, note: str) -> None:
        """Append a note to a phase."""
        self.phases[phase_name].notes.append(note)

    # ---- queries -----------------------------------------------------------

    def get_current_phase(self) -> Phase | None:
        """Return the first incomplete phase whose deps are all met."""
        for name in self._phase_order:
            phase = self.phases[name]
            if phase.status in ("completed", "skipped"):
                continue
            if self._deps_met(name):
                return phase
        return None

    def can_finish(self) -> bool:
        """True if all phases are completed or skipped."""
        return all(self.phases[n].status in ("completed", "skipped") for n in self._phase_order)

    def get_progress(self) -> dict[str, Any]:
        """Return a full progress snapshot."""
        completed = sum(
            1 for n in self._phase_order if self.phases[n].status in ("completed", "skipped")
        )
        total = len(self._phase_order)
        pct = round(completed / total * 100) if total else 0

        phase_details = {}
        for name in self._phase_order:
            p = self.phases[name]
            phase_details[name] = {
                "status": p.status,
                "description": p.description,
                "dependencies": p.dependencies,
                "required_tools": sorted(p.required_tools),
                "tools_called": sorted(p.tools_called),
                "completion_criteria": p.completion_criteria,
                "started_at": p.started_at,
                "completed_at": p.completed_at,
                "notes": p.notes,
            }

        return {
            "total_phases": total,
            "completed_phases": completed,
            "completion_pct": pct,
            "can_finish": self.can_finish(),
            "current_phase": cp.name if (cp := self.get_current_phase()) else None,
            "blocked_reason": self.get_blocked_reason(),
            "phases": phase_details,
        }

    def get_blocked_reason(self) -> str | None:
        """Explain why the scan cannot finish yet."""
        if self.can_finish():
            return None
        for name in self._phase_order:
            phase = self.phases[name]
            if phase.status in ("completed", "skipped"):
                continue
            if self._deps_met(name):
                # This is the current phase — explain what's needed
                missing_tools = phase.required_tools - phase.tools_called
                if missing_tools:
                    return (
                        f"Phase '{name}' is in progress but missing required "
                        f"tool calls: {', '.join(sorted(missing_tools))}. "
                        f"Criteria: {phase.completion_criteria}"
                    )
                return f"Phase '{name}' is in progress. Criteria: {phase.completion_criteria}"
            else:
                unmet = [
                    d
                    for d in phase.dependencies
                    if self.phases[d].status not in ("completed", "skipped")
                ]
                return f"Phase '{name}' is blocked — waiting for: {', '.join(unmet)}"
        return None

    def to_prompt_context(self) -> str:
        """Format the PTG state for injection into the agent system prompt."""
        lines = ["=== PENETRATION TASK GRAPH (PTG) ==="]
        lines.append(
            f"Progress: {self.get_progress()['completed_phases']}"
            f"/{len(self._phase_order)} phases complete "
            f"({self.get_progress()['completion_pct']}%)"
        )
        lines.append("")
        for name in self._phase_order:
            p = self.phases[name]
            icon = {
                "pending": "[ ]",
                "in_progress": "[>]",
                "completed": "[x]",
                "skipped": "[-]",
            }[p.status]
            deps_str = f" (deps: {', '.join(p.dependencies)})" if p.dependencies else ""
            lines.append(f"  {icon} {name}{deps_str}")
            if p.status == "in_progress":
                lines.append(f"       {p.description}")
                missing = p.required_tools - p.tools_called
                if missing:
                    lines.append(
                        f"       Required tools not yet called: {', '.join(sorted(missing))}"
                    )
                lines.append(f"       Criteria: {p.completion_criteria}")
            if p.notes:
                for note in p.notes[-3:]:  # last 3 notes
                    lines.append(f"       Note: {note}")

        blocked = self.get_blocked_reason()
        if blocked:
            lines.append("")
            lines.append(f"BLOCKED: {blocked}")

        current = self.get_current_phase()
        if current:
            lines.append("")
            lines.append(f"CURRENT PHASE: {current.name}")
            lines.append(f"Action: {current.completion_criteria}")

        return "\n".join(lines)

    # ---- tool call tracking -----------------------------------------------

    def record_tool_call(self, tool_name: str, cmd: str = "") -> None:
        """Record that a tool was called; auto-advance phases.

        Args:
            tool_name: Name of the tool (e.g. "exec_command", "web_search").
            cmd: For exec_command, the command string (used for pattern matching).
        """
        # Find all phases that are in_progress and accept this tool
        for name in self._phase_order:
            phase = self.phases[name]
            if phase.status != "in_progress":
                continue
            if tool_name in phase.required_tools:
                phase.tools_called.add(tool_name)

        # For exec_command, do deeper pattern matching
        if tool_name == "exec_command" and cmd:
            self._record_exec_patterns(cmd)

        # Check if any phase can auto-complete
        self._check_auto_complete()

    def _record_exec_patterns(self, cmd: str) -> None:
        """Match exec_command content against phase-specific tool patterns."""
        recon = self.phases["RECON"]
        if recon.status == "in_progress" and _matches_any(cmd, _RECON_PATTERNS):
            recon.tools_called.add("exec_command")

        fp = self.phases["FINGERPRINT"]
        if fp.status == "in_progress" and _matches_any(cmd, _FINGERPRINT_PATTERNS):
            fp.tools_called.add("exec_command")

        vs = self.phases["VULNERABILITY_SCAN"]
        if vs.status == "in_progress" and _matches_any(cmd, _VULN_SCAN_PATTERNS):
            vs.tools_called.add("exec_command")

        ex = self.phases["EXPLOITATION"]
        if ex.status == "in_progress" and _matches_any(cmd, _EXPLOIT_PATTERNS):
            ex.tools_called.add("exec_command")

    def _check_auto_complete(self) -> None:
        """Auto-complete phases whose criteria are met."""
        for name in self._phase_order:
            phase = self.phases[name]
            if phase.status != "in_progress":
                continue
            if phase.required_tools and phase.required_tools.issubset(phase.tools_called):
                self.mark_phase_complete(name)

    # ---- internal helpers --------------------------------------------------

    def _deps_met(self, name: str) -> bool:
        """Check if all dependencies of a phase are completed/skipped."""
        phase = self.phases[name]
        return all(self.phases[d].status in ("completed", "skipped") for d in phase.dependencies)

    def _auto_start_next(self) -> None:
        """Start the next phase whose deps are now met."""
        for name in self._phase_order:
            phase = self.phases[name]
            if phase.status == "pending" and self._deps_met(name):
                self._start_phase(name)


# ---------------------------------------------------------------------------
# Module-level singleton — one PTG per scan
# ---------------------------------------------------------------------------

_active_ptg: PentestingTaskGraph | None = None


def get_active_ptg() -> PentestingTaskGraph | None:
    """Return the active PTG instance, if any."""
    return _active_ptg


def init_ptg() -> PentestingTaskGraph:
    """Create and activate a new PTG for the current scan."""
    global _active_ptg
    _active_ptg = PentestingTaskGraph()
    return _active_ptg


def reset_ptg() -> None:
    """Clear the active PTG (called at scan end)."""
    global _active_ptg
    _active_ptg = None


# ---------------------------------------------------------------------------
# function_tool — agent-callable progress query
# ---------------------------------------------------------------------------


@function_tool
async def get_scan_progress(ctx: RunContextWrapper) -> str:
    """Get the current penetration testing progress across all phases.

    Shows which phases are complete, which are in progress, what tools
    have been called, and what's blocking finish_scan.  Use this tool
    to orient yourself during a scan and understand what to do next.
    """
    ptg = get_active_ptg()
    if ptg is None:
        return json.dumps(
            {
                "error": "No active Penetration Task Graph. The PTG is initialized at scan start.",
            }
        )

    progress = ptg.get_progress()
    return json.dumps(progress, indent=2, default=str)
