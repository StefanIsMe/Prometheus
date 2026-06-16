"""``finish_scan`` — root-agent termination + executive report persistence."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

from prometheus.core.agents import coordinator_from_context
from prometheus.tools.todo.tools import get_pending_high_priority_todos
from prometheus.tools.ptg.tool import get_active_ptg


logger = logging.getLogger(__name__)

# Minimum phases that MUST be completed before finish_scan is accepted.
# EXPLOITATION is skippable (no vulns found). REPORTING is completed by this call.
_REQUIRED_PHASES = {"RECON", "FINGERPRINT", "THREAT_INTEL", "VULNERABILITY_SCAN"}


def _validate_scan_gates() -> dict[str, Any]:
    """Check PTG phases and mandatory tool usage before allowing scan completion.

    Returns a dict with 'passed' (bool) and 'blocked_reason' (str | None).
    When passed=False, blocked_reason explains exactly what the agent must do.
    """
    ptg = get_active_ptg()
    if ptg is None:
        # No PTG — allow finish (backward compat)
        return {"passed": True, "blocked_reason": None}

    # Check each required phase
    incomplete: list[str] = []
    blocked_details: list[str] = []

    for name in _REQUIRED_PHASES:
        phase = ptg.phases.get(name)
        if phase is None:
            continue
        if phase.status == "completed":
            continue
        incomplete.append(name)
        missing_tools = phase.required_tools - phase.tools_called
        detail = f"  {name}: status={phase.status}"
        if missing_tools:
            detail += f", missing tools: {', '.join(sorted(missing_tools))}"
        detail += f"\n    Criteria: {phase.completion_criteria}"
        blocked_details.append(detail)

    # Check EXPLOITATION — must be completed or skipped
    exploit = ptg.phases.get("EXPLOITATION")
    if exploit and exploit.status not in ("completed", "skipped"):
        incomplete.append("EXPLOITATION")
        blocked_details.append(
            f"  EXPLOITATION: status={exploit.status}\n"
            f"    Criteria: {exploit.completion_criteria}\n"
            f"    If no exploitable vulnerabilities were found, mark this phase as skipped."
        )

    if incomplete:
        details = "\n".join(blocked_details)
        return {
            "passed": False,
            "blocked_reason": (
                f"Scan cannot finish. {len(incomplete)} phase(s) incomplete:\n\n"
                f"{details}\n\n"
                f"Complete these phases before calling finish_scan. "
                f"Use get_scan_progress to check your current status."
            ),
        }

    # --- Check factory-level gates (Tor, fingerprint, research, nuclei) ---
    # These gates previously fired in _finish_tool_use_behavior AFTER the
    # report was already written.  Moving them here ensures the report is
    # only persisted when ALL gates pass.
    try:
        from prometheus.agents.factory import (  # noqa: PLC0415  # codeql[py/cyclic-import] : suppressed via the security dashboard triage
            _research_gate_enabled,
            _research_complete,
            _RESEARCH_REQUIRED_TOOLS,
            _research_calls,
            _tor_gate_enabled,
            _tor_verified,
            _tor_ever_used,
            _fingerprint_gate_enabled,
            _fingerprint_done,
            _nuclei_gate_enabled,
            _nuclei_run,
        )

        if _tor_gate_enabled and not _tor_verified and _tor_ever_used:
            return {
                "passed": False,
                "blocked_reason": (
                    "Tor verification not confirmed. Run "
                    "'curl -s --proxy socks5h://host.docker.internal:9050 "
                    "https://check.torproject.org/api/ip' and verify "
                    "'IsTor: true' before finishing."
                ),
            }

        if _fingerprint_gate_enabled and not _fingerprint_done:
            return {
                "passed": False,
                "blocked_reason": (
                    "No technology fingerprinting detected. Run httpx, whatweb, "
                    "or similar tools to identify the target stack before finishing."
                ),
            }

        if _research_gate_enabled and not _research_complete():
            missing = _RESEARCH_REQUIRED_TOOLS - _research_calls
            return {
                "passed": False,
                "blocked_reason": (
                    f"Mandatory research incomplete. "
                    f"Missing tool calls: {', '.join(missing)}. "
                    f"Call query_threat_feeds before finishing."
                ),
            }

        if _nuclei_gate_enabled and not _nuclei_run:
            return {
                "passed": False,
                "blocked_reason": (
                    "Nuclei scan required. Run nuclei against at least one target before finishing."
                ),
            }
    except ImportError:
        pass  # factory.py not available (shouldn't happen in production)

    # --- Filed-finding gate ---
    # The PTG tracks PHASE completion (did the agent run the right tools?)
    # but not finding filing (did the agent actually call
    # create_vulnerability_report for what it found?).  An agent can
    # run nuclei, see a CVE-2025-XXXX, and write "**Major finding**" in
    # its reasoning, then call finish_scan without ever filing — the
    # scan exits "completed" with zero findings.  This gate makes sure
    # the comms stream actually has a tool_call_stream for
    # create_vulnerability_report (or run_scan_pipeline) from this
    # scan_id before the report is written.
    #
    # Disabled when the comms stream is not active (e.g. dry-run) so
    # backward-compat is preserved. Bypass-able via the same
    # escape-hatch mechanism as the gate blocks (counted per agent, so
    # the existing _consecutive_gate_blocks in execution.py applies).
    try:
        from prometheus.core.comms import get_active_run
        from prometheus.core.execution import _FINDING_FILE_TOOLS
        from pathlib import Path as _Path

        run_id = get_active_run()
        if run_id:
            status_path = _Path.home() / ".prometheus" / "comms" / run_id / "status.jsonl"
            filed = False
            if status_path.exists():
                with status_path.open() as _f:
                    for _line in _f:
                        _line = _line.strip()
                        if not _line:
                            continue
                        try:
                            import json as _json

                            _ev = _json.loads(_line)
                        except ValueError:
                            continue
                        if _ev.get("type") != "tool_call_stream":
                            continue
                        if _ev.get("data", {}).get("tool") in _FINDING_FILE_TOOLS:
                            filed = True
                            break
            if not filed:
                return {
                    "passed": False,
                    "blocked_reason": (
                        "No vulnerability has been filed for this scan. "
                        "You must call create_vulnerability_report (or "
                        "run_scan_pipeline) at least once with concrete "
                        "evidence before finish_scan can succeed. "
                        "If you suspect a finding but have not yet "
                        "proven exploitability, run the validation tools "
                        "(e.g. nuclei, exec_command) until you have a "
                        "reproducible PoC, then file it."
                    ),
                }
    except ImportError:
        pass  # comms/execution not available (unit-test path)

    return {"passed": True, "blocked_reason": None}


def _do_finish(
    *,
    parent_id: str | None,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
) -> dict[str, Any]:
    if parent_id is not None:
        return {
            "success": False,
            "error": (
                "This tool can only be used by the root/main agent. "
                "If you are a subagent, use agent_finish instead"
            ),
        }

    errors: list[str] = []
    if not executive_summary.strip():
        errors.append("Executive summary cannot be empty")
    if not methodology.strip():
        errors.append("Methodology cannot be empty")
    if not technical_analysis.strip():
        errors.append("Technical analysis cannot be empty")
    if not recommendations.strip():
        errors.append("Recommendations cannot be empty")
    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    try:
        from prometheus.report.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            logger.warning("No global report state; scan results not persisted")
            return {
                "success": True,
                "scan_completed": True,
                "message": "Scan completed (not persisted)",
                "warning": "Results could not be persisted - report state unavailable",
            }
        report_state.update_scan_final_fields(
            executive_summary=executive_summary.strip(),
            methodology=methodology.strip(),
            technical_analysis=technical_analysis.strip(),
            recommendations=recommendations.strip(),
        )
        vuln_count = len(report_state.vulnerability_reports)
    except (ImportError, AttributeError) as e:
        logger.exception("finish_scan persistence failed")
        return {"success": False, "error": f"Failed to complete scan: {e!s}"}
    else:
        logger.info(
            "finish_scan: completed scan with %d vulnerability report(s)",
            vuln_count,
        )
        return {
            "success": True,
            "scan_completed": True,
            "message": "Scan completed successfully",
            "vulnerabilities_found": vuln_count,
        }


@function_tool(timeout=60)
async def finish_scan(
    ctx: RunContextWrapper,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
) -> str:
    """Finalize the scan — persist the customer-facing report.

    **Root-agent only.** Subagents must call ``agent_finish`` from the
    multi-agent graph tools instead. Calling this finalizes everything:

    1. Verifies you are the root agent.
    2. Writes the four narrative sections to the scan record.
    3. Marks the scan completed and stops execution.

    **Pre-flight checklist (mandatory — do not skip):**

    1. **Call ``view_agent_graph`` first.** Inspect every entry in the
       summary. If ANY agent is in ``running`` / ``waiting`` state,
       you MUST NOT call ``finish_scan`` yet —
       wrap them up first via ``send_message_to_agent`` (ask them to
       finish), ``wait_for_message`` (block until their report
       arrives), or ``stop_agent`` (graceful cancel). Only ``completed``
       / ``crashed`` / ``stopped`` agents are safe to leave behind.
       Calling ``finish_scan`` while children are alive orphans their
       work and produces an incomplete report.
    2. All vulnerabilities you found are filed via
       ``create_vulnerability_report`` (un-reported findings are not
       tracked and not credited).
    3. Don't double-report — one report per distinct vulnerability.

    **Calling this multiple times overwrites the previous report.**
    Make the single call comprehensive.

    **Customer-facing report rules** (this output is rendered into the
    final PDF the client sees):

    - Never mention internal infrastructure: no local/absolute paths
      (``/workspace/...``), no agent names, no sandbox/orchestrator/
      tooling references, no system prompts, no model-internal errors.
    - Tone: formal, third-person, objective, concise. This is a
      consultant deliverable, not an engineering log.
    - Each section has a specific role:

        - ``executive_summary`` — for non-technical leadership. Risk
          posture, business impact (data exposure / compliance /
          reputation), notable criticals, overarching remediation
          theme.
        - ``methodology`` — frameworks followed (OWASP WSTG, PTES,
          OSSTMM, NIST), engagement type (black/gray/white box), scope
          and constraints, categories of testing performed. **No**
          internal execution detail.
        - ``technical_analysis`` — consolidated findings overview with
          severity model and systemic root causes. Reference individual
          vuln reports for repro steps; don't duplicate raw evidence.
        - ``recommendations`` — prioritized actions grouped by urgency
          (Immediate / Short-term / Medium-term), each with concrete
          remediation steps. End with retest/validation guidance.

    Args:
        executive_summary: Business-level summary for leadership.
        methodology: Frameworks, scope, and approach.
        technical_analysis: Consolidated findings + systemic themes.
        recommendations: Prioritized, actionable remediation.
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    parent_id = inner.get("parent_id")
    if coordinator is not None and parent_id is None and me is not None:
        active_agents = await coordinator.active_agents_except(me)
    else:
        active_agents = []

    if active_agents:
        return json.dumps(
            {
                "success": False,
                "scan_completed": False,
                "error": (
                    "Cannot finish scan while child agents are still active. "
                    "Wait for completion, send them finish instructions, or stop them first"
                ),
                "active_agents": active_agents,
            },
            ensure_ascii=False,
            default=str,
        )

    # --- GATE ENFORCEMENT: validate PTG phases before writing report ---
    gate_result = _validate_scan_gates()
    if not gate_result["passed"]:
        return json.dumps(
            {
                "success": False,
                "scan_completed": False,
                "error": "GATE BLOCKED: " + gate_result["blocked_reason"],
            },
            ensure_ascii=False,
            default=str,
        )

    result = await asyncio.to_thread(
        _do_finish,
        parent_id=parent_id,
        executive_summary=executive_summary,
        methodology=methodology,
        technical_analysis=technical_analysis,
        recommendations=recommendations,
    )
    # Check for pending high/critical todos before allowing finish
    if parent_id is None and me is not None:
        pending_high = get_pending_high_priority_todos(me)
        if pending_high:
            pending_list = [
                {"todo_id": t["todo_id"], "title": t["title"], "priority": t["priority"]}
                for t in pending_high
            ]
            return json.dumps(
                {
                    "success": False,
                    "scan_completed": False,
                    "error": (
                        f"GATE BLOCKED: {len(pending_high)} HIGH/CRITICAL priority todo(s) still PENDING. "
                        "Complete them or mark them done/cancelled before finishing."
                    ),
                    "pending_todos": pending_list,
                },
                ensure_ascii=False,
                default=str,
            )
    if (
        result.get("success")
        and result.get("scan_completed")
        and coordinator is not None
        and isinstance(me, str)
    ):
        await coordinator.set_status(me, "completed")
    return json.dumps(result, ensure_ascii=False, default=str)
