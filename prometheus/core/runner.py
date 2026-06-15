"""Top-level prometheus scan runner."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from agents import RunConfig
from agents.models.multi_provider import MultiProvider
from agents.sandbox import SandboxRunConfig

from prometheus.agents.factory import build_prometheus_agent, make_child_factory
from prometheus.config import load_settings
from prometheus.config.models import (
    configure_sdk_model_defaults,
    normalize_model_name,
    uses_chat_completions_tool_schema,
)
from prometheus.core.agents import AgentCoordinator
from prometheus.core.comms import set_active_run, write_status
from prometheus.core.execution import (
    respawn_subagents,
    run_agent_loop,
)
from prometheus.core.execution import (
    spawn_child_agent as start_child_agent,
)
from prometheus.core.hooks import ReportUsageHooks
from prometheus.core.inputs import (
    DEFAULT_MAX_TURNS,
    build_root_task,
    build_scope_context,
    make_model_settings,
)
from prometheus.core.paths import run_dir_for, runtime_state_dir
from prometheus.core.sessions import open_agent_session
from prometheus.core.context_manager import (
    ContextManagedSession,
    ContextOverflowStore,
    create_context_managed_session,
)
from prometheus.runtime import session_manager
from prometheus.telemetry.logging import set_scan_id, setup_scan_logging
from prometheus.tools.threat_intel.tool import clear_scan_cache


if TYPE_CHECKING:
    from agents.memory import SQLiteSession
    from agents.result import RunResultBase


logger = logging.getLogger(__name__)

StreamEventSink = Callable[[str, Any], None]


# ---------------------------------------------------------------------------
# Phase 2B: a synthetic ExecResult used by ``_safe_exec`` to translate
# the post-shutdown ``RuntimeError: cannot schedule new futures`` into
# a normal failure (so call-sites see a failed result, not a raise).
# Kept at module level so external tests (test_safe_exec_shutdown.py)
# can import and inspect it.
# ---------------------------------------------------------------------------


class _SyntheticExecResult:
    """Mimics a failed ExecResult so the existing call-sites work unchanged."""

    def ok(self) -> bool:
        return False

    exit_code = -1
    stdout = b""
    stderr = b"executor shut down"


_SYNTHETIC_EXEC_FAILURE = _SyntheticExecResult()


async def run_prometheus_scan(
    *,
    scan_config: dict[str, Any],
    scan_id: str | None = None,
    image: str,
    local_sources: list[dict[str, str]] | None = None,
    coordinator: AgentCoordinator | None = None,
    interactive: bool = False,
    max_turns: int = DEFAULT_MAX_TURNS,
    model: str | None = None,
    cleanup_on_exit: bool = True,
    event_sink: StreamEventSink | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> RunResultBase | None:
    """Run or resume one prometheus scan against a sandbox."""

    def _progress(msg: str) -> None:
        logger.info("[scan %s] %s", scan_id, msg)
        if progress_callback:
            progress_callback(msg)

    if scan_id is None:
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"

    _progress("Setting up scan directories...")
    run_dir = run_dir_for(scan_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    teardown_logging = setup_scan_logging(run_dir)
    set_scan_id(scan_id)
    set_active_run(scan_id)
    clear_scan_cache()

    # --- Phase 3D: LLM budget preflight ---
    # Cheap, fast credits check BEFORE we spin up a sandbox. Saves a
    # full scan launch when the account is out of credits.
    try:
        from prometheus.core.runner import _check_llm_budget

        budget_ok, budget_msg = await _check_llm_budget(scan_id)
        if not budget_ok:
            _progress(f"Budget preflight FAILED: {budget_msg}")
            logger.error(
                "LLM budget preflight failed for scan %s: %s",
                scan_id,
                budget_msg,
            )
            return None
    except Exception as exc:
        # Never let a budget-check failure kill a scan — log and continue.
        logger.warning("LLM budget preflight raised (non-fatal): %s", exc)

    # --- ALWAYS refresh threat intel from online sources before scan ---
    _progress("Refreshing threat intelligence feeds from online sources...")
    try:
        from prometheus.tools.threat_intel.feeds import ingest_all
        from prometheus.tools.threat_intel.local_db import ThreatIntelDB

        _progress("  Connecting to local threat intel database...")
        intel_db = ThreatIntelDB()
        try:
            _progress("  Pulling CISA KEV, NVD, GHSA, EPSS, Shodan, CIRCL, Exploit-DB...")
            intel_summary = await asyncio.to_thread(ingest_all, intel_db)
            total_records = intel_summary.get("total_records", 0)
            total_duration = intel_summary.get("total_duration", 0)
            errors = intel_summary.get("errors", [])
            _progress(f"  Threat intel refreshed: {total_records} records in {total_duration:.1f}s")
            db_stats = intel_summary.get("db_stats", {})
            if db_stats:
                _progress(
                    f"  Local DB: {db_stats.get('total_cves', 0)} CVEs, "
                    f"{db_stats.get('cisa_kev_count', 0)} KEV, "
                    f"{db_stats.get('exploit_count', 0)} with exploits"
                )
            if errors:
                _progress(f"  Warning: {len(errors)} feed(s) had errors (continuing)")
                for err in errors[:3]:
                    _progress(f"    - {err}")
            logger.info(
                "Pre-scan threat intel refreshed: %d records in %.1fs, %d errors",
                total_records,
                total_duration,
                len(errors),
            )
        finally:
            intel_db.close()
    except Exception as exc:
        _progress(f"Threat intel refresh FAILED: {exc}")
        _progress("Continuing with existing database — results may be stale")
        logger.warning("Pre-scan threat intel refresh failed (non-fatal): %s", exc)
    # --- Query local threat intel DB for pre-scan context ---
    _threat_intel_context: str = ""
    try:
        from prometheus.tools.threat_intel.query_engine import query_threats

        # Build fingerprints from scan_config for local DB lookup
        _ti_fingerprints = _build_threat_fingerprints(scan_config)
        if _ti_fingerprints:
            _ti_result = await query_threats(_ti_fingerprints)
            if _ti_result.get("success") and _ti_result.get("total_vulnerabilities", 0) > 0:
                _threat_intel_context = _format_threat_intel_context(_ti_result)
                logger.info(
                    "Pre-scan threat intel: %d vulns across %d technologies (%d local, %d online)",
                    _ti_result.get("total_vulnerabilities", 0),
                    _ti_result.get("technologies_queried", 0),
                    _ti_result.get("local_hits", 0),
                    _ti_result.get("online_fallbacks", 0),
                )
    except Exception as exc:
        logger.warning("Pre-scan threat intel query failed (non-fatal): %s", exc)

    # --- Offline HTTP fingerprint (no LLM, no sandbox) ---
    _pre_scan_fingerprints: dict[str, str] = {}
    try:
        import subprocess

        _progress("Running offline HTTP fingerprint...")
        for target in scan_config.get("targets", []) or []:
            url = target.get("details", {}).get("target_url") or target.get("original") or ""
            if not url or not url.startswith("http"):
                continue
            domain = url.split("/")[2] if "//" in url else url
            try:
                result = subprocess.run(
                    [
                        "curl",
                        "-sS",
                        "-o",
                        "/dev/null",
                        "-D",
                        "-",
                        "--connect-timeout",
                        "10",
                        "--max-time",
                        "15",
                        "-H",
                        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/IP_ADDRESS Safari/537.36",
                        url,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                headers = result.stdout[:2000]
                status_line = headers.split("\n")[0] if headers else "no response"
                content_length = ""
                server = ""
                for line in headers.split("\n"):
                    if line.lower().startswith("content-length:"):
                        content_length = line.strip()
                    if line.lower().startswith("server:"):
                        server = line.strip()
                ssl_info = ""
                ssl_result = subprocess.run(
                    [
                        "curl",
                        "-sS",
                        "-o",
                        "/dev/null",
                        "-w",
                        "SSL:%{ssl_verify_result}|TLS:%{ssl_version}|Issuer:%{ssl_issuer}",
                        "--connect-timeout",
                        "10",
                        url,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if ssl_result.returncode == 0:
                    ssl_info = ssl_result.stdout.strip()[:500]
                fingerprint = (
                    f"URL: {url}\n"
                    f"Status: {status_line}\n"
                    f"Server: {server}\n"
                    f"Content-Length: {content_length}\n"
                    f"SSL/TLS: {ssl_info}\n"
                    f"Headers (first 2KB):\n{headers}"
                )
                _pre_scan_fingerprints[domain] = fingerprint
                logger.info(
                    "Pre-scan fingerprint for %s: %s (headers=%d bytes)",
                    domain,
                    status_line.strip(),
                    len(headers),
                )
            except Exception as exc:
                logger.warning("Pre-scan fingerprint failed for %s: %s", url, exc)
    except Exception as exc:
        logger.warning("Pre-scan HTTP fingerprint failed (non-fatal): %s", exc)

    write_status(
        scan_id,
        "scan_start",
        {"targets": [t.get("original", "") for t in scan_config.get("targets", [])]},
    )

    agents_path = state_dir / "agents.json"
    agents_db = state_dir / "agents.db"
    is_resume = agents_path.exists()

    logger.info(
        "%s prometheus scan %s (image=%s, max_turns=%d, interactive=%s, run_dir=%s)",
        "Resuming" if is_resume else "Starting",
        scan_id,
        image,
        max_turns,
        interactive,
        run_dir,
    )

    settings = load_settings()
    # Prometheus is single-mode: every scan is deep. Use the HARD model
    # tier for the root agent and SIMPLE for children.
    resolution = configure_sdk_model_defaults(settings)
    resolved_model = normalize_model_name(model or settings.llm.model or "")
    if not resolved_model:
        raise RuntimeError(
            "No LLM model configured. Set provider API keys and check ~/.prometheus/llm.yaml.",
        )
    logger.info(
        "LLM model resolved: %s (provider=%s, tier=%s)",
        resolved_model,
        resolution.provider_name,
        resolution.tier.value,
    )
    chat_completions_tools = uses_chat_completions_tool_schema(resolved_model, settings)

    if coordinator is None:
        coordinator = AgentCoordinator()
    coordinator.set_snapshot_path(agents_path)

    from prometheus.core.attack_surface import hydrate_attack_surface_from_disk
    from prometheus.core.hypotheses import hydrate_hypotheses_from_disk
    from prometheus.core.scan_goals import ScanGoalManager
    from prometheus.tools.coverage.tool import hydrate_coverage_from_disk
    from prometheus.tools.knowledge.store import KnowledgeStore
    from prometheus.tools.notes.tools import hydrate_notes_from_disk
    from prometheus.tools.todo.tools import hydrate_todos_from_disk

    hydrate_todos_from_disk(state_dir)
    hydrate_notes_from_disk(state_dir)
    hydrate_coverage_from_disk(state_dir)
    hydrate_hypotheses_from_disk(state_dir)
    hydrate_attack_surface_from_disk(state_dir)

    # Initialize discovery goal manager for this scan
    goal_manager = ScanGoalManager(state_dir)
    goal_manager.load()
    logger.info("Loaded %d existing discovery goals", len(goal_manager.get_all_goals()))

    # Hydrate cross-scan knowledge for target domains
    targets: list[dict[str, Any]] = scan_config.get("targets") or []
    ks = KnowledgeStore()
    prior_knowledge_summary: list[str] = []
    target_domains: list[str] = []
    total_knowledge_entries = 0
    targets_with_knowledge: set[str] = set()  # domains that have prior knowledge
    for target in targets:
        domain: str = target.get("original") or target.get("value") or ""
        if domain:
            target_domains.append(domain)
            entries = ks.hydrate(domain)
            if entries:
                total_knowledge_entries += len(entries)
                targets_with_knowledge.add(domain)
                logger.info("Loaded %d prior knowledge entries for %s", len(entries), domain)
                # Build summary for agent injection
                for entry in entries[:20]:  # Cap at 20 to avoid context bloat
                    cat = entry.get("category", "")
                    key = entry.get("key", "")
                    val = str(entry.get("value", ""))[:200]
                    prior_knowledge_summary.append(f"  [{cat}] {key}: {val}")
                if len(entries) > 20:
                    prior_knowledge_summary.append(f"  ... and {len(entries) - 20} more entries")

            # Record scan start in target profile
            instruction_val = str(scan_config.get("user_instructions") or "")
            custom_headers_val = scan_config.get("custom_headers") or []
            ks.record_scan_start(
                domain=domain,
                scan_id=scan_id,
                instruction=instruction_val,
                custom_headers=custom_headers_val,
            )
            logger.info("Recorded scan start in target profile for %s", domain)

    # --- Tor routing strategy: query tor_status knowledge per target ---
    tor_routing_summary: list[str] = []
    for domain in target_domains:
        tor_entries = ks.query(domain, category="tor_status")
        if tor_entries:
            for entry in tor_entries:
                key = entry.get("key", "")
                val = str(entry.get("value", ""))[:200]
                tor_routing_summary.append(f"  {domain}: [{key}] {val}")
        else:
            tor_routing_summary.append(f"  {domain}: no prior tor_status — use Phase 1 (Tor)")

    if tor_routing_summary:
        logger.info("Tor routing knowledge: %d targets", len(tor_routing_summary))

    root_id: str | None = None
    if is_resume:
        try:
            snap = json.loads(agents_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json is unreadable: {exc}",
            ) from exc
        if not agents_db.exists():
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: missing SDK session database at {agents_db}",
            )
        await coordinator.restore(snap)
        for aid, parent in coordinator.parent_of.items():
            if parent is None:
                root_id = aid
                break
        if root_id is None:
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json has no root agent (parent=None)",
            )
        logger.info(
            "Resume: restored coordinator with %d agent(s); root=%s",
            len(coordinator.statuses),
            root_id,
        )
    else:
        root_id = uuid.uuid4().hex[:8]

    logger.info("Bringing up sandbox session for scan %s", scan_id)
    _progress("Creating Docker sandbox (this takes 20-30s)...")
    bundle = await session_manager.create_or_reuse(
        scan_id,
        image=image,
        local_sources=local_sources or [],
        allow_direct=bool(scan_config.get("allow_direct", False)),
    )
    _progress("Sandbox ready. Updating nuclei templates...")
    logger.info("Sandbox ready for scan %s", scan_id)

    # --- ALWAYS update nuclei templates before agents start ---
    session = bundle.get("session")
    _pre_scan_technologies: dict[str, str] = {}
    _wpscan_results: dict[str, dict[str, Any]] = {}

    # Phase 2B: wrap every ``session.exec`` call below with a small helper
    # that converts the post-shutdown ``RuntimeError: cannot schedule new
    # futures after shutdown`` into a clean failure rather than bubbling
    # up and crashing the run-loop.
    async def _safe_exec(*args: Any, **kwargs: Any) -> Any:
        """Call ``session.exec`` and translate the executor-shutdown error.

        The SDK's BaseSandboxSession.exec awaits on a private ThreadPoolExecutor.
        When the parent process's ``_python_exit`` hook tears it down first,
        the next ``await session.exec(...)`` raises a ``RuntimeError`` with
        ``cannot schedule new futures after shutdown`` in the message — this
        would normally bubble up and kill the scan. We catch it and return a
        synthetic failure result so the caller (which always inspects
        ``.ok()`` / ``.stdout``) sees a normal failure and the scan continues.
        """
        try:
            return await session.exec(*args, **kwargs)
        except RuntimeError as exc:
            if "cannot schedule new futures" not in str(exc):
                raise
            logger.warning(
                "[scan %s] session.exec failed: executor shut down — returning synthetic failure",
                scan_id,
            )
            return _SYNTHETIC_EXEC_FAILURE

    if session:
        try:
            nuc_result = await _safe_exec(
                "sh",
                "-c",
                "which nuclei && nuclei -update-templates -silent 2>&1 || echo 'nuclei not installed'",
                timeout=60,
            )
            nuc_out = nuc_result.stdout.decode("utf-8", errors="replace").strip()[:500]
            logger.info("Pre-scan nuclei template update: %s", nuc_out)
            _progress("Nuclei templates updated. Running tech detection...")
        except Exception as exc:
            _progress("Nuclei update skipped (non-fatal). Building agents...")
            logger.warning("Pre-scan nuclei update failed (non-fatal): %s", exc)

        # --- Pre-scan technology fingerprinting (httpx -tech-detect) ---
        # Runs before agents start so FINGERPRINT phase is pre-satisfied.
        # This eliminates the #1 cause of incomplete scans — the agent
        # skipping fingerprinting tools and then being blocked by gates.
        try:
            for target in scan_config.get("targets", []) or []:
                url = target.get("details", {}).get("target_url") or target.get("original") or ""
                if not url or not url.startswith("http"):
                    continue
                domain = url.split("/")[2] if "//" in url else url
                try:
                    tech_result = await _safe_exec(
                        "sh",
                        "-c",
                        f"httpx -u {url} -tech-detect -json -silent -timeout 15 2>&1",
                        timeout=30,
                    )
                    tech_out = tech_result.stdout.decode("utf-8", errors="replace").strip()
                    if tech_out:
                        _pre_scan_technologies[domain] = tech_out
                        logger.info(
                            "Pre-scan tech detection for %s: %d bytes",
                            domain,
                            len(tech_out),
                        )
                        # Save technology data to knowledge store for PTG
                        try:
                            import json as _json

                            tech_data = _json.loads(tech_out.split("\n")[0])
                            tech_names = tech_data.get("tech", [])
                            if tech_names:
                                ks.store(
                                    domain=domain,
                                    category="tech_stack",
                                    key="technologies",
                                    value=", ".join(tech_names),
                                )
                                logger.info(
                                    "Saved %d technologies for %s to knowledge store",
                                    len(tech_names),
                                    domain,
                                )
                        except Exception:
                            logger.debug(
                                "Failed to parse httpx output for %s", domain, exc_info=True
                            )
                except Exception as exc:
                    logger.warning("Pre-scan tech detection failed for %s: %s", url, exc)
            if _pre_scan_technologies:
                _progress("Tech detection complete. Running WPScan on WordPress targets...")

            # --- WPScan: auto-run on WordPress targets through Tor ---
            if _pre_scan_technologies:
                for domain, tech_json in _pre_scan_technologies.items():
                    is_wordpress = False
                    try:
                        import json as _json

                        tech_data = _json.loads(tech_json.split("\n")[0])
                        tech_names = [t.lower() for t in tech_data.get("tech", [])]
                        is_wordpress = "wordpress" in tech_names
                    except Exception:
                        logger.debug("WPScan: could not parse tech data for %s", domain)

                    if not is_wordpress:
                        continue

                    _progress(f"WordPress detected on {domain} — launching WPScan through Tor...")
                    try:
                        from prometheus.tools.wpscan.tool import (
                            build_wpscan_context_block,
                            findings_to_knowledge_entries,
                            parse_wpscan_results,
                            run_wpscan,
                        )

                        target_url = f"https://{domain}"
                        # Find the original URL from scan config for scheme correctness
                        for target in scan_config.get("targets", []):
                            orig = target.get("original", "")
                            if domain in orig:
                                target_url = orig
                                break

                        wpscan_data = await run_wpscan(session, target_url)
                        _wpscan_results[domain] = wpscan_data

                        if not wpscan_data.get("error"):
                            # Save findings to knowledge store
                            findings = parse_wpscan_results(wpscan_data, domain)
                            entries = findings_to_knowledge_entries(
                                findings,
                                domain,
                                scan_id=scan_id,
                            )
                            for entry in entries:
                                ks.store(
                                    domain=entry["domain"],
                                    category=entry["category"],
                                    key=entry["key"],
                                    value=entry["value"],
                                    confidence=entry["confidence"],
                                    source=entry["source"],
                                    scan_id=entry["scan_id"],
                                )
                            v_count = len(findings)
                            k_count = len(entries)
                            _progress(
                                f"WPScan found {v_count} items on {domain} "
                                f"({k_count} saved to knowledge store)"
                            )
                        else:
                            _progress(
                                f"WPScan failed for {domain}: {wpscan_data.get('message', 'Unknown error')}"
                            )
                    except ImportError:
                        logger.warning("WPScan tool module not available — skipping")
                    except Exception as exc:
                        logger.exception("WPScan failed for %s", domain)
                        _progress(f"WPScan error for {domain}: {exc}")

            _progress("Building agents...")
        except Exception as exc:
            logger.warning("Pre-scan tech detection failed (non-fatal): %s", exc)

    sessions_to_close: list[SQLiteSession] = []

    try:
        targets = scan_config.get("targets") or []
        is_whitebox = any(t.get("type") == "local_code" for t in targets)
        skills = list(scan_config.get("skills") or [])
        # Determine if this is a rescan (prior knowledge exists for all targets)
        is_rescan = bool(prior_knowledge_summary)

        root_task = build_root_task(
            scan_config,
            is_rescan=is_rescan,
            targets_with_knowledge=targets_with_knowledge if targets_with_knowledge else None,
        )

        # Inject prior knowledge into the root task if available
        if prior_knowledge_summary:
            knowledge_block = "\n".join(prior_knowledge_summary)

            # Build comprehensive rescan context
            profile_blocks: list[str] = []
            previous_findings_blocks: list[str] = []
            unassessed_knowledge: list[str] = []

            for domain in target_domains:
                profile = ks.get_target_profile(domain)
                if not profile.get("exists"):
                    continue

                p = profile["profile"]
                scans = profile.get("scan_history", [])
                failed = profile.get("failed_approaches", [])
                succeeded = profile.get("successful_techniques", [])
                knowledge_by_cat = profile.get("knowledge_by_category", {})

                block_lines = [
                    f"\n=== TARGET PROFILE: {domain} ===",
                    f"Total scans: {p.get('scan_count', 0)}",
                    f"Total findings: {p.get('total_findings', 0)} "
                    f"(C:{p.get('critical_count', 0)} H:{p.get('high_count', 0)} "
                    f"M:{p.get('medium_count', 0)} L:{p.get('low_count', 0)} "
                    f"I:{p.get('info_count', 0)})",
                    f"First scan: {p.get('first_scan_at', 'unknown')}",
                    f"Last scan: {p.get('last_scan_at', 'unknown')} ({p.get('last_status', 'unknown')})",
                ]

                if scans:
                    block_lines.append(f"\nScan history ({len(scans)} runs):")
                    for s in scans[:5]:
                        block_lines.append(
                            f"  {s['scan_id']} | {s['status']} | "
                            f"{s['finding_count']} findings | "
                            f"{s.get('started_at', '?')[:10]}"
                        )

                # Include previous findings explicitly
                prev_findings = ks.get_findings_for_domain(domain)
                if prev_findings:
                    findings_header = (
                        f"\n=== PREVIOUS FINDINGS for {domain} ({len(prev_findings)} total) ==="
                    )
                    finding_lines = [findings_header]
                    for f_entry in prev_findings:
                        finding_lines.append(
                            f"  [{f_entry.get('lifecycle_status', '?')}] {f_entry.get('title', '')} "
                            f"(severity: {f_entry.get('severity', '?')}, "
                            f"endpoint: {f_entry.get('endpoint', '?')})"
                        )
                    previous_findings_blocks.append("\n".join(finding_lines))

                # Identify unassessed knowledge (vulnerability entries not yet filed)
                vuln_entries = knowledge_by_cat.get("vulnerability", [])
                finding_titles_lower = {f.get("title", "").lower() for f in prev_findings}
                for ve in vuln_entries:
                    ve_key = ve.get("key", "").lower()
                    # Check if this knowledge entry has a corresponding finding
                    already_filed = any(ve_key in ft or ft in ve_key for ft in finding_titles_lower)
                    if not already_filed:
                        unassessed_knowledge.append(
                            f"  [{ve.get('category', '?')}] {ve.get('key', '')}: "
                            f"{str(ve.get('value', ''))[:200]}"
                        )

                if failed:
                    block_lines.append("\nFailed approaches (DO NOT repeat):")
                    for f_entry in failed[:5]:
                        block_lines.append(f"  - {f_entry['key']}: {f_entry['value'][:150]}")

                if succeeded:
                    block_lines.append("\nSuccessful techniques (build on these):")
                    for s_entry in succeeded[:5]:
                        block_lines.append(f"  - {s_entry['key']}: {s_entry['value'][:150]}")

                block_lines.append(f'\nUse get_target_profile("{domain}") for full details.')
                profile_blocks.append("\n".join(block_lines))

            profile_section = "\n".join(profile_blocks) if profile_blocks else ""
            findings_section = (
                "\n".join(previous_findings_blocks) if previous_findings_blocks else ""
            )
            unassessed_section = (
                (
                    "\n=== UNASSESSED KNOWLEDGE (discovered but NOT yet filed as findings) ===\n"
                    + "\n".join(unassessed_knowledge[:20])
                )
                if unassessed_knowledge
                else ""
            )

            # Rescan-specific mandatory directive
            rescan_directive = """
RESCAN MODE — EFFICIENCY DIRECTIVES:
1. DO NOT re-fingerprint the tech stack — use the tech_stack knowledge entries above.
2. DO NOT re-run basic recon (robots.txt, sitemap, headers) unless there's reason to believe they changed.
3. FIRST PRIORITY: Validate that previous findings still exist. For each finding listed above, send the exact request and confirm the vulnerability is still present. Mark as "validated" or "fixed".
4. SECOND PRIORITY: Check the UNASSESSED KNOWLEDGE section. These are vulnerabilities discovered in prior scans but never filed as formal findings. For each one, create a proper finding with reproducible PoC evidence.
5. THIRD PRIORITY: Look for new attack surface not covered by previous scans. Check for new endpoints, changed responses, or newly deployed features.
6. TOKEN BUDGET: This is a rescan. Target 40% or fewer tokens than a first scan. Use offline tools (nuclei, local threat intel DB, shell scripts) before making LLM calls.
7. If nothing has changed and all previous findings are still valid, report that and finish. Do not pad the scan with redundant checks.
""".strip()

            root_task = (
                f"{rescan_directive}\n\n"
                f"TARGET PROFILE AND PRIOR KNOWLEDGE:\n"
                f"{profile_section}\n\n"
                f"{findings_section}\n\n"
                f"{unassessed_section}\n\n"
                f"KNOWLEDGE ENTRIES:\n{knowledge_block}\n\n"
                f"ORIGINAL SCAN TASK:\n{root_task}"
            )

        # Inject local threat intel context if available
        if _threat_intel_context:
            root_task = (
                f"KNOWN VULNERABILITIES (from local threat intel DB):\n"
                f"{_threat_intel_context}\n\n"
                f"Use this pre-computed vulnerability data to prioritize testing. "
                f"These CVEs were matched against detected technologies. "
                f"Focus on CISA KEV entries and high-priority CVEs first.\n\n"
                f"{root_task}"
            )

        # Inject pre-scan HTTP fingerprint if available (no LLM needed for this data)
        if _pre_scan_fingerprints:
            fp_block = "\n\n".join(
                f"--- {domain} ---\n{fp}" for domain, fp in _pre_scan_fingerprints.items()
            )
            root_task = (
                f"OFFLINE PRE-SCAN FINGERPRINT (gathered without LLM, use directly):\n"
                f"{fp_block}\n\n"
                f"This data was gathered before the scan started. "
                f"You do NOT need to re-request the homepage or re-check headers. "
                f"Use these status codes, headers, and SSL info directly. "
                f"Only re-request if you suspect the response changed.\n\n"
                f"{root_task}"
            )

        # Inject pre-scan technology detection if available
        if _pre_scan_technologies:
            tech_block = "\n\n".join(
                f"--- {domain} ---\n{tech}" for domain, tech in _pre_scan_technologies.items()
            )
            root_task = (
                f"OFFLINE TECHNOLOGY DETECTION (gathered via httpx -tech-detect, use directly):\n"
                f"{tech_block}\n\n"
                f"Technology fingerprinting is COMPLETE. You do NOT need to run httpx, "
                f"whatweb, or any other fingerprinting tools. The tech stack is already "
                f"identified above. Use these technologies for threat intel research.\n\n"
                f"{root_task}"
            )

        # Inject WPScan results if available
        if _wpscan_results:
            from prometheus.tools.wpscan.tool import build_wpscan_context_block

            wpscan_block = "\n\n".join(
                build_wpscan_context_block(data, domain) for domain, data in _wpscan_results.items()
            )
            root_task = (
                f"WPSCAN RESULTS (run pre-scan through Tor, use directly):\n"
                f"{wpscan_block}\n\n"
                f"WPScan has already been run against WordPress targets through Tor. "
                f"Do NOT re-run WPScan. Use the findings above for vulnerability research. "
                f"Vulnerabilities marked critical/high were already saved to the knowledge store.\n\n"
                f"{root_task}"
            )

        # Inject Tor routing strategy if available
        if tor_routing_summary:
            tor_block = "\n".join(tor_routing_summary)
            root_task = (
                f"TOR ROUTING STRATEGY (two-phase scanning):\n"
                f"Phase 1: ALL scans MUST go through Tor first (mandatory).\n"
                f"Phase 2: If a target REJECTS Tor (connection refused, 403, timeout),\n"
                f"save tor_status knowledge (save_knowledge category=tor_status, key=tor_rejected,\n"
                f"value=true with details), then use #tor-bypass# prefix for direct connections.\n\n"
                f"Known Tor status from previous scans:\n{tor_block}\n\n"
                f"Targets marked tor_rejected=true: use #tor-bypass# prefix on commands.\n"
                f"Targets with no tor_status: test via Tor first (Phase 1).\n\n"
                f"{root_task}"
            )

        model_settings = make_model_settings(
            settings.llm.reasoning_effort,
            supports_thinking=resolution.supports_thinking,
            provider_name=resolution.provider_name,
            model_id=resolved_model,
        )
        run_config = RunConfig(
            model=resolved_model,
            model_provider=MultiProvider(unknown_prefix_mode="model_id"),
            model_settings=model_settings,
            sandbox=SandboxRunConfig(client=bundle["client"], session=bundle["session"]),
            trace_include_sensitive_data=False,
        )
        hooks = ReportUsageHooks(model=resolved_model)

        scope_context = build_scope_context(scan_config)

        # Use target domain as agent name for single-target scans
        agent_name = (
            (targets[0].get("original") or "prometheus").split("/")[0]
            if len(targets) == 1
            else "prometheus"
        )

        root_agent = build_prometheus_agent(
            name=agent_name,
            skills=skills,
            is_root=True,
            is_whitebox=is_whitebox,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            system_prompt_context=scope_context,
            prior_knowledge_count=total_knowledge_entries,
            pre_scan_fingerprint_done=bool(_pre_scan_technologies),
        )

        _progress("Registering root agent...")
        if not is_resume:
            await coordinator.register(
                root_id,
                agent_name,
                parent_id=None,
                task=root_task,
                skills=skills,
            )

        child_agent_builder = make_child_factory(
            is_whitebox=is_whitebox,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            system_prompt_context=scope_context,
        )

        async def spawn_child_agent(**kwargs: Any) -> dict[str, Any]:
            return await start_child_agent(
                coordinator=coordinator,
                factory=child_agent_builder,
                agents_db_path=agents_db,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                event_sink=event_sink,
                hooks=hooks,
                **kwargs,
            )

        context: dict[str, Any] = {
            "coordinator": coordinator,
            "sandbox_session": bundle["session"],
            "caido_client": bundle["caido_client"],
            "agent_id": root_id,
            "parent_id": None,
            "interactive": interactive,
            "spawn_child_agent": spawn_child_agent,
            "goal_manager": goal_manager,
            "state_dir": str(state_dir),
        }

        root_session = open_agent_session(root_id, agents_db)
        # Phase 0+1: Wrap with context management (truncation + masking)
        # Phase 4: Use SQLite-backed overflow store for demand paging
        overflow_db = state_dir / "context_overflow.db"
        overflow_store = ContextOverflowStore(db_path=str(overflow_db))
        managed_session = create_context_managed_session(
            inner=root_session,
            enable_truncation=True,
            enable_masking=True,
            mask_after_turns=3,
        )
        # Set the overflow store on the managed session
        managed_session._overflow = overflow_store
        # Phase 4: Register overflow store for the paging tools
        from prometheus.tools.context_paging import set_overflow_store

        set_overflow_store(overflow_store)
        sessions_to_close.append(root_session)
        await coordinator.attach_runtime(root_id, session=managed_session)

        if is_resume:
            await respawn_subagents(
                coordinator=coordinator,
                factory=child_agent_builder,
                agents_db_path=agents_db,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                parent_ctx=context,
                root_id=root_id,
                event_sink=event_sink,
                hooks=hooks,
            )

        initial_input: Any = [] if is_resume else root_task

        _progress("Starting agent loop (first LLM call may take 10-20s)...")
        # Resume + new ``--instruction``: SDK replay drives root from
        # agents.db with ``initial_input=[]``, so a brand-new instruction
        # passed on the resume CLI would otherwise be silently ignored.
        # Inject it as a fresh user message in root's SDK session; the
        # next run cycle will replay it with the rest of the session.
        resume_instruction = str(scan_config.get("resume_instruction") or "").strip()
        if is_resume and resume_instruction:
            await coordinator.send(
                root_id,
                {
                    "from": "user",
                    "type": "instruction",
                    "priority": "high",
                    "content": resume_instruction,
                },
            )
            logger.info(
                "Resume: injected new instruction into root SDK session (len=%d)",
                len(resume_instruction),
            )

        async with coordinator._lock:
            root_status = coordinator.statuses.get(root_id)

        result = await run_agent_loop(
            agent=root_agent,
            initial_input=initial_input,
            run_config=run_config,
            context=context,
            max_turns=max_turns,
            coordinator=coordinator,
            agent_id=root_id,
            interactive=interactive,
            session=root_session,
            start_parked=bool(interactive and is_resume and root_status != "running"),
            event_sink=event_sink,
            hooks=hooks,
        )
        # Wait for child agents to finish before tearing down sessions.
        # Without this, children still writing findings get their SQLite
        # sessions yanked out from under them, losing all results.
        await _wait_for_children(coordinator, root_id)
        return result
    except BaseException:
        logger.exception("prometheus scan %s failed", scan_id)
        if root_id is not None:
            await coordinator.cancel_descendants(root_id)
            with contextlib.suppress(Exception):
                await coordinator.set_status(root_id, "failed")
        raise
    finally:
        for s in sessions_to_close:
            with contextlib.suppress(Exception):
                s.close()
        with contextlib.suppress(Exception):
            await coordinator._maybe_snapshot()
        if cleanup_on_exit:
            logger.info("Tearing down sandbox session for scan %s", scan_id)
            await session_manager.cleanup(scan_id)

        # Record scan end in target profiles
        try:
            vuln_path = run_dir / "vulnerabilities.json"
            findings_list: list[dict[str, Any]] = []
            if vuln_path.exists():
                findings_list = json.loads(vuln_path.read_text(encoding="utf-8"))
            # Determine final status
            scan_status = "completed"
            try:
                run_json_path = run_dir / "run.json"
                if run_json_path.exists():
                    run_data = json.loads(run_json_path.read_text(encoding="utf-8"))
                    scan_status = run_data.get("status", "completed")
                    llm_usage = run_data.get("llm_usage", {})
                    llm_requests = llm_usage.get("requests")
                    total_tokens = llm_usage.get("total_tokens")
                else:
                    llm_requests = None
                    total_tokens = None
            except Exception:
                logger.debug(
                    "Failed to read run.json for LLM usage stats (non-fatal)",
                    exc_info=True,
                )
                llm_requests = None
                total_tokens = None

            for domain in target_domains:
                ks.record_scan_end(
                    domain=domain,
                    scan_id=scan_id,
                    status=scan_status,
                    findings=findings_list,
                    llm_requests=llm_requests,
                    total_tokens=total_tokens,
                )
                # Auto-register findings in report_status tracker.
                # Before syncing, run should_revalidate on each finding to
                # block re-filing when the external state says "closed" and
                # the cooldown hasn't elapsed. This is the scan-end gate
                # that prevents a re-scanned finding from being silently
                # accepted as a new submission.
                if findings_list:
                    try:
                        filtered_findings: list[dict[str, Any]] = []
                        blocked: list[dict[str, Any]] = []
                        for f in findings_list:
                            try:
                                policy = ks.should_revalidate(
                                    domain=domain,
                                    finding_title=str(f.get("title") or ""),
                                    endpoint=str(f.get("endpoint") or ""),
                                    cwe=str(f.get("cwe") or ""),
                                )
                                if policy.get("action") == "archive":
                                    blocked.append(
                                        {
                                            "title": f.get("title"),
                                            "reason": policy.get("reason"),
                                        }
                                    )
                                    continue
                                filtered_findings.append(f)
                            except Exception:
                                # On policy-check failure, default to
                                # letting the sync proceed (matches
                                # the previous "always sync" behavior).
                                filtered_findings.append(f)
                        if blocked:
                            logger.info(
                                "runner.py: scan-end dedup blocked %d finding(s) on %s "
                                "from being re-registered: %s",
                                len(blocked),
                                domain,
                                [b.get("title") for b in blocked],
                            )
                        sync_result = ks.sync_scan_findings(
                            domain=domain,
                            scan_id=scan_id,
                            findings=filtered_findings,
                        )
                        logger.info(
                            "Synced %d new findings to report_status for %s",
                            sync_result.get("created", 0),
                            domain,
                        )
                    except Exception:
                        logger.exception("Failed to sync findings to report_status for %s", domain)
                else:
                    logger.debug("No findings to sync for %s", domain)
                logger.info(
                    "Recorded scan end in target profile for %s: %d findings, status=%s",
                    domain,
                    len(findings_list),
                    scan_status,
                )

                # Post-scan: detect knowledge entries that were never filed as findings
                try:
                    unfiled = ks.get_unfiled_vulnerabilities(domain)
                    if unfiled:
                        logger.warning(
                            "UNFILED KNOWLEDGE: %d vulnerability knowledge entries for %s "
                            "have no corresponding finding. These were discovered but never filed.",
                            len(unfiled),
                            domain,
                        )
                        for uf in unfiled[:10]:
                            logger.warning(
                                "  Unfiled: [%s] %s (scan: %s)",
                                uf.get("key", "?"),
                                str(uf.get("value", ""))[:120],
                                uf.get("scan_id", "?"),
                            )
                except Exception:
                    logger.exception("Unfiled vulnerability check failed for %s", domain)
        except Exception:
            logger.exception("Failed to record scan end in target profiles")

        logger.info("prometheus scan %s done", scan_id)
        write_status(scan_id, "scan_complete", {"status": "completed"})
        teardown_logging()


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Child agent wait helper — prevents premature session teardown
# ---------------------------------------------------------------------------

_CHILD_DRAIN_TIMEOUT = 300  # seconds to wait for children to finish
_CHILD_DRAIN_POLL = 5  # seconds between status checks


async def _wait_for_children(
    coordinator: AgentCoordinator,
    root_id: str,
) -> None:
    """Wait for all child agents to reach a terminal state.

    After the root agent stops (naturally or via error), child agents may
    still be running.  If we tear down the sandbox and close SQLite sessions
    before children finish, their findings are lost (SQLiteSession is closed
    mid-write).  This function polls child statuses until every child is in a
    terminal state or the timeout expires.
    """
    # Collect child IDs
    async with coordinator._lock:
        child_ids = [aid for aid, parent in coordinator.parent_of.items() if parent == root_id]

    if not child_ids:
        return

    logger.info(
        "Waiting for %d child agent(s) to finish (timeout=%ds)...",
        len(child_ids),
        _CHILD_DRAIN_TIMEOUT,
    )

    deadline = time.monotonic() + _CHILD_DRAIN_TIMEOUT
    terminal = {"completed", "failed", "crashed", "stopped"}
    still_running: list[str] = []

    while time.monotonic() < deadline:
        async with coordinator._lock:
            still_running = [
                aid for aid in child_ids if coordinator.statuses.get(aid) not in terminal
            ]
        if not still_running:
            logger.info("All %d child agent(s) finished.", len(child_ids))
            return
        logger.debug(
            "%d/%d children still running: %s",
            len(still_running),
            len(child_ids),
            ", ".join(still_running),
        )
        await asyncio.sleep(_CHILD_DRAIN_POLL)

    # Timeout: gracefully stop any remaining children so their sessions
    # can be closed cleanly.
    logger.warning(
        "Child drain timeout after %ds — %d child(ren) still running: %s. "
        "Requesting graceful stop.",
        _CHILD_DRAIN_TIMEOUT,
        len(still_running),
        ", ".join(still_running),
    )
    try:
        await coordinator.cancel_descendants_graceful(root_id)
        # Give them a few more seconds to wrap up
        await asyncio.sleep(10)
    except Exception:
        logger.debug("Graceful stop during drain failed (non-fatal)", exc_info=True)


# ---------------------------------------------------------------------------
# Threat intel helpers (used by the pre-scan injection above)
# ---------------------------------------------------------------------------


def _build_threat_fingerprints(scan_config: dict[str, Any]) -> list[dict[str, str]]:
    """Extract technology fingerprints from scan_config for threat intel lookup.
    Looks at targets for hints about the technology stack being scanned.
    """
    fingerprints: list[dict[str, str]] = []
    seen: set[str] = set()

    # Extract from targets — look for technology hints in URL patterns
    targets = scan_config.get("targets") or []
    for target in targets:
        original = target.get("original") or target.get("value") or ""
        if not original:
            continue

        # Check for tech hints in scan_config
        tech_hints = scan_config.get("tech_stack") or []
        for hint in tech_hints:
            tech = hint.get("technology", "").strip()
            version = hint.get("version", "").strip()
            key = f"{tech}@{version}".lower()
            if tech and key not in seen:
                seen.add(key)
                fingerprints.append({"technology": tech, "version": version})

    return fingerprints


# ---------------------------------------------------------------------------
# Phase 3D: LLM budget preflight
# ---------------------------------------------------------------------------

# Headroom in tokens. If the account is below this, refuse to launch.
# 50K tokens ≈ 1 small scan; tuned so an out-of-credits account fails
# the preflight before spinning up a sandbox.
_LLM_BUDGET_MIN_HEADROOM_TOKENS = 50_000


async def _check_llm_budget(scan_id: str) -> tuple[bool, str]:
    """Best-effort credits check. Returns ``(ok, message)``.

    Implementation: try ``client.models.list()`` and look at the
    response. Most providers expose credit / quota information via
    either an HTTP header (``x-ratelimit-remaining-tokens``) or a
    response body field. We accept any of: (a) ``x-ratelimit-remaining-tokens``
    header below the headroom floor, (b) a 402/429 status code, or
    (c) a body field that explicitly says out of credits.

    Anything we can't parse → assume "OK" — better to launch and fail
    at the SDK layer than to false-positive at preflight.
    """
    try:
        from prometheus.config import load_settings

        settings = load_settings()
        provider_name = (settings.llm.provider or "").lower()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Budget preflight: settings load failed (%s); skipping", exc)
        return True, "settings load failed; skipping preflight"

    if not provider_name:
        return True, "no provider configured; skipping preflight"

    try:
        import httpx
        from prometheus.config.llm_config import _PROVIDER_ENV_KEY_MAP

        api_key_env = _PROVIDER_ENV_KEY_MAP.get(provider_name)
        if not api_key_env:
            return True, f"no API key env mapping for provider '{provider_name}'"
        import os

        api_key = os.environ.get(api_key_env)
        if not api_key:
            return True, f"no API key in env {api_key_env}; skipping preflight"
        api_base = (settings.llm.api_base or "https://api.openai.com/v1").rstrip("/")
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{api_base}/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
        if resp.status_code in (402, 429):
            return False, f"provider {provider_name} returned {resp.status_code}: {resp.text[:200]}"
        # Some providers return remaining-tokens in headers.
        remaining = resp.headers.get("x-ratelimit-remaining-tokens")
        if remaining is not None:
            try:
                if int(remaining) < _LLM_BUDGET_MIN_HEADROOM_TOKENS:
                    return False, (
                        f"provider {provider_name} reports only {remaining} tokens of headroom "
                        f"(min={_LLM_BUDGET_MIN_HEADROOM_TOKENS})"
                    )
            except (TypeError, ValueError):
                pass
        return True, "preflight OK"
    except Exception as exc:  # noqa: BLE001
        # Best-effort: never block a scan on a failed preflight.
        logger.debug("Budget preflight check raised (non-fatal): %s", exc)
        return True, f"preflight check raised: {exc}"


def _format_threat_intel_context(result: dict[str, Any]) -> str:
    """Format threat intel query results for injection into agent context."""
    lines: list[str] = []
    lines.append(
        f"Total: {result.get('total_vulnerabilities', 0)} vulnerabilities "
        f"across {result.get('technologies_queried', 0)} technologies"
    )
    if result.get("cisa_kev_matches_total"):
        lines.append(f"CISA KEV matches: {result['cisa_kev_matches_total']}")
    lines.append("")

    for tech_result in result.get("results", []):
        tech = tech_result.get("technology", "?")
        version = tech_result.get("version", "?")
        vulns = tech_result.get("vulnerabilities", [])
        if not vulns:
            continue

        # SCA confidence indicator
        sca_conf = tech_result.get("sca_confidence", "unknown")
        conf_tag = ""
        if sca_conf == "low":
            conf_tag = " [SCA: LOW CONFIDENCE — no ecosystem match, keyword-only]"
        elif sca_conf == "mixed":
            conf_tag = " [SCA: MIXED — some version ranges unconfirmed]"
        elif sca_conf == "medium":
            conf_tag = " [SCA: MEDIUM — version ranges not all confirmed]"

        lines.append(f"=== {tech} {version} ({len(vulns)} CVEs){conf_tag} ===")

        # SCA confidence warnings for this technology
        if sca_conf == "low":
            lines.append(
                "  ** VERSION MATCHING UNCONFIRMED - manually verify this technology/version against NVD **"
            )
        elif sca_conf in ("medium", "mixed"):
            lines.append("  Version range not confirmed - test regardless")

        for v in vulns[:15]:  # Cap per-tech to avoid context bloat
            cve_id = v.get("cve_id", "?")
            severity = v.get("severity", "?")
            cvss = v.get("cvss_score", 0)
            score = v.get("priority_score", 0)
            kev = " [CISA-KEV]" if v.get("cisa_kev") or v.get("in_cisa_kev") else ""
            exploit = " [EXPLOIT]" if v.get("has_exploit") else ""

            # Per-vulnerability SCA confidence
            vuln_sca = v.get("sca_confidence", "")
            if vuln_sca == "low":
                sca_tag = " [SCA-LOW]"
            elif vuln_sca == "high":
                sca_tag = ""  # don't clutter high-confidence results
            else:
                sca_tag = ""

            desc = (v.get("description") or "")[:80]
            lines.append(
                f"  [{severity} CVSS:{cvss} Score:{score}] {cve_id}{kev}{exploit}{sca_tag} — {desc}"
            )
        if len(vulns) > 15:
            lines.append(f"  ... and {len(vulns) - 15} more")
        lines.append("")

    return "\n".join(lines)
