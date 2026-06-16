"""Panels for automated scan management and program tracking in the prometheus TUI.

Provides:
- ProgramsPanel: Bug bounty program details (HackerOne/Bugcrowd), scope,
  rewards, automated scan configuration per program.
- AutomatedScansPanel: Shows running/completed automated scans with
  real-time output.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Static


if TYPE_CHECKING:
    from textual.app import ComposeResult


logger = logging.getLogger(__name__)

STATUS_COLORS = {
    "starting": "#d97706",
    "running": "#3b82f6",
    "completed": "#22c55e",
    "failed": "#dc2626",
    "stopped": "#6b7280",
    "paused": "#d97706",
    "active": "#22c55e",
}

PLATFORM_COLORS = {
    "hackerone": "#494649",
    "bugcrowd": "#f26822",
    "intigriti": "#1b8189",
}

# Default programs file location
PROGRAMS_FILE = Path.home() / ".prometheus" / "programs.json"


def _load_programs() -> list[dict[str, Any]]:
    """Load programs from the JSON file."""
    if not PROGRAMS_FILE.exists():
        return []
    try:
        with PROGRAMS_FILE.open(encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_programs(programs: list[dict[str, Any]]) -> None:
    """Save programs to the JSON file."""
    PROGRAMS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with PROGRAMS_FILE.open("w", encoding="utf-8") as f:
        json.dump(programs, f, indent=2, ensure_ascii=False)


class ProgramsPanel(VerticalScroll):
    """Bug bounty program tracker with automated scan configuration.

    Shows all registered programs from HackerOne/Bugcrowd with:
    - Program details (name, platform, domain, scope)
    - Reward ranges (bounty min/max)
    - Automated scan status (interval, last scan, next scan)
    - Ability to launch/stop automated scans per program
    """

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("a", "add_program", "Add Program"),
        ("s", "toggle_scan", "Toggle Scan"),
    ]

    def compose(self) -> ComposeResult:
        yield Vertical(
            Horizontal(
                Button("Refresh", id="programs_refresh_btn", variant="default"),
                Static("", id="programs_summary"),
                id="programs_toolbar",
            ),
            VerticalScroll(id="programs_list"),
            id="programs_content",
        )

    def on_mount(self) -> None:
        self._load_programs()

    def _load_programs(self) -> None:
        """Load all registered programs."""
        try:
            programs = _load_programs()

            # Enrich with scan scheduler info
            try:
                from prometheus.core.scheduler import ScanScheduler
                from prometheus.core.target_registry import TargetRegistry

                scheduler = ScanScheduler()
                registry = TargetRegistry()
                schedule_info = scheduler.get_schedule_info()
                schedule_map = {s["target_id"]: s for s in schedule_info}

                # Match programs to registered targets
                targets = registry.list_targets(status="active")
                target_map = {}
                for t in targets:
                    domain = t.get("domain", "")
                    target_map[domain] = t
            except Exception:
                schedule_map = {}
                target_map = {}

            self._render_programs(programs, schedule_map, target_map)
        except Exception as exc:
            logger.exception("Failed to load programs")
            try:
                summary = self.query_one("#programs_summary", Static)
                summary.update(f"[red]Error: {exc}[/red]")
            except Exception:
                logger.debug("could not update programs_summary widget", exc_info=True)

    def _render_programs(
        self,
        programs: list[dict[str, Any]],
        schedule_map: dict[str, dict[str, Any]],
        target_map: dict[str, dict[str, Any]],
    ) -> None:
        """Render all program cards."""
        try:
            summary = self.query_one("#programs_summary", Static)
            programs_list = self.query_one("#programs_list", VerticalScroll)
        except Exception:
            return

        # Clear
        for child in list(programs_list.children):
            child.remove()

        if not programs:
            summary.update("No programs registered")
            no_programs = Static(
                "[dim]No bug bounty programs tracked yet.\n"
                "Press 'a' to add a program or edit ~/.prometheus/programs.json[/dim]"
            )
            programs_list.mount(no_programs)
            return

        # Count by platform
        h1_count = sum(1 for p in programs if p.get("platform") == "hackerone")
        bc_count = sum(1 for p in programs if p.get("platform") == "bugcrowd")

        summary.update(
            f"Programs: [bold]{len(programs)}[/bold]  |  "
            f"H1: {h1_count}  |  BC: {bc_count}  |  "
            f"Auto-scan: [red]DISABLED[/red]"
        )

        for program in programs:
            domain = program.get("domain", "")
            target_data = target_map.get(domain, {})
            sched_data = schedule_map.get(target_data.get("id", ""), {})
            self._render_program_card(program, sched_data, programs_list)

    def _render_program_card(
        self,
        program: dict[str, Any],
        sched_data: dict[str, Any],
        container: VerticalScroll,
    ) -> None:
        """Render a single program card."""
        name = program.get("name", "Unknown")
        platform = program.get("platform", "unknown")
        domain = program.get("domain", "")
        handle = program.get("handle", "")
        url = program.get("url", "")
        scope = program.get("scope", [])
        rewards = program.get("rewards", {})
        auto_scan = program.get("auto_scan_enabled", False)
        instructions = program.get("instructions", "")
        notes = program.get("notes", "")

        # Platform badge
        platform_color = PLATFORM_COLORS.get(platform, "#737373")
        platform_badge = f"[{platform_color}]{platform.upper()}[/{platform_color}]"

        # Auto-scan badge
        auto_badge = "[red]AUTO-SCAN DISABLED[/red]" if auto_scan else "[dim]auto-scan off[/dim]"

        # Schedule info from scheduler
        interval = sched_data.get("interval_hours", 24)
        next_scan = sched_data.get("next_scan_at", "")
        paused = sched_data.get("paused", False)
        had_vulns = sched_data.get("had_vulns", False)

        pause_badge = " [yellow]PAUSED[/yellow]" if paused else ""
        vuln_badge = " [red]HAD VULNS[/red]" if had_vulns else ""

        # Format next scan
        next_display = "Not scheduled"
        if next_scan:
            try:
                dt = datetime.fromisoformat(next_scan)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                now = datetime.now(UTC)
                delta_hours = (dt - now).total_seconds() / 3600
                if delta_hours <= 0:
                    next_display = "[yellow]DUE NOW[/yellow]"
                else:
                    next_display = f"in {delta_hours:.1f}h"
            except (ValueError, TypeError):
                next_display = str(next_scan)

        # Build card
        card_lines = [
            f"[bold]{name}[/bold]  {platform_badge}  {auto_badge}{pause_badge}{vuln_badge}",
        ]

        if domain:
            card_lines.append(f"  Domain: {domain}")
        if handle:
            card_lines.append(f"  Handle: {handle}")
        if url:
            card_lines.append(f"  URL: {url}")

        # Rewards
        if rewards:
            min_bounty = rewards.get("min", "")
            max_bounty = rewards.get("max", "")
            currency = rewards.get("currency", "USD")
            if min_bounty or max_bounty:
                card_lines.append(f"  Bounty: {min_bounty} - {max_bounty} {currency}")

        # Scope summary
        if scope:
            card_lines.append(f"  Scope: {len(scope)} target(s)")
            for s in scope[:5]:
                if isinstance(s, dict):
                    stype = s.get("type", "url")
                    val = s.get("value", s.get("asset_identifier", "?"))
                    card_lines.append(f"    - {val} ({stype})")
                else:
                    card_lines.append(f"    - {s}")
            if len(scope) > 5:
                card_lines.append(f"    ... and {len(scope) - 5} more")

        # Scan config
        if auto_scan:
            card_lines.append("")
            card_lines.append(f"  Mode: deep  |  Interval: {interval}h")
            card_lines.append(f"  Next scan: {next_display}")
            if instructions:
                instr_preview = instructions[:100]
                if len(instructions) > 100:
                    instr_preview += "..."
                card_lines.append(f"  Instructions: {instr_preview}")

        if notes:
            card_lines.append(f"  Notes: {notes[:80]}")

        card = Static("\n".join(card_lines))
        card.styles.margin = (0, 0, 1, 2)
        container.mount(card)

    def action_refresh(self) -> None:
        self._load_programs()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "programs_refresh_btn":
            self._load_programs()

    def action_add_program(self) -> None:
        """Open add program dialog. For now, notify user to edit JSON."""
        self.app.notify(
            f"Edit {PROGRAMS_FILE} to add programs. See format in the existing entries.",
            severity="information",
        )

    def action_toggle_scan(self) -> None:
        """Toggle auto-scan on the selected program."""
        self.app.notify(
            "Program selection not yet implemented. "
            "Edit programs.json directly to toggle auto_scan_enabled.",
            severity="warning",
        )


class TargetsPanel(VerticalScroll):
    """Full target and program management panel.

    Shows all registered targets with:
    - Program details (display name, platform, domain)
    - In-scope targets list
    - Scan config (mode, instructions, headers)
    - Schedule config (interval, next scan, pause state)
    - Scan history (last N scans with findings counts)
    """

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("p", "toggle_pause", "Pause/Resume"),
    ]

    def compose(self) -> ComposeResult:
        yield Vertical(
            Horizontal(
                Button("Refresh", id="targets_refresh_btn", variant="default"),
                Static("", id="targets_summary"),
                id="targets_toolbar",
            ),
            VerticalScroll(id="targets_list"),
            id="targets_content",
        )

    def on_mount(self) -> None:
        self._load_targets()

    def _load_targets(self) -> None:
        """Load all targets from registry + scheduler info."""
        try:
            from prometheus.core.scan_persistence import ScanPersistence
            from prometheus.core.scheduler import ScanScheduler
            from prometheus.core.target_registry import TargetRegistry

            registry = TargetRegistry()
            scheduler = ScanScheduler()
            persistence = ScanPersistence()

            targets = registry.list_targets(status="active")
            schedule_info = scheduler.get_schedule_info()
            schedule_map = {s["target_id"]: s for s in schedule_info}

            # Get scan history per target
            history_map: dict[str, list[dict[str, Any]]] = {}
            try:
                with persistence._lock:
                    rows = persistence._conn.execute(
                        """
                        SELECT target_id, scan_id, status, started_at,
                               ended_at, findings_count
                        FROM scans
                        ORDER BY started_at DESC
                        """
                    ).fetchall()
                for row in rows:
                    tid = row["target_id"]
                    if tid not in history_map:
                        history_map[tid] = []
                    if len(history_map[tid]) < 10:
                        history_map[tid].append(dict(row))
            except Exception:
                logger.debug("history rows fetch failed, ignoring", exc_info=True)

            self._render_targets(targets, schedule_map, history_map, scheduler)
        except Exception as exc:
            logger.exception("Failed to load targets")
            try:
                summary = self.query_one("#targets_summary", Static)
                summary.update(f"[red]Error: {exc}[/red]")
            except Exception:
                logger.debug("could not update targets_summary widget", exc_info=True)

    def _render_targets(
        self,
        targets: list[dict[str, Any]],
        schedule_map: dict[str, dict[str, Any]],
        history_map: dict[str, list[dict[str, Any]]],
        scheduler: Any,
    ) -> None:
        """Render all target cards."""
        try:
            summary = self.query_one("#targets_summary", Static)
            target_list = self.query_one("#targets_list", VerticalScroll)
        except Exception:
            return

        sched_status = "[red]DISABLED[/red]"
        summary.update(f"Auto-scan: {sched_status}  |  Targets: {len(targets)}")

        # Clear
        for child in list(target_list.children):
            child.remove()

        if not targets:
            target_list.mount(Static("[dim]No active targets registered[/dim]"))
            return

        for target in targets:
            self._render_single_target(target, schedule_map, history_map, target_list)

    def _render_single_target(
        self,
        target: dict[str, Any],
        schedule_map: dict[str, dict[str, Any]],
        history_map: dict[str, list[dict[str, Any]]],
        container: VerticalScroll,
    ) -> None:
        """Render one target as a collapsible card."""
        tid = target["id"]
        domain = target.get("domain", "?")
        target_type = target.get("target_type", "url")
        target_config = target.get("target_config") or {}
        scan_config = target.get("scan_config") or {}

        display_name = target_config.get("display_name", domain)

        # Schedule info (auto-scans disabled, but badges still shown)
        sched_info = schedule_map.get(tid, {})
        paused = sched_info.get("paused", False)
        had_vulns = sched_info.get("had_vulns", False)

        # Scan config
        instructions = scan_config.get("user_instructions", scan_config.get("instructions", ""))
        custom_headers = scan_config.get("custom_headers", [])
        targets_list = scan_config.get("targets", [])

        # Status badges
        pause_badge = " [yellow]PAUSED[/yellow]" if paused else ""
        vuln_badge = " [red]HAD VULNS[/red]" if had_vulns else ""

        # Build card
        card_lines = [
            f"[bold]{display_name}[/bold]{pause_badge}{vuln_badge}",
            f"  ID: {tid}  |  Type: {target_type}  |  Domain: {domain}",
            "",
            "[bold]Schedule:[/bold]",
            "  [red]Auto-scanning is disabled[/red]",
            "",
            "[bold]Scan Config:[/bold]",
            f"  Mode: deep  |  Headers: {len(custom_headers)} custom",
        ]

        # Show in-scope targets
        if targets_list:
            card_lines.append("")
            card_lines.append(f"[bold]In-Scope Targets ({len(targets_list)}):[/bold]")
            for t in targets_list[:10]:
                original = t.get("original", t.get("value", "?"))
                ttype = t.get("type", "?")
                card_lines.append(f"  - {original} ({ttype})")
            if len(targets_list) > 10:
                card_lines.append(f"  ... and {len(targets_list) - 10} more")

        # Show instructions (truncated)
        if instructions:
            card_lines.append("")
            card_lines.append("[bold]Program Details:[/bold]")
            instr_lines = instructions.split("\n")
            for line in instr_lines[:15]:
                card_lines.append(f"  {line}")
            if len(instr_lines) > 15:
                card_lines.append(f"  ... ({len(instr_lines) - 15} more lines)")

        # Show scan history
        history = history_map.get(tid, [])
        if history:
            card_lines.append("")
            card_lines.append(f"[bold]Scan History ({len(history)} recent):[/bold]")
            for h in history[:5]:
                h_status = h.get("status", "?")
                h_started = h.get("started_at", "?")
                h_findings = h.get("findings_count", 0)
                h_sid = h.get("scan_id", "?")[:12]

                if h_started and h_started != "?":
                    try:
                        dt = datetime.fromisoformat(h_started)
                        h_started = dt.strftime("%m-%d %H:%M")
                    except (ValueError, TypeError):
                        logger.debug(
                            "history_started %r not iso-parseable, ignoring",
                            h_started,
                            exc_info=True,
                        )

                color = STATUS_COLORS.get(h_status, "#6b7280")
                findings_str = (
                    f"[red]{h_findings} findings[/red]"
                    if h_findings > 0
                    else "[green]clean[/green]"
                )
                card_lines.append(
                    f"  [{color}]{h_status:<10}[/{color}] {h_started}  {h_sid}  {findings_str}"
                )

        card = Static("\n".join(card_lines))
        card.styles.margin = (0, 0, 1, 2)
        container.mount(card)

    def action_refresh(self) -> None:
        self._load_targets()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "targets_refresh_btn":
            self._load_targets()

    def action_toggle_pause(self) -> None:
        """Toggle pause on selected target."""
        self.app.notify(
            "Target selection not yet implemented. "
            "Use the Automated Scans tab to manage running scans.",
            severity="warning",
        )


class AutomatedScansPanel(VerticalScroll):
    """Shows all automated (scheduled) scans with real-time output."""

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("enter", "open_scan", "Open Scan"),
        ("s", "stop_scan", "Stop Scan"),
    ]

    _selected_scan_id: str | None = None

    def compose(self) -> ComposeResult:
        yield Vertical(
            Horizontal(
                Button("Refresh", id="auto_refresh_btn", variant="default"),
                Static("", id="auto_scan_count"),
                id="auto_toolbar",
            ),
            Horizontal(
                VerticalScroll(
                    Static("Loading...", id="auto_scan_list_placeholder"),
                    id="auto_scan_list",
                ),
                VerticalScroll(
                    Static("[dim]Select a scan to view details[/dim]", id="auto_scan_detail"),
                    id="auto_scan_detail_scroll",
                ),
                id="auto_scan_split",
            ),
            id="auto_content",
        )

    def on_mount(self) -> None:
        self._refresh_scans()
        self.set_interval(5.0, self._refresh_scans)

    def _refresh_scans(self) -> None:
        """Refresh the list of automated scans."""
        try:
            from prometheus.core.orchestrator import ScanOrchestrator
            from prometheus.core.scan_persistence import ScanPersistence

            orchestrator = ScanOrchestrator()
            persistence = ScanPersistence()

            active_scans = orchestrator.list_scans()

            with persistence._lock:
                rows = persistence._conn.execute(
                    """
                    SELECT scan_id, target_id, target_name, status, started_at,
                           ended_at, findings_count
                    FROM scans
                    ORDER BY started_at DESC
                    LIMIT 50
                    """
                ).fetchall()

            historical = [dict(row) for row in rows]
            self._render_scan_list(active_scans, historical)

            # Auto-refresh detail panel for running scans
            if self._selected_scan_id:
                self._show_scan_detail(self._selected_scan_id)
        except Exception as exc:
            logger.exception("Failed to refresh automated scans")
            try:
                placeholder = self.query_one("#auto_scan_list_placeholder", Static)
                placeholder.update(f"[red]Error: {exc}[/red]")
            except Exception:
                logger.debug("could not update auto_scan_list_placeholder widget", exc_info=True)

    def _render_scan_list(
        self,
        active: list[dict[str, Any]],
        historical: list[dict[str, Any]],
    ) -> None:
        """Render the scan list."""
        try:
            scan_list = self.query_one("#auto_scan_list", VerticalScroll)
            count_display = self.query_one("#auto_scan_count", Static)
        except Exception:
            return

        scan_list.remove_children()

        active_ids = {s["scan_id"] for s in active}
        all_scans = list(active)
        for h in historical:
            if h["scan_id"] not in active_ids:
                all_scans.append(h)

        if not all_scans:
            scan_list.mount(Static("[dim]No automated scans yet[/dim]"))
            count_display.update("")
            return

        running = sum(1 for s in active if s.get("status") in ("starting", "running"))
        total = len(all_scans)
        count_display.update(f"[green]{running} running[/green] / {total} total")

        for scan in all_scans:
            sid = scan["scan_id"]
            target = scan.get("target_name", scan.get("target_id", "?"))
            status = scan.get("status", "unknown")
            started = scan.get("started_at", "?")
            findings = scan.get("findings_count", 0)

            color = STATUS_COLORS.get(status, "#6b7280")

            if started and started != "?":
                try:
                    dt = datetime.fromisoformat(started)
                    started = dt.strftime("%Y-%m-%d %H:%M")
                except (ValueError, TypeError):
                    logger.debug("started %r not iso-parseable, ignoring", started, exc_info=True)

            is_selected = sid == self._selected_scan_id
            selected_mark = "[bold white]>[/bold white] " if is_selected else "  "

            findings_str = ""
            if findings > 0:
                findings_str = f"  [bold red]{findings} findings[/bold red]"
            elif status == "completed":
                findings_str = "  [dim green]clean[/dim green]"

            label = f"{selected_mark}[{color}]{status.upper()}[/{color}]  [bold]{target}[/bold]  [dim]{started}[/dim]{findings_str}"

            item = Static(label, id=f"scan_item_{sid}", classes="scan-item")
            item.can_focus = True
            try:
                scan_list.mount(item)
            except Exception:
                # DuplicateIds race: remove_children() is async and the old widget
                # may still be in the DOM. Remove it synchronously and retry.
                try:
                    existing = scan_list.query(f"#{item.id}")
                    for w in existing:
                        w._pruning = True
                        scan_list._nodes._nodes.remove(w)
                        scan_list._nodes._nodes_set.discard(w)
                        scan_list._nodes._nodes_by_id.pop(item.id, None)
                        scan_list._nodes._updates += 1
                except Exception:
                    logger.debug("scan_list node removal failed, ignoring", exc_info=True)
                scan_list.mount(item)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if btn_id == "auto_refresh_btn":
            self._refresh_scans()

    def on_click(self, event) -> None:
        """Handle clicks on scan list items."""
        widget = event.widget
        if widget is not None and widget.id and widget.id.startswith("scan_item_"):
            scan_id = widget.id.replace("scan_item_", "")
            self._selected_scan_id = scan_id
            self._show_scan_detail(scan_id)
            self._refresh_scans()

    def on_focus(self, event) -> None:
        """Handle keyboard focus on scan list items."""
        widget = event.control
        if widget is not None and widget.id and widget.id.startswith("scan_item_"):
            scan_id = widget.id.replace("scan_item_", "")
            self._selected_scan_id = scan_id
            self._show_scan_detail(scan_id)

    def _show_scan_detail(self, scan_id: str) -> None:
        """Show details for a specific scan."""
        try:
            detail = self.query_one("#auto_scan_detail", Static)
        except Exception:
            return

        try:
            from prometheus.core.orchestrator import ScanOrchestrator
            from prometheus.core.scan_persistence import ScanPersistence

            orchestrator = ScanOrchestrator()
            instance = orchestrator.get_scan(scan_id)

            if instance:
                status = instance.status
                findings = (
                    len(instance.report_state.vulnerability_reports) if instance.report_state else 0
                )
                error = instance.error or ""

                lines = [
                    f"[bold]Scan: {scan_id}[/bold]",
                    f"Target: {instance.target_name}",
                    f"Status: [{STATUS_COLORS.get(status, '#6b7280')}]{status.upper()}[/]",
                    f"Started: {instance.started_at}",
                    f"Findings: {findings}",
                ]
                if error:
                    lines.append(f"[red]Error: {error}[/red]")

                # Show vulnerability reports from in-memory state
                if instance.report_state and instance.report_state.vulnerability_reports:
                    lines.append("\n[bold]Vulnerability Reports:[/bold]")
                    for vuln in instance.report_state.vulnerability_reports:
                        vid = vuln.get("id", "?")
                        vtitle = vuln.get("title", "Unknown")
                        vsev = vuln.get("severity", "info")
                        vcolor = STATUS_COLORS.get(vsev, "#6b7280")
                        lines.append(
                            f"  [{vcolor}]{vid}[/{vcolor}]  {vtitle}  [{vcolor}]{vsev.upper()}[/{vcolor}]"
                        )

                if instance.live_view and instance.live_view.events:
                    lines.append("\n[bold]Recent Events:[/bold]")
                    for event in instance.live_view.events[-15:]:
                        etype = event.get("type", "?")
                        ts = event.get("timestamp", "")
                        agent = event.get("agent_id", "")[:8]
                        lines.append(f"  {ts} [{agent}] {etype}")

                detail.update("\n".join(lines))
            else:
                # Scan no longer in memory — load from persistence + disk
                persistence = ScanPersistence()
                scan_data = persistence.get_scan(scan_id)
                if not scan_data:
                    detail.update(f"[dim]Scan {scan_id} not found[/dim]")
                    return

                lines = [
                    f"[bold]Scan: {scan_id}[/bold]",
                    f"Target: {scan_data.get('target_name', '?')}",
                    f"Status: {scan_data.get('status', '?').upper()}",
                    f"Started: {scan_data.get('started_at', '?')}",
                    f"Ended: {scan_data.get('ended_at', '?')}",
                    f"Findings: {scan_data.get('findings_count', 0)}",
                ]

                # Load vulnerability reports from disk
                run_dir = scan_data.get("run_dir", "")
                if run_dir:
                    vulns_path = Path(run_dir) / "vulnerabilities.json"
                    if vulns_path.exists():
                        try:
                            import json as _json

                            vulns = _json.loads(vulns_path.read_text(encoding="utf-8"))
                            if vulns:
                                lines.append("\n[bold]Vulnerability Reports:[/bold]")
                                for vuln in vulns:
                                    if not isinstance(vuln, dict):
                                        continue
                                    vid = vuln.get("id", "?")
                                    vtitle = vuln.get("title", "Unknown")
                                    vsev = vuln.get("severity", "info")
                                    vcolor = STATUS_COLORS.get(vsev, "#6b7280")
                                    lines.append(
                                        f"  [{vcolor}]{vid}[/{vcolor}]  {vtitle}  [{vcolor}]{vsev.upper()}[/{vcolor}]"
                                    )
                        except Exception:
                            lines.append(
                                "  [dim]Could not load vulnerability reports from disk[/dim]"
                            )

                    # Also load executive report if available
                    exec_path = Path(run_dir) / "penetration_test_report.md"
                    if exec_path.exists():
                        try:
                            content = exec_path.read_text(encoding="utf-8")
                            preview = content[:500]
                            if len(content) > 500:
                                preview += "..."
                            lines.append(f"\n[bold]Executive Report:[/bold]\n{preview}")
                        except Exception:
                            logger.debug("executive report preview failed, ignoring", exc_info=True)

                detail.update("\n".join(lines))

        except Exception as exc:
            detail.update(f"[red]Error loading scan: {exc}[/red]")

    def action_refresh(self) -> None:
        self._refresh_scans()

    def action_open_scan(self) -> None:
        if self._selected_scan_id:
            self._show_scan_detail(self._selected_scan_id)

    def action_stop_scan(self) -> None:
        """Stop the selected scan."""
        if not self._selected_scan_id:
            return
        try:
            from prometheus.core.orchestrator import ScanOrchestrator

            orchestrator = ScanOrchestrator()
            stopped = orchestrator.stop_scan(self._selected_scan_id)
            if stopped:
                self.notify(f"Stop requested for {self._selected_scan_id}")
            else:
                self.notify("Scan not found or already stopped", severity="warning")
            self._refresh_scans()
        except Exception as exc:
            self.notify(f"Error stopping scan: {exc}", severity="error")
