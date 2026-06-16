import argparse
import asyncio
import atexit
import contextlib
import logging
import os
import signal
import sys
import threading
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar


if TYPE_CHECKING:
    from textual.timer import Timer

from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from rich.style import Style
from rich.text import Span, Text
from textual import events, on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static, TabbedContent, TabPane, TextArea, Tree
from textual.widgets.tree import TreeNode

from prometheus.config import load_settings
from prometheus.core.runner import run_prometheus_scan
from prometheus.interface.tui.automation_panels import AutomatedScansPanel, ProgramsPanel
from prometheus.interface.tui.findings_library import (
    FindingsLibraryPanel,
)  # codeql[py/unsafe-cyclic-import] : findings_library only imports app.prometheusTUIApp inside TYPE_CHECKING, so no runtime cycle
from prometheus.interface.tui.live_view import TuiLiveView
from prometheus.interface.tui.messages import send_user_message_to_agent
from prometheus.interface.tui.renderers import render_tool_widget
from prometheus.interface.tui.renderers.agent_message_renderer import AgentMessageRenderer
from prometheus.interface.tui.renderers.user_message_renderer import UserMessageRenderer
from prometheus.interface.tui.scan_launcher import ScanLauncherScreen
from prometheus.interface.tui.security_feeds_panel import SecurityFeedsPanel
from prometheus.interface.utils import build_tui_stats_text
from prometheus.report.state import ReportState, set_global_report_state
from prometheus.runtime import session_manager


logger = logging.getLogger(__name__)


def get_package_version() -> str:
    try:
        return pkg_version("prometheus-agent")
    except PackageNotFoundError:
        return "dev"


class ChatTextArea(TextArea):  # type: ignore[misc]
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._app_reference: prometheusTUIApp | None = None

    def set_app_reference(self, app: "prometheusTUIApp") -> None:
        self._app_reference = app

    def on_mount(self) -> None:
        self._update_height()

    def _on_key(self, event: events.Key) -> None:
        if event.key == "shift+enter":
            self.insert("\n")
            event.prevent_default()
            return

        if event.key == "enter" and self._app_reference:
            text_content = str(self.text)  # type: ignore[has-type]
            message = text_content.strip()
            if message:
                self.text = ""

                self._app_reference._send_user_message(message)

                event.prevent_default()
                return

        super()._on_key(event)

    @on(TextArea.Changed)  # type: ignore[misc]
    def _update_height(self, _event: TextArea.Changed | None = None) -> None:
        if not self.parent:
            return

        line_count = self.document.line_count
        target_lines = min(max(1, line_count), 8)

        new_height = target_lines + 2

        if self.parent.styles.height != new_height:
            self.parent.styles.height = new_height
            self.scroll_cursor_visible()


class SplashScreen(Static):  # type: ignore[misc]
    ALLOW_SELECT = False
    PRIMARY_GREEN = "#22c55e"
    BANNER = (
        " ██████╗ ██████╗  ██████╗ ███╗   ███╗███████╗████████╗██╗  ██╗███████╗██╗   ██╗███████╗\n"
        " ██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔════╝╚══██╔══╝██║  ██║██╔════╝██║   ██║██╔════╝\n"
        " ██████╔╝██████╔╝██║   ██║██╔████╔██║█████╗     ██║   ███████║█████╗  ██║   ██║███████╗\n"
        " ██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔══╝     ██║   ██╔══██║██╔══╝  ██║   ██║╚════██║\n"
        " ██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ██║  ██║███████╗╚██████╔╝███████║\n"
        " ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝"
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._animation_step = 0
        self._animation_timer: Timer | None = None
        self._panel_static: Static | None = None
        self._version = "dev"

    def compose(self) -> ComposeResult:
        self._version = get_package_version()
        self._animation_step = 0
        start_line = self._build_start_line_text(self._animation_step)
        panel = self._build_panel(start_line)

        panel_static = Static(panel, id="splash_content")
        self._panel_static = panel_static
        yield panel_static

    def on_mount(self) -> None:
        self._animation_timer = self.set_interval(0.05, self._animate_start_line)

    def on_unmount(self) -> None:
        if self._animation_timer is not None:
            self._animation_timer.stop()
            self._animation_timer = None

    def _animate_start_line(self) -> None:
        if not self._panel_static:
            return

        self._animation_step += 1
        start_line = self._build_start_line_text(self._animation_step)
        panel = self._build_panel(start_line)
        self._panel_static.update(panel)

    def _build_panel(self, start_line: Text) -> Panel:
        content_parts: list[Any] = [
            Align.center(Text(self.BANNER.strip("\n"), style=self.PRIMARY_GREEN, justify="center")),
            Align.center(Text(" ")),
            Align.center(self._build_welcome_text()),
            Align.center(self._build_version_text()),
            Align.center(self._build_tagline_text()),
            Align.center(Text(" ")),
            Align.center(start_line.copy()),
            Align.center(Text(" ")),
        ]

        # Show target and scan mode if available
        try:
            app = self.app
            args = getattr(app, "args", None)
            if args:
                target_infos = getattr(args, "targets_info", None) or []
                if target_infos:
                    target_names = [t.get("original", str(t)) for t in target_infos]
                    scan_text = Text()
                    scan_text.append("Target: ", style=Style(color="white", dim=True))
                    scan_text.append(
                        ", ".join(target_names[:3]),
                        style=Style(color="white", bold=True),
                    )
                    if len(target_names) > 3:
                        scan_text.append(
                            f" (+{len(target_names) - 3} more)", style=Style(color="#737373")
                        )
                    content_parts.append(Align.center(scan_text))
                    content_parts.append(Align.center(Text(" ")))
        except Exception:
            logger.debug("splash content build failed, ignoring", exc_info=True)

        content_parts.append(Align.center(self._build_url_text()))

        return Panel.fit(Group(*content_parts), border_style=self.PRIMARY_GREEN, padding=(1, 6))

    def _build_url_text(self) -> Text:
        return Text("Prometheus.ai", style=Style(color=self.PRIMARY_GREEN, bold=True))

    def _build_welcome_text(self) -> Text:
        text = Text("Welcome to ", style=Style(color="white", bold=True))
        text.append("Prometheus", style=Style(color=self.PRIMARY_GREEN, bold=True))
        text.append("!", style=Style(color="white", bold=True))
        return text

    def _build_version_text(self) -> Text:
        return Text(f"v{self._version}", style=Style(color="white", dim=True))

    def _build_tagline_text(self) -> Text:
        return Text("Open-source AI hackers for your apps", style=Style(color="white", dim=True))

    def _build_start_line_text(self, phase: int) -> Text:
        full_text = "Starting Prometheus Agent"
        text_len = len(full_text)

        shine_pos = phase % (text_len + 8)

        text = Text()
        for i, char in enumerate(full_text):
            dist = abs(i - shine_pos)

            if dist <= 1:
                style = Style(color="bright_white", bold=True)
            elif dist <= 3:
                style = Style(color="white", bold=True)
            elif dist <= 5:
                style = Style(color="#a3a3a3")
            else:
                style = Style(color="#525252")

            text.append(char, style=style)

        return text


class HelpScreen(ModalScreen):  # type: ignore[misc]
    def compose(self) -> ComposeResult:
        yield Grid(
            Label("Prometheus Help", id="help_title"),
            Label(
                "F1        Help\nF2        Cycle Tabs (Manual/Auto/Programs/Reports/Feeds)\nCtrl+Q/C  Quit\nESC       Stop Agent\n"
                "Enter     Send message to agent\nTab       Switch panels\n↑/↓       Navigate tree",
                id="help_content",
            ),
            id="dialog",
        )

    def on_key(self, _event: events.Key) -> None:
        self.app.pop_screen()


class StopAgentScreen(ModalScreen):  # type: ignore[misc]
    def __init__(self, agent_name: str, agent_id: str):
        super().__init__()
        self.agent_name = agent_name
        self.agent_id = agent_id

    def compose(self) -> ComposeResult:
        yield Grid(
            Label(f"🛑 Stop '{self.agent_name}'?", id="stop_agent_title"),
            Grid(
                Button("Yes", variant="error", id="stop_agent"),
                Button("No", variant="default", id="cancel_stop"),
                id="stop_agent_buttons",
            ),
            id="stop_agent_dialog",
        )

    def on_mount(self) -> None:
        cancel_button = self.query_one("#cancel_stop", Button)
        cancel_button.focus()

    def on_key(self, event: events.Key) -> None:
        if event.key in ("left", "right", "up", "down"):
            focused = self.focused

            if focused and focused.id == "stop_agent":
                cancel_button = self.query_one("#cancel_stop", Button)
                cancel_button.focus()
            else:
                stop_button = self.query_one("#stop_agent", Button)
                stop_button.focus()

            event.prevent_default()
        elif event.key == "enter":
            focused = self.focused
            if focused and isinstance(focused, Button):
                focused.press()
            event.prevent_default()
        elif event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.app.pop_screen()
        if event.button.id == "stop_agent":
            self.app.action_confirm_stop_agent(self.agent_id)


class VulnerabilityDetailScreen(ModalScreen):  # type: ignore[misc]
    SEVERITY_COLORS: ClassVar[dict[str, str]] = {
        "critical": "#dc2626",  # Red
        "high": "#ea580c",  # Orange
        "medium": "#d97706",  # Amber
        "low": "#22c55e",  # Green
        "info": "#3b82f6",  # Blue
    }

    FIELD_STYLE: ClassVar[str] = "bold #4ade80"

    def __init__(self, vulnerability: dict[str, Any]) -> None:
        super().__init__()
        self.vulnerability = vulnerability

    def compose(self) -> ComposeResult:
        content = self._render_vulnerability()
        yield Grid(
            VerticalScroll(Static(content, id="vuln_detail_content"), id="vuln_detail_scroll"),
            Horizontal(
                Button("Copy", variant="default", id="copy_vuln_detail"),
                Button("Done", variant="default", id="close_vuln_detail"),
                id="vuln_detail_buttons",
            ),
            id="vuln_detail_dialog",
        )

    def on_mount(self) -> None:
        close_button = self.query_one("#close_vuln_detail", Button)
        close_button.focus()

    def _get_cvss_color(self, cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "#dc2626"
        if cvss_score >= 7.0:
            return "#ea580c"
        if cvss_score >= 4.0:
            return "#d97706"
        if cvss_score >= 0.1:
            return "#65a30d"
        return "#6b7280"

    def _highlight_python(self, code: str) -> Text:
        try:
            from pygments.lexers import PythonLexer
            from pygments.styles import get_style_by_name

            lexer = PythonLexer()
            style = get_style_by_name("native")
            colors = {
                token: f"#{style_def['color']}" for token, style_def in style if style_def["color"]
            }

            text = Text()
            for token_type, token_value in lexer.get_tokens(code):
                if not token_value:
                    continue
                color = None
                tt = token_type
                while tt:
                    if tt in colors:
                        color = colors[tt]
                        break
                    tt = tt.parent
                text.append(token_value, style=color)
        except (ImportError, KeyError, AttributeError):
            return Text(code)
        else:
            return text

    def _render_vulnerability(self) -> Text:
        vuln = self.vulnerability
        text = Text()

        text.append("🐞 ")
        text.append("Vulnerability Report", style="bold #ea580c")

        agent_name = vuln.get("agent_name", "")
        if agent_name:
            text.append("\n\n")
            text.append("Agent: ", style=self.FIELD_STYLE)
            text.append(agent_name)

        title = vuln.get("title", "")
        if title:
            text.append("\n\n")
            text.append("Title: ", style=self.FIELD_STYLE)
            text.append(title)

        severity = vuln.get("severity", "")
        if severity:
            text.append("\n\n")
            text.append("Severity: ", style=self.FIELD_STYLE)
            severity_color = self.SEVERITY_COLORS.get(severity.lower(), "#6b7280")
            text.append(severity.upper(), style=f"bold {severity_color}")

        cvss_score = vuln.get("cvss")
        if cvss_score is not None:
            text.append("\n\n")
            text.append("CVSS Score: ", style=self.FIELD_STYLE)
            cvss_color = self._get_cvss_color(float(cvss_score))
            text.append(str(cvss_score), style=f"bold {cvss_color}")

        target = vuln.get("target", "")
        if target:
            text.append("\n\n")
            text.append("Target: ", style=self.FIELD_STYLE)
            text.append(target)

        endpoint = vuln.get("endpoint", "")
        if endpoint:
            text.append("\n\n")
            text.append("Endpoint: ", style=self.FIELD_STYLE)
            text.append(endpoint)

        method = vuln.get("method", "")
        if method:
            text.append("\n\n")
            text.append("Method: ", style=self.FIELD_STYLE)
            text.append(method)

        cve = vuln.get("cve", "")
        if cve:
            text.append("\n\n")
            text.append("CVE: ", style=self.FIELD_STYLE)
            text.append(cve)

        cvss_breakdown = vuln.get("cvss_breakdown", {})
        if cvss_breakdown:
            cvss_parts = []
            if cvss_breakdown.get("attack_vector"):
                cvss_parts.append(f"AV:{cvss_breakdown['attack_vector']}")
            if cvss_breakdown.get("attack_complexity"):
                cvss_parts.append(f"AC:{cvss_breakdown['attack_complexity']}")
            if cvss_breakdown.get("privileges_required"):
                cvss_parts.append(f"PR:{cvss_breakdown['privileges_required']}")
            if cvss_breakdown.get("user_interaction"):
                cvss_parts.append(f"UI:{cvss_breakdown['user_interaction']}")
            if cvss_breakdown.get("scope"):
                cvss_parts.append(f"S:{cvss_breakdown['scope']}")
            if cvss_breakdown.get("confidentiality"):
                cvss_parts.append(f"C:{cvss_breakdown['confidentiality']}")
            if cvss_breakdown.get("integrity"):
                cvss_parts.append(f"I:{cvss_breakdown['integrity']}")
            if cvss_breakdown.get("availability"):
                cvss_parts.append(f"A:{cvss_breakdown['availability']}")
            if cvss_parts:
                text.append("\n\n")
                text.append("CVSS Vector: ", style=self.FIELD_STYLE)
                text.append("/".join(cvss_parts), style="dim")

        description = vuln.get("description", "")
        if description:
            text.append("\n\n")
            text.append("Description", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(description)

        impact = vuln.get("impact", "")
        if impact:
            text.append("\n\n")
            text.append("Impact", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(impact)

        technical_analysis = vuln.get("technical_analysis", "")
        if technical_analysis:
            text.append("\n\n")
            text.append("Technical Analysis", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(technical_analysis)

        poc_description = vuln.get("poc_description", "")
        if poc_description:
            text.append("\n\n")
            text.append("PoC Description", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(poc_description)

        poc_script_code = vuln.get("poc_script_code", "")
        if poc_script_code:
            text.append("\n\n")
            text.append("PoC Code", style=self.FIELD_STYLE)
            text.append("\n")
            text.append_text(self._highlight_python(poc_script_code))

        remediation_steps = vuln.get("remediation_steps", "")
        if remediation_steps:
            text.append("\n\n")
            text.append("Remediation", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(remediation_steps)

        return text

    def _get_markdown_report(self) -> str:
        """Get Markdown version of vulnerability report for clipboard."""
        vuln = self.vulnerability
        lines: list[str] = []

        title = vuln.get("title", "Untitled Vulnerability")
        lines.append(f"# {title}")
        lines.append("")

        if vuln.get("id"):
            lines.append(f"**ID:** {vuln['id']}")
        if vuln.get("severity"):
            lines.append(f"**Severity:** {vuln['severity'].upper()}")
        if vuln.get("timestamp"):
            lines.append(f"**Found:** {vuln['timestamp']}")
        if vuln.get("agent_name"):
            lines.append(f"**Agent:** {vuln['agent_name']}")
        if vuln.get("target"):
            lines.append(f"**Target:** {vuln['target']}")
        if vuln.get("endpoint"):
            lines.append(f"**Endpoint:** {vuln['endpoint']}")
        if vuln.get("method"):
            lines.append(f"**Method:** {vuln['method']}")
        if vuln.get("cve"):
            lines.append(f"**CVE:** {vuln['cve']}")
        if vuln.get("cvss") is not None:
            lines.append(f"**CVSS:** {vuln['cvss']}")

        cvss_breakdown = vuln.get("cvss_breakdown", {})
        if cvss_breakdown:
            abbrevs = {
                "attack_vector": "AV",
                "attack_complexity": "AC",
                "privileges_required": "PR",
                "user_interaction": "UI",
                "scope": "S",
                "confidentiality": "C",
                "integrity": "I",
                "availability": "A",
            }
            parts = [
                f"{abbrevs.get(k, k)}:{v}" for k, v in cvss_breakdown.items() if v and k in abbrevs
            ]
            if parts:
                lines.append(f"**CVSS Vector:** {'/'.join(parts)}")

        lines.append("")
        lines.append("## Description")
        lines.append("")
        lines.append(vuln.get("description") or "No description provided.")

        if vuln.get("impact"):
            lines.extend(["", "## Impact", "", vuln["impact"]])

        if vuln.get("technical_analysis"):
            lines.extend(["", "## Technical Analysis", "", vuln["technical_analysis"]])

        if vuln.get("poc_description") or vuln.get("poc_script_code"):
            lines.extend(["", "## Proof of Concept", ""])
            if vuln.get("poc_description"):
                lines.append(vuln["poc_description"])
                lines.append("")
            if vuln.get("poc_script_code"):
                lines.append("```python")
                lines.append(vuln["poc_script_code"])
                lines.append("```")

        if vuln.get("code_locations"):
            lines.extend(["", "## Code Analysis", ""])
            for i, loc in enumerate(vuln["code_locations"]):
                file_ref = loc.get("file", "unknown")
                line_ref = ""
                if loc.get("start_line") is not None:
                    if loc.get("end_line") and loc["end_line"] != loc["start_line"]:
                        line_ref = f" (lines {loc['start_line']}-{loc['end_line']})"
                    else:
                        line_ref = f" (line {loc['start_line']})"
                lines.append(f"**Location {i + 1}:** `{file_ref}`{line_ref}")
                if loc.get("label"):
                    lines.append(f"  {loc['label']}")
                if loc.get("snippet"):
                    lines.append(f"```\n{loc['snippet']}\n```")
                if loc.get("fix_before") or loc.get("fix_after"):
                    lines.append("**Suggested Fix:**")
                    lines.append("```diff")
                    if loc.get("fix_before"):
                        lines.extend(f"- {line}" for line in loc["fix_before"].splitlines())
                    if loc.get("fix_after"):
                        lines.extend(f"+ {line}" for line in loc["fix_after"].splitlines())
                    lines.append("```")
                lines.append("")

        if vuln.get("remediation_steps"):
            lines.extend(["", "## Remediation", "", vuln["remediation_steps"]])

        lines.append("")
        return "\n".join(lines)

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "copy_vuln_detail":
            markdown_text = self._get_markdown_report()
            self.app.copy_to_clipboard(markdown_text)

            copy_button = self.query_one("#copy_vuln_detail", Button)
            copy_button.label = "Copied!"
            self.set_timer(1.5, lambda: setattr(copy_button, "label", "Copy"))
        elif event.button.id == "close_vuln_detail":
            self.app.pop_screen()


class VulnerabilityItem(Static):  # type: ignore[misc]
    def __init__(self, label: Text, vuln_data: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(label, **kwargs)
        self.vuln_data = vuln_data

    def on_click(self, _event: events.Click) -> None:
        """Handle click to open vulnerability detail."""
        self.app.push_screen(VulnerabilityDetailScreen(self.vuln_data))


class VulnerabilitiesPanel(VerticalScroll):  # type: ignore[misc]
    SEVERITY_COLORS: ClassVar[dict[str, str]] = {
        "critical": "#dc2626",  # Red
        "high": "#ea580c",  # Orange
        "medium": "#d97706",  # Amber
        "low": "#22c55e",  # Green
        "info": "#3b82f6",  # Blue
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._vulnerabilities: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        return []

    def update_vulnerabilities(self, vulnerabilities: list[dict[str, Any]]) -> None:
        """Update the list of vulnerabilities and re-render."""
        if self._vulnerabilities == vulnerabilities:
            return
        self._vulnerabilities = list(vulnerabilities)
        self._render_panel()

    def _render_panel(self) -> None:
        """Render the vulnerabilities panel content."""
        for child in list(self.children):
            if isinstance(child, VulnerabilityItem):
                child.remove()

        if not self._vulnerabilities:
            return

        for vuln in self._vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            title = vuln.get("title", "Unknown Vulnerability")
            color = self.SEVERITY_COLORS.get(severity, "#3b82f6")

            label = Text()
            label.append("● ", style=Style(color=color))
            label.append(title, style=Style(color="#d4d4d4"))

            item = VulnerabilityItem(label, vuln, classes="vuln-item")
            self.mount(item)


class QuitScreen(ModalScreen):  # type: ignore[misc]
    def compose(self) -> ComposeResult:
        yield Grid(
            Label("Quit Prometheus?", id="quit_title"),
            Grid(
                Button("Yes", variant="error", id="quit"),
                Button("No", variant="default", id="cancel"),
                id="quit_buttons",
            ),
            id="quit_dialog",
        )

    def on_mount(self) -> None:
        cancel_button = self.query_one("#cancel", Button)
        cancel_button.focus()

    def on_key(self, event: events.Key) -> None:
        if event.key in ("left", "right", "up", "down"):
            focused = self.focused

            if focused and focused.id == "quit":
                cancel_button = self.query_one("#cancel", Button)
                cancel_button.focus()
            else:
                quit_button = self.query_one("#quit", Button)
                quit_button.focus()

            event.prevent_default()
        elif event.key == "enter":
            focused = self.focused
            if focused and isinstance(focused, Button):
                focused.press()
            event.prevent_default()
        elif event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit":
            self.app.action_custom_quit()
        else:
            self.app.pop_screen()


class prometheusTUIApp(App):  # type: ignore[misc]
    CSS_PATH = str(Path(__file__).resolve().parent.parent / "assets" / "tui_styles.tcss")
    ALLOW_SELECT = True

    SIDEBAR_MIN_WIDTH = 120

    selected_agent_id: reactive[str | None] = reactive(default=None)
    show_splash: reactive[bool] = reactive(default=True)
    active_tab: reactive[str] = reactive(
        default="manual"
    )  # "manual", "auto", "programs", "reports", "feeds"

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("f1", "toggle_help", "Help", priority=True),
        Binding("f2", "toggle_tab", "Cycle Tabs", priority=True),
        Binding("ctrl+q", "request_quit", "Quit", priority=True),
        Binding("ctrl+c", "request_quit", "Quit", priority=True),
        Binding("escape", "stop_selected_agent", "Stop Agent", priority=True),
        Binding("f3", "launch_scan", "Launch Scan", priority=True),
    ]

    def __init__(self, args: argparse.Namespace):
        super().__init__()
        self.args = args
        self.scan_config = self._build_scan_config(args)

        self.report_state = ReportState(self.scan_config["run_name"])
        self.report_state.hydrate_from_run_dir()
        self.report_state.set_scan_config(self.scan_config)
        self.report_state.save_run_data()
        set_global_report_state(self.report_state)
        self.live_view = TuiLiveView()
        self.live_view.hydrate_from_run_dir(self.report_state.get_run_dir())
        self._agent_graph_sync_future: Any | None = None

        from prometheus.core.agents import AgentCoordinator

        self.coordinator = AgentCoordinator()

        self.agent_nodes: dict[str, TreeNode] = {}

        self._displayed_agents: set[str] = set()
        self._displayed_events: list[str] = []

        self._scan_thread: threading.Thread | None = None
        self._scan_loop: asyncio.AbstractEventLoop | None = None
        self._scan_stop_event = threading.Event()
        self._scan_completed = threading.Event()
        self._scan_error: BaseException | None = None

        self._spinner_frame_index: int = 0
        self._sweep_num_squares: int = 6
        self._sweep_colors: list[str] = [
            "#000000",  # Dimmest (shows dot)
            "#031a09",
            "#052e16",
            "#0d4a2a",
            "#15803d",
            "#22c55e",
            "#4ade80",
            "#86efac",  # Brightest
        ]
        self._dot_animation_timer: Any | None = None

        self._reports_refresh_counter: int = 0
        self._reports_refresh_interval: int = 15  # refresh every ~5s (15 * 0.35s)
        self._reports_needs_refresh: bool = False

        self._setup_cleanup_handlers()

    def _build_scan_config(self, args: argparse.Namespace) -> dict[str, Any]:
        return {
            "scan_id": args.run_name,
            "targets": args.targets_info,
            "user_instructions": args.instruction or "",
            "run_name": args.run_name,
            "diff_scope": getattr(args, "diff_scope", {"active": False}),
            "non_interactive": bool(getattr(args, "non_interactive", False)),
            "local_sources": getattr(args, "local_sources", None) or [],
            "scope_mode": getattr(args, "scope_mode", "auto"),
            "diff_base": getattr(args, "diff_base", None),
            "resume_instruction": getattr(args, "user_explicit_instruction", None) or "",
            "allow_direct": bool(getattr(args, "allow_direct", False)),
        }

    def _setup_cleanup_handlers(self) -> None:
        def _cancel_agents() -> None:
            """Cancel all running agents before exit."""
            try:
                loop = getattr(self, "_scan_loop", None)
                if loop and not loop.is_closed():
                    root_ids = [
                        aid
                        for aid, st in self.coordinator.statuses.items()
                        if st == "running" and self.coordinator.parent_of.get(aid) is None
                    ]
                    for root_id in root_ids:
                        try:
                            future = asyncio.run_coroutine_threadsafe(
                                self.coordinator.cancel_descendants(root_id),
                                loop,
                            )
                            future.result(timeout=5)
                        except Exception:
                            logger.debug(
                                "cancel_descendants for %s failed, ignoring", root_id, exc_info=True
                            )
            except Exception:
                logger.debug("agent cancellation loop failed, ignoring", exc_info=True)

        def cleanup_on_exit() -> None:
            self._scan_stop_event.set()
            _cancel_agents()
            if self._scan_thread and self._scan_thread.is_alive():
                self._scan_thread.join(timeout=5)
            # Force-close the scan event loop to prevent deadlock during
            # interpreter finalization (daemon thread may still be running)
            loop = getattr(self, "_scan_loop", None)
            if loop and not loop.is_closed():
                try:
                    loop.call_soon_threadsafe(loop.stop)
                except Exception:
                    logger.debug(
                        "loop.call_soon_threadsafe(loop.stop) failed, ignoring", exc_info=True
                    )
                with contextlib.suppress(Exception):
                    loop.close()
            self.report_state.cleanup()
            # Kill orphaned sandbox containers
            try:
                import subprocess

                result = subprocess.run(
                    [
                        "docker",
                        "ps",
                        "--filter",
                        "ancestor=prometheus-sandbox:local",
                        "--format",
                        "{{.ID}}",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                container_ids = result.stdout.strip().split()
                if container_ids:
                    subprocess.run(
                        ["docker", "stop", *container_ids], capture_output=True, timeout=30
                    )
                    subprocess.run(
                        ["docker", "rm", *container_ids], capture_output=True, timeout=10
                    )
            except Exception:
                logger.debug("docker stop/rm of scan containers failed, ignoring", exc_info=True)

        def signal_handler(_signum: int, _frame: Any) -> None:
            self._scan_stop_event.set()
            _cancel_agents()
            self.report_state.cleanup(status="interrupted")
            sys.exit(0)

        atexit.register(cleanup_on_exit)
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, signal_handler)

    def compose(self) -> ComposeResult:
        if self.show_splash:
            yield SplashScreen(id="splash_screen")

    def watch_show_splash(self, show_splash: bool) -> None:
        if not show_splash and self.is_mounted:
            try:
                splash = self.query_one("#splash_screen")
                splash.remove()
            except ValueError:
                logger.debug("splash_screen already removed, ignoring", exc_info=True)

            main_container = Vertical(id="main_container")
            self.mount(main_container)

            # Tab 1: Manual Scans (existing chat + sidebar layout)
            chat_display = Static("", id="chat_display")
            chat_history = VerticalScroll(chat_display, id="chat_history")
            chat_history.can_focus = True

            status_text = Static("", id="status_text")
            status_text.ALLOW_SELECT = False
            keymap_indicator = Static("", id="keymap_indicator")
            keymap_indicator.ALLOW_SELECT = False

            agent_status_display = Horizontal(
                status_text, keymap_indicator, id="agent_status_display", classes="hidden"
            )

            chat_prompt = Static("> ", id="chat_prompt")
            chat_prompt.ALLOW_SELECT = False
            chat_input = ChatTextArea(
                "",
                id="chat_input",
                show_line_numbers=False,
            )
            chat_input.set_app_reference(self)
            chat_input_container = Horizontal(chat_prompt, chat_input, id="chat_input_container")

            agents_tree = Tree("Agents", id="agents_tree")
            agents_tree.root.expand()
            agents_tree.show_root = False

            agents_tree.show_guide = True
            agents_tree.guide_depth = 3
            agents_tree.guide_style = "dashed"

            stats_display = Static("", id="stats_display")
            stats_scroll = VerticalScroll(stats_display, id="stats_scroll")

            vulnerabilities_panel = VulnerabilitiesPanel(id="vulnerabilities_panel")

            sidebar = Vertical(agents_tree, vulnerabilities_panel, stats_scroll, id="sidebar")

            chat_area_container = Vertical(
                chat_history, agent_status_display, chat_input_container, id="chat_area_container"
            )
            scan_content = Horizontal(chat_area_container, sidebar, id="content_container")

            # Tab 2: Automated Scans
            auto_scans_content = AutomatedScansPanel(id="auto_scans_container")

            # Tab 3: Programs
            programs_content = ProgramsPanel(id="programs_container")

            # Tab 4: Reports
            reports_content = FindingsLibraryPanel(id="reports_container")

            # Tab 5: Security Feeds
            feeds_content = SecurityFeedsPanel(id="security_feeds_container")

            # Build TabbedContent with 5 tabs
            tabbed = TabbedContent(id="main_tabs")
            main_container.mount(tabbed)

            tabbed.add_pane(TabPane("Manual Scans", scan_content, id="tab_manual"))
            tabbed.add_pane(TabPane("Automated Scans", auto_scans_content, id="tab_auto"))
            tabbed.add_pane(TabPane("Programs", programs_content, id="tab_programs"))
            tabbed.add_pane(TabPane("Reports", reports_content, id="tab_reports"))
            tabbed.add_pane(TabPane("Security Feeds", feeds_content, id="tab_feeds"))

            self.call_after_refresh(self._focus_chat_input)

    def _focus_chat_input(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        try:
            chat_input = self.query_one("#chat_input", ChatTextArea)
            chat_input.show_vertical_scrollbar = False
            chat_input.show_horizontal_scrollbar = False
            chat_input.focus()
        except Exception:
            logger.debug("focus_chat_input failed, scheduling retry", exc_info=True)
            self.call_after_refresh(self._focus_chat_input)

    def _focus_agents_tree(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        try:
            agents_tree = self.query_one("#agents_tree", Tree)
            agents_tree.focus()

            if agents_tree.root.children:
                first_node = agents_tree.root.children[0]
                agents_tree.select_node(first_node)
        except Exception:
            logger.debug("focus_agents_tree failed, scheduling retry", exc_info=True)
            self.call_after_refresh(self._focus_agents_tree)

    def _switch_to_reports(self) -> None:
        """Switch to the Programs tab on startup (browse mode)."""
        try:
            tabbed = self.query_one("#main_tabs", TabbedContent)
            tabbed.active = "tab_programs"
            self.active_tab = "programs"
        except Exception:
            logger.debug("switch_to_reports failed, main_tabs not yet mounted", exc_info=True)

    def action_toggle_tab(self) -> None:
        """Cycle through tabs: Manual -> Auto -> Programs -> Reports -> Feeds -> Manual."""
        if self.show_splash or not self.is_mounted:
            return
        if len(self.screen_stack) > 1:
            return

        try:
            tabbed = self.query_one("#main_tabs", TabbedContent)
        except Exception:
            return

        tab_order = ["manual", "auto", "programs", "reports", "feeds"]
        tab_ids = ["tab_manual", "tab_auto", "tab_programs", "tab_reports", "tab_feeds"]

        try:
            current_idx = tab_order.index(self.active_tab)
        except ValueError:
            current_idx = 0

        next_idx = (current_idx + 1) % len(tab_order)
        self.active_tab = tab_order[next_idx]
        tabbed.active = tab_ids[next_idx]

        # Refresh reports when switching to it
        if self.active_tab == "reports":
            try:
                reports_container = self.query_one("#reports_container", FindingsLibraryPanel)
                reports_container.refresh_findings()
                reports_container.focus()
            except Exception:
                logger.debug("reports_container not yet mounted, skipping refresh", exc_info=True)
        elif self.active_tab == "manual":
            self._focus_chat_input()

    def on_mount(self) -> None:
        self.title = "Prometheus"

        self.set_timer(4.5, self._hide_splash_screen)

    def _hide_splash_screen(self) -> None:
        self.show_splash = False

        self._start_scan_thread()

        self.set_interval(0.35, self._update_ui)

    def action_launch_scan(self) -> None:
        """Open the scan launcher modal (F3)."""
        if self._scan_thread and self._scan_thread.is_alive():
            self.notify("Scan already running", severity="warning")
            return
        self.push_screen(ScanLauncherScreen(), self._on_scan_launcher_result)

    def _on_scan_launcher_result(self, result: dict[str, Any] | None) -> None:
        """Handle scan launcher result — update config and start scan."""
        if result is None:
            return

        self.notify("Preparing scan...", severity="information", timeout=5)

        from prometheus.core.rate_limiter import set_rate

        rate_limit = result.get("rate_limit", 5)
        if rate_limit > 0:
            set_rate(rate_limit)
        else:
            set_rate(0)

        from prometheus.interface.utils import (
            assign_workspace_subdirs,
            generate_run_name,
            infer_target_type,
            rewrite_localhost_targets,
        )

        target = result["target"]
        target_type, target_dict = infer_target_type(target)
        targets_info = [{"type": target_type, "details": target_dict, "original": target}]
        assign_workspace_subdirs(targets_info)
        rewrite_localhost_targets(targets_info, "host.docker.internal")
        run_name = generate_run_name(targets_info)

        self.scan_config = {
            "scan_id": run_name,
            "targets": targets_info,
            "user_instructions": result.get("instructions", ""),
            "run_name": run_name,
            "diff_scope": {"active": False},
            "non_interactive": False,
            "local_sources": [],
            "scope_mode": "auto",
            "diff_base": None,
            "resume_instruction": "",
        }

        self.report_state = ReportState(run_name)
        self.report_state.set_scan_config(self.scan_config)
        self.report_state.save_run_data()
        set_global_report_state(self.report_state)
        self.live_view = TuiLiveView()
        from prometheus.core.agents import AgentCoordinator

        self.coordinator = AgentCoordinator()
        self.agent_nodes = {}
        self._displayed_agents = set()
        self._displayed_events = []
        self.selected_agent_id = None

        self._start_scan_thread()
        self.notify("Scan started — agents are loading", severity="information", timeout=3)

    def _update_ui(self) -> None:
        if self.show_splash:
            return

        if len(self.screen_stack) > 1:
            return

        if not self.is_mounted:
            return

        try:
            chat_history = self.query_one("#chat_history", VerticalScroll)
            agents_tree = self.query_one("#agents_tree", Tree)

            if not self._is_widget_safe(chat_history) or not self._is_widget_safe(agents_tree):
                return
        except Exception:
            return

        self._sync_agent_graph()

        for agent_id, agent_data in list(self.live_view.agents.items()):
            if agent_id not in self._displayed_agents:
                self._add_agent_node(agent_data)
                self._displayed_agents.add(agent_id)
            else:
                self._update_agent_node(agent_id, agent_data)

        self._update_chat_view()

        self._update_agent_status_display()

        self._update_stats_display()

        self._update_vulnerabilities_panel()
        self._maybe_refresh_reports_tab()

    def _sync_agent_graph(self) -> None:
        future = self._agent_graph_sync_future
        if future is not None:
            if not future.done():
                if self._scan_loop is not None and self._scan_loop.is_closed():
                    future.cancel()
                    self._agent_graph_sync_future = None
                else:
                    return
            else:
                self._agent_graph_sync_future = None
                try:
                    parent_of, statuses, names = future.result()
                except Exception:
                    logger.exception("TUI agent graph sync failed")
                else:
                    for agent_id, status in statuses.items():
                        self.live_view.upsert_agent(
                            agent_id,
                            name=names.get(agent_id, agent_id),
                            parent_id=parent_of.get(agent_id),
                            status=status,
                        )

        if self._scan_loop is None or self._scan_loop.is_closed():
            return

        async def collect() -> tuple[dict[str, str | None], dict[str, Any], dict[str, str]]:
            return await self.coordinator.graph_snapshot()

        self._agent_graph_sync_future = asyncio.run_coroutine_threadsafe(collect(), self._scan_loop)

    def _update_agent_node(self, agent_id: str, agent_data: dict[str, Any]) -> bool:
        if agent_id not in self.agent_nodes:
            return False

        try:
            agent_node = self.agent_nodes[agent_id]
            agent_name_raw = agent_data.get("name", "Agent")
            status = agent_data.get("status", "running")

            status_indicators = {
                "running": "⚪",
                "waiting": "⏸",
                "completed": "🟢",
                "failed": "🔴",
                "stopped": "■",
            }

            status_icon = status_indicators.get(status, "○")
            vuln_count = self._agent_vulnerability_count(agent_id)
            vuln_indicator = f" ({vuln_count})" if vuln_count > 0 else ""
            agent_name = f"{status_icon} {agent_name_raw}{vuln_indicator}"

            if agent_node.label != agent_name:
                agent_node.set_label(agent_name)
                return True

        except (KeyError, AttributeError, ValueError) as e:
            logger.warning(f"Failed to update agent node label: {e}")

        return False

    def _get_chat_content(
        self,
    ) -> tuple[Any, str | None]:
        if not self.selected_agent_id:
            return self._get_startup_progress_content()

        events = self._gather_agent_events(self.selected_agent_id)

        if not events:
            # Agent registered but first LLM event hasn't arrived yet.
            # Show startup progress (Docker sandbox, threat intel, etc.)
            # so the user sees what's happening instead of a static message.
            return self._get_startup_progress_content()

        current_event_ids = [f"{e['id']}:{e.get('version', 0)}" for e in events]
        if current_event_ids == self._displayed_events:
            return None, None

        self._displayed_events = current_event_ids
        return self._get_rendered_events_content(events), "chat-content"

    def _update_chat_view(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash or not self.is_mounted:
            return

        try:
            chat_history = self.query_one("#chat_history", VerticalScroll)
        except Exception:
            return

        if not self._is_widget_safe(chat_history):
            return

        try:
            is_at_bottom = chat_history.scroll_y >= chat_history.max_scroll_y
        except (AttributeError, ValueError):
            is_at_bottom = True

        content, css_class = self._get_chat_content()
        if content is None:
            return

        chat_display = self.query_one("#chat_display", Static)
        self._safe_widget_operation(chat_display.update, content)
        chat_display.set_classes(css_class)

        if is_at_bottom:
            self.call_later(chat_history.scroll_end, animate=False)

    def _get_startup_progress_content(self) -> tuple[Text, str]:
        """Show scan startup progress messages instead of generic 'Loading...'."""
        messages = self.live_view.system_messages
        text = Text()

        # Header
        target_names = [t.get("original", "?") for t in (self.scan_config.get("targets") or [])]
        targets_str = ", ".join(target_names) if target_names else "starting"
        text.append(f"Starting deep scan of ", style="dim")
        text.append(targets_str, style="bold white")
        text.append("\n\n")

        if not messages:
            text.append("Initializing scan engine...", style="dim")
            return text, "chat-placeholder placeholder-startup"

        # Show the latest 12 messages, newest first
        recent = messages[-12:]
        for msg in reversed(recent):
            text.append("  ")
            text.append("●", style="#4ade80")
            text.append("  ")
            text.append(msg["message"], style="dim")
            text.append("\n")

        # If we have agents now, add a hint
        if self.live_view.agents:
            text.append("\n")
            text.append(
                "Agents are live — select one from the sidebar to view activity.", style="#22c55e"
            )

        return text, "chat-placeholder placeholder-startup"

    def _get_chat_placeholder_content(
        self, message: str, placeholder_class: str
    ) -> tuple[Text, str]:
        self._displayed_events = [placeholder_class]
        text = Text()
        text.append(message)
        return text, f"chat-placeholder {placeholder_class}"

    @staticmethod
    def _merge_renderables(renderables: list[Any]) -> Text:
        """Merge renderables into a single Text for mouse text selection support."""
        combined = Text()
        for i, item in enumerate(renderables):
            if i > 0:
                combined.append("\n")
            prometheusTUIApp._append_renderable(combined, item)
        return prometheusTUIApp._sanitize_text(combined)

    @staticmethod
    def _sanitize_text(text: Text) -> Text:
        """Clamp spans so Rich/Textual can't crash on malformed offsets."""
        plain = text.plain
        text_length = len(plain)
        sanitized_spans: list[Span] = []

        for span in text.spans:
            start = max(0, min(span.start, text_length))
            end = max(0, min(span.end, text_length))
            if end > start:
                sanitized_spans.append(Span(start, end, span.style))

        return Text(
            plain,
            style=text.style,
            justify=text.justify,
            overflow=text.overflow,
            no_wrap=text.no_wrap,
            end=text.end,
            tab_size=text.tab_size,
            spans=sanitized_spans,
        )

    @staticmethod
    def _append_renderable(combined: Text, item: Any) -> None:
        """Recursively append a renderable's text content to a combined Text."""
        if isinstance(item, Text):
            combined.append_text(prometheusTUIApp._sanitize_text(item))
        elif isinstance(item, Group):
            for j, sub in enumerate(item.renderables):
                if j > 0:
                    combined.append("\n")
                prometheusTUIApp._append_renderable(combined, sub)
        else:
            inner = getattr(item, "content", None) or getattr(item, "renderable", None)
            if inner is not None:
                prometheusTUIApp._append_renderable(combined, inner)
            else:
                combined.append(str(item))

    def _get_rendered_events_content(self, events: list[dict[str, Any]]) -> Any:
        renderables: list[Any] = []

        if not events:
            return Text()

        for event in events:
            content: Any = None

            if event["type"] == "chat":
                content = self._render_chat_content(event["data"])
            elif event["type"] == "tool":
                content = render_tool_widget(event["data"])

            if content:
                if renderables:
                    renderables.append(Text(""))
                renderables.append(content)

        if not renderables:
            return Text()

        if len(renderables) == 1 and isinstance(renderables[0], Text):
            return self._sanitize_text(renderables[0])

        return self._merge_renderables(renderables)

    def _get_status_display_content(
        self, agent_id: str, agent_data: dict[str, Any]
    ) -> tuple[Text | None, Text, bool]:
        status = agent_data.get("status", "running")

        def keymap_styled(keys: list[tuple[str, str]]) -> Text:
            t = Text()
            for i, (key, action) in enumerate(keys):
                if i > 0:
                    t.append(" · ", style="dim")
                t.append(key, style="white")
                t.append(" ", style="dim")
                t.append(action, style="dim")
            return t

        simple_statuses: dict[str, tuple[str, str]] = {
            "stopped": ("Agent stopped", ""),
            "completed": ("Agent completed", ""),
        }

        if status in simple_statuses:
            msg, _ = simple_statuses[status]
            text = Text()
            text.append(msg)
            return (text, Text(), False)

        if status == "failed":
            error_msg = agent_data.get("error_message", "")
            text = Text()
            if error_msg:
                text.append(error_msg, style="red")
            else:
                text.append("Scan failed", style="red")
            self._stop_dot_animation()
            return (text, Text(), False)

        if status == "waiting":
            keymap = Text()
            keymap.append("Send message to resume", style="dim")
            return (Text(" "), keymap, False)

        if status == "running":
            if self._agent_has_real_activity(agent_id):
                animated_text = Text()
                animated_text.append_text(self._get_sweep_animation(self._sweep_colors))
                animated_text.append("esc", style="white")
                animated_text.append(" ", style="dim")
                animated_text.append("stop", style="dim")
                return (animated_text, keymap_styled([("ctrl-q", "quit")]), True)
            animated_text = self._get_animated_verb_text(agent_id, "Initializing")
            return (animated_text, keymap_styled([("ctrl-q", "quit")]), True)

        return (None, Text(), False)

    def _update_agent_status_display(self) -> None:
        try:
            status_display = self.query_one("#agent_status_display", Horizontal)
            status_text = self.query_one("#status_text", Static)
            keymap_indicator = self.query_one("#keymap_indicator", Static)
        except Exception:
            return

        widgets = [status_display, status_text, keymap_indicator]
        if not all(self._is_widget_safe(w) for w in widgets):
            return

        if not self.selected_agent_id:
            # Show startup progress in status bar when scan is initializing
            msgs = self.live_view.system_messages
            if msgs and not self.live_view.agents:
                latest = msgs[-1]["message"]
                text = Text()
                text.append_text(self._get_sweep_animation(self._sweep_colors))
                text.append(latest, style="dim")
                self._safe_widget_operation(status_text.update, text)
                self._safe_widget_operation(keymap_indicator.update, Text())
                self._safe_widget_operation(status_display.remove_class, "hidden")
                self._start_dot_animation()
                return
            self._safe_widget_operation(status_display.add_class, "hidden")
            return

        try:
            agent_data = self.live_view.agents[self.selected_agent_id]
            content, keymap, should_animate = self._get_status_display_content(
                self.selected_agent_id, agent_data
            )

            if not content:
                self._safe_widget_operation(status_display.add_class, "hidden")
                return

            self._safe_widget_operation(status_text.update, content)
            self._safe_widget_operation(keymap_indicator.update, keymap)
            self._safe_widget_operation(status_display.remove_class, "hidden")

            if should_animate:
                self._start_dot_animation()

        except Exception:
            self._safe_widget_operation(status_display.add_class, "hidden")

    def _update_stats_display(self) -> None:
        try:
            stats_display = self.query_one("#stats_display", Static)
        except Exception:
            return

        if not self._is_widget_safe(stats_display):
            return

        if self.screen.selections:
            return

        stats_content = Text()

        stats_text = build_tui_stats_text(self.report_state)
        if stats_text:
            stats_content.append(stats_text)

        version = get_package_version()
        stats_content.append(f"\nv{version}", style="white")

        self._safe_widget_operation(stats_display.update, stats_content)

    def _update_vulnerabilities_panel(self) -> None:
        """Update the vulnerabilities panel with current vulnerability data."""
        try:
            vuln_panel = self.query_one("#vulnerabilities_panel", VulnerabilitiesPanel)
        except Exception:
            return

        if not self._is_widget_safe(vuln_panel):
            return

        vulnerabilities = self.report_state.vulnerability_reports

        if not vulnerabilities:
            self._safe_widget_operation(vuln_panel.add_class, "hidden")
            return

        enriched_vulns = []
        for vuln in vulnerabilities:
            enriched = dict(vuln)
            agent_name = enriched.get("agent_name")
            agent_id = enriched.get("agent_id")
            if not agent_name and isinstance(agent_id, str):
                agent_name = self._get_agent_name(agent_id)
            if agent_name:
                enriched["agent_name"] = agent_name
            enriched_vulns.append(enriched)

        self._safe_widget_operation(vuln_panel.remove_class, "hidden")
        vuln_panel.update_vulnerabilities(enriched_vulns)

    def _maybe_refresh_reports_tab(self) -> None:
        """Periodically refresh the Reports tab when it's active."""
        # Immediate refresh when a new finding was filed
        if self._reports_needs_refresh and self.active_tab == "reports":
            self._reports_needs_refresh = False
            self._do_refresh_reports()
            return

        # Periodic refresh on interval
        self._reports_refresh_counter += 1
        if self._reports_refresh_counter >= self._reports_refresh_interval:
            self._reports_refresh_counter = 0
            if self.active_tab == "reports":
                self._do_refresh_reports()

    def _do_refresh_reports(self) -> None:
        """Refresh the FindingsLibraryPanel if mounted."""
        try:
            panel = self.query_one("#reports_container", FindingsLibraryPanel)
            panel.refresh_findings()
        except Exception:
            logger.debug("reports_container not mounted, refresh no-op", exc_info=True)

    def _get_sweep_animation(self, color_palette: list[str]) -> Text:
        text = Text()
        num_squares = self._sweep_num_squares
        num_colors = len(color_palette)

        offset = num_colors - 1
        max_pos = (num_squares - 1) + offset
        total_range = max_pos + offset
        cycle_length = total_range * 2
        frame_in_cycle = self._spinner_frame_index % cycle_length

        wave_pos = total_range - abs(total_range - frame_in_cycle)
        sweep_pos = wave_pos - offset

        dot_color = "#0a3d1f"

        for i in range(num_squares):
            dist = abs(i - sweep_pos)
            color_idx = max(0, num_colors - 1 - dist)

            if color_idx == 0:
                text.append("·", style=Style(color=dot_color))
            else:
                color = color_palette[color_idx]
                text.append("▪", style=Style(color=color))

        text.append(" ")
        return text

    def _get_animated_verb_text(self, agent_id: str, verb: str) -> Text:  # noqa: ARG002
        text = Text()
        sweep = self._get_sweep_animation(self._sweep_colors)
        text.append_text(sweep)
        parts = verb.split(" ", 1)
        text.append(parts[0], style="white")
        if len(parts) > 1:
            text.append(" ", style="dim")
            text.append(parts[1], style="dim")
        return text

    def _start_dot_animation(self) -> None:
        if self._dot_animation_timer is None:
            self._dot_animation_timer = self.set_interval(0.06, self._animate_dots)

    def _stop_dot_animation(self) -> None:
        if self._dot_animation_timer is not None:
            self._dot_animation_timer.stop()
            self._dot_animation_timer = None

    def _animate_dots(self) -> None:
        has_active_agents = False

        if self.selected_agent_id and self.selected_agent_id in self.live_view.agents:
            agent_data = self.live_view.agents[self.selected_agent_id]
            status = agent_data.get("status", "running")
            if status in ["running", "waiting"]:
                has_active_agents = True
                num_colors = len(self._sweep_colors)
                offset = num_colors - 1
                max_pos = (self._sweep_num_squares - 1) + offset
                total_range = max_pos + offset
                cycle_length = total_range * 2
                self._spinner_frame_index = (self._spinner_frame_index + 1) % cycle_length
                self._update_agent_status_display()

        if not has_active_agents:
            has_active_agents = any(
                agent_data.get("status", "running") in ["running", "waiting"]
                for agent_data in self.live_view.agents.values()
            )

        if not has_active_agents:
            self._stop_dot_animation()
            self._spinner_frame_index = 0

    def _agent_has_real_activity(self, agent_id: str) -> bool:
        return self.live_view.has_events_for_agent(agent_id)

    def _agent_vulnerability_count(self, agent_id: str) -> int:
        return sum(
            1
            for vuln in self.report_state.vulnerability_reports
            if vuln.get("agent_id") == agent_id
        )

    def _gather_agent_events(self, agent_id: str) -> list[dict[str, Any]]:
        events = self.live_view.events_for_agent(agent_id)
        events.sort(key=lambda e: (e["timestamp"], e["id"]))
        return events

    def watch_selected_agent_id(self, _agent_id: str | None) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        self._displayed_events.clear()

        self.call_later(self._update_chat_view)
        self._update_agent_status_display()

    def _start_scan_thread(self) -> None:
        def _post_progress(msg: str) -> None:
            """Thread-safe: post a progress message to the TUI."""
            try:
                self.call_from_thread(self.live_view.add_system_message, msg)
            except Exception:
                logger.debug("call_from_thread for progress msg failed, ignoring", exc_info=True)

        def scan_target() -> None:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._scan_loop = loop

                try:
                    if not self._scan_stop_event.is_set():
                        image = load_settings().runtime.image or "prometheus-sandbox:latest"

                        # Browser prescan — runs before the Docker sandbox scan.
                        # Discovers in-scope assets via program DB match and runs
                        # offline IDOR + info disclosure checks. Zero LLM tokens.
                        # Runs in the scan thread so it doesn't block the TUI startup.
                        try:
                            from prometheus.tools.idor_scanner.prescan import run_browser_prescan

                            prescan_targets = run_browser_prescan(
                                self.scan_config.get("targets", [])
                            )
                            if prescan_targets:
                                from prometheus.interface.utils import (
                                    assign_workspace_subdirs,
                                    infer_target_type,
                                    rewrite_localhost_targets,
                                )

                                original = (self.scan_config.get("targets") or [{}])[0].get(
                                    "original", ""
                                )
                                _post_progress(
                                    f"Expanded scan targets: {original} -> {len(prescan_targets)} asset(s)"
                                )
                                new_targets = []
                                for t in prescan_targets:
                                    target_type, target_dict = infer_target_type(t)
                                    new_targets.append(
                                        {
                                            "type": target_type,
                                            "details": target_dict,
                                            "original": t,
                                        }
                                    )
                                assign_workspace_subdirs(new_targets)
                                rewrite_localhost_targets(new_targets, "host.docker.internal")
                                self.scan_config["targets"] = new_targets
                        except Exception as e:
                            logger.warning("Browser prescan skipped: %s", e)

                        loop.run_until_complete(
                            run_prometheus_scan(
                                scan_config=self.scan_config,
                                scan_id=self.scan_config["run_name"],
                                image=str(image),
                                local_sources=getattr(self.args, "local_sources", None) or [],
                                coordinator=self.coordinator,
                                interactive=True,
                                event_sink=self._capture_sdk_event,
                                progress_callback=_post_progress,
                            ),
                        )

                except (KeyboardInterrupt, asyncio.CancelledError):
                    logger.info("Scan interrupted by user")
                except RuntimeError as e:
                    if "Event loop stopped before Future completed" in str(
                        e
                    ) or "Prepared model input is empty" in str(e):
                        logger.info("Scan loop stopped (clean shutdown): %s", e)
                    else:
                        logging.exception("Runtime error during scan")
                        self._scan_error = e
                except (ConnectionError, TimeoutError) as e:
                    logging.exception("Network error during scan")
                    self._scan_error = e
                except Exception as e:
                    logging.exception("Unexpected error during scan")
                    self._scan_error = e
                finally:
                    with contextlib.suppress(Exception):
                        loop.run_until_complete(
                            session_manager.cleanup(self.scan_config["run_name"]),
                        )
                    loop.close()
                    self._scan_completed.set()

            except Exception:
                logging.exception("Error setting up scan thread")
                self._scan_completed.set()

        self._scan_thread = threading.Thread(target=scan_target, daemon=True)
        self._scan_thread.start()

    def _capture_sdk_event(self, agent_id: str, event: Any) -> None:
        # The SDK event sink is invoked from the scan's asyncio loop on a
        # background thread. Textual's call_from_thread raises RuntimeError
        # when the app's loop is not yet up or is shutting down, and that
        # early-exit path drops the run_callback coroutine it just built,
        # producing a `coroutine 'run_callback' was never awaited` warning.
        # use_post_message routes the call through Textual's internal
        # thread-safe message queue, which is the documented primitive for
        # this exact case. On Python 3.14 we still need to guard against the
        # post-teardown window where post_message is no longer safe.
        if not self._loop or not self._thread_id or not self.is_running:
            try:
                self._record_sdk_event(agent_id, event)
            except Exception:
                logger.debug("_record_sdk_event (off-loop) failed, ignoring", exc_info=True)
            return
        try:
            self.call_later(self._record_sdk_event, agent_id, event)
        except RuntimeError:
            try:
                self._record_sdk_event(agent_id, event)
            except Exception:
                logger.debug(
                    "_record_sdk_event (call_later fallback) failed, ignoring", exc_info=True
                )

    def _record_sdk_event(self, agent_id: str, event: Any) -> None:
        self.live_view.ingest_sdk_event(agent_id, event)
        # Detect vulnerability report creation for real-time Reports tab refresh
        try:
            event_type = getattr(event, "type", "")
            if event_type == "run_item_stream_event":
                item = getattr(event, "item", None)
                if item is not None and getattr(item, "type", "") == "tool_call_output_item":
                    raw = getattr(item, "raw_item", None)
                    if raw is not None:
                        name = str(
                            raw.get("name", "")
                            if isinstance(raw, dict)
                            else getattr(raw, "name", "") or ""
                        )
                        if name == "create_vulnerability_report":
                            output = getattr(item, "output", None)
                            if output is None:
                                output = (
                                    raw.get("output", "")
                                    if isinstance(raw, dict)
                                    else getattr(raw, "output", "")
                                )
                            output_str = str(output) if not isinstance(output, str) else output
                            if '"success": true' in output_str.lower():
                                self._reports_needs_refresh = True
        except Exception:
            logger.debug("tool-output success scan failed, ignoring", exc_info=True)

    def _add_agent_node(self, agent_data: dict[str, Any]) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        agent_id = agent_data["id"]
        parent_id = agent_data.get("parent_id")
        status = agent_data.get("status", "running")

        try:
            agents_tree = self.query_one("#agents_tree", Tree)
        except Exception:
            return

        agent_name_raw = agent_data.get("name", "Agent")

        status_indicators = {
            "running": "⚪",
            "waiting": "⏸",
            "completed": "🟢",
            "failed": "🔴",
            "stopped": "■",
        }

        status_icon = status_indicators.get(status, "○")
        vuln_count = self._agent_vulnerability_count(agent_id)
        vuln_indicator = f" ({vuln_count})" if vuln_count > 0 else ""
        agent_name = f"{status_icon} {agent_name_raw}{vuln_indicator}"

        try:
            if parent_id and parent_id in self.agent_nodes:
                parent_node = self.agent_nodes[parent_id]
                agent_node = parent_node.add(
                    agent_name,
                    data={"agent_id": agent_id},
                )
                parent_node.allow_expand = True
            else:
                agent_node = agents_tree.root.add(
                    agent_name,
                    data={"agent_id": agent_id},
                )

            agent_node.allow_expand = False
            agent_node.expand()
            self.agent_nodes[agent_id] = agent_node

            if len(self.agent_nodes) == 1:
                agents_tree.select_node(agent_node)
                self.selected_agent_id = agent_id

            self._reorganize_orphaned_agents(agent_id)
        except (AttributeError, ValueError, RuntimeError) as e:
            logger.warning(f"Failed to add agent node {agent_id}: {e}")

    def _copy_node_under(self, node_to_copy: TreeNode, new_parent: TreeNode) -> None:
        agent_id = node_to_copy.data["agent_id"]
        agent_data = self.live_view.agents.get(agent_id, {})
        agent_name_raw = agent_data.get("name", "Agent")
        status = agent_data.get("status", "running")

        status_indicators = {
            "running": "⚪",
            "waiting": "⏸",
            "completed": "🟢",
            "failed": "🔴",
            "stopped": "■",
        }

        status_icon = status_indicators.get(status, "○")
        vuln_count = self._agent_vulnerability_count(agent_id)
        vuln_indicator = f" ({vuln_count})" if vuln_count > 0 else ""
        agent_name = f"{status_icon} {agent_name_raw}{vuln_indicator}"

        new_node = new_parent.add(
            agent_name,
            data=node_to_copy.data,
        )
        new_node.allow_expand = node_to_copy.allow_expand

        self.agent_nodes[agent_id] = new_node

        for child in node_to_copy.children:
            self._copy_node_under(child, new_node)

        if node_to_copy.is_expanded:
            new_node.expand()

    def _reorganize_orphaned_agents(self, new_parent_id: str) -> None:
        agents_to_move = []

        for agent_id, agent_data in list(self.live_view.agents.items()):
            if (
                agent_data.get("parent_id") == new_parent_id
                and agent_id in self.agent_nodes
                and agent_id != new_parent_id
            ):
                agents_to_move.append(agent_id)

        if not agents_to_move:
            return

        parent_node = self.agent_nodes[new_parent_id]

        for child_agent_id in agents_to_move:
            if child_agent_id in self.agent_nodes:
                old_node = self.agent_nodes[child_agent_id]

                if old_node.parent is parent_node:
                    continue

                self._copy_node_under(old_node, parent_node)

                old_node.remove()

        parent_node.allow_expand = True
        parent_node.expand()

    def _render_chat_content(self, msg_data: dict[str, Any]) -> Any:
        role = msg_data.get("role")
        content = msg_data.get("content", "")
        metadata = msg_data.get("metadata", {})

        if not content:
            return None

        del metadata
        if role == "user":
            return UserMessageRenderer.render_simple(content)

        return AgentMessageRenderer.render_simple(content)

    @on(Tree.NodeHighlighted)  # type: ignore[misc]
    def handle_tree_highlight(self, event: Tree.NodeHighlighted) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:  # type: ignore[truthy-function]
            return

        node = event.node

        try:
            agents_tree = self.query_one("#agents_tree", Tree)
        except Exception:
            return

        if self.focused == agents_tree and node.data:
            agent_id = node.data.get("agent_id")
            if agent_id:
                self.selected_agent_id = agent_id

    @on(Tree.NodeSelected)  # type: ignore[misc]
    def handle_tree_node_selected(self, event: Tree.NodeSelected) -> None:  # type: ignore[type-arg]
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:  # type: ignore[truthy-function]
            return

        node = event.node

        if node.allow_expand:
            if node.is_expanded:
                node.collapse()
            else:
                node.expand()

    def _send_user_message(self, message: str) -> None:
        if not self.selected_agent_id:
            return

        logger.info(
            "TUI: user message -> %s (len=%d)",
            self.selected_agent_id,
            len(message),
        )
        target_agent_id = self.selected_agent_id

        submitted = send_user_message_to_agent(
            coordinator=self.coordinator,
            loop=self._scan_loop,
            live_view=self.live_view,
            target_agent_id=target_agent_id,
            message=message,
        )
        if not submitted:
            self.notify("Scan loop is not ready; message was not sent", severity="warning")
            return

        self._displayed_events.clear()
        self._update_chat_view()

        self.call_after_refresh(self._focus_chat_input)

    def _get_agent_name(self, agent_id: str) -> str:
        try:
            if agent_id in self.live_view.agents:
                agent_name = self.live_view.agents[agent_id].get("name")
                if isinstance(agent_name, str):
                    return agent_name
        except (KeyError, AttributeError) as e:
            logger.warning(f"Could not retrieve agent name for {agent_id}: {e}")
        return "Unknown Agent"

    def action_toggle_help(self) -> None:
        if self.show_splash or not self.is_mounted:  # type: ignore[truthy-function]
            return

        try:
            self.query_one("#main_container")
        except Exception:
            return

        if isinstance(self.screen, HelpScreen):
            self.pop_screen()
            return

        if len(self.screen_stack) > 1:
            return

        self.push_screen(HelpScreen())

    def action_request_quit(self) -> None:
        if self.show_splash or not self.is_mounted:
            self.action_custom_quit()
            return

        if len(self.screen_stack) > 1:
            return

        try:
            self.query_one("#main_container")
        except Exception:
            self.action_custom_quit()
            return

        self.push_screen(QuitScreen())

    def action_stop_selected_agent(self) -> None:
        if self.show_splash or not self.is_mounted:  # type: ignore[truthy-function]
            return

        if len(self.screen_stack) > 1:
            self.pop_screen()
            return

        if not self.selected_agent_id:
            return

        agent_name, should_stop = self._validate_agent_for_stopping()
        if not should_stop:
            return

        try:
            self.query_one("#main_container")
        except Exception:
            return

        self.push_screen(StopAgentScreen(agent_name, self.selected_agent_id))

    def _validate_agent_for_stopping(self) -> tuple[str, bool]:
        agent_name = "Unknown Agent"

        try:
            if self.selected_agent_id in self.live_view.agents:
                agent_data = self.live_view.agents[self.selected_agent_id]
                agent_name = agent_data.get("name", "Unknown Agent")

                agent_status = agent_data.get("status", "running")
                if agent_status not in ["running", "waiting"]:
                    return agent_name, False

                agent_events = self._gather_agent_events(self.selected_agent_id)
                if not agent_events:
                    return agent_name, False

                return agent_name, True

        except (KeyError, AttributeError, ValueError) as e:
            logger.warning(f"Failed to gather agent events: {e}")

        return agent_name, False

    def action_confirm_stop_agent(self, agent_id: str) -> None:
        if self._scan_loop is None or self._scan_loop.is_closed():
            logger.warning("No active scan loop; cannot stop agent %s", agent_id)
            return
        logger.info("TUI: graceful stop requested for %s (cascade)", agent_id)
        asyncio.run_coroutine_threadsafe(
            self.coordinator.cancel_descendants_graceful(agent_id),
            self._scan_loop,
        )

    def action_custom_quit(self) -> None:
        self._scan_stop_event.set()

        # Cancel all running agents before joining
        try:
            loop = getattr(self, "_scan_loop", None)
            if loop and not loop.is_closed():
                root_ids = [
                    aid
                    for aid, st in self.coordinator.statuses.items()
                    if st == "running" and self.coordinator.parent_of.get(aid) is None
                ]
                for root_id in root_ids:
                    try:
                        future = asyncio.run_coroutine_threadsafe(
                            self.coordinator.cancel_descendants(root_id),
                            loop,
                        )
                        future.result(timeout=3)
                    except Exception:
                        logger.debug(
                            "cancel_descendants for %s failed, ignoring", root_id, exc_info=True
                        )
        except Exception:
            logger.debug("shutdown cancellation loop failed, ignoring", exc_info=True)

        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_thread.join(timeout=5)

        # Force-close the scan event loop to prevent deadlock
        loop = getattr(self, "_scan_loop", None)
        if loop and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(loop.stop)
            except Exception:
                logger.debug(
                    "loop.call_soon_threadsafe(loop.stop) failed during cleanup, ignoring",
                    exc_info=True,
                )
            with contextlib.suppress(Exception):
                loop.close()

        self.report_state.cleanup()

        self.exit()

    def _is_widget_safe(self, widget: Any) -> bool:
        try:
            _ = widget.screen
        except Exception:
            return False
        else:
            return bool(widget.is_mounted)

    def _safe_widget_operation(
        self, operation: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> bool:
        try:
            operation(*args, **kwargs)
        except Exception:
            return False
        else:
            return True

    def on_resize(self, event: events.Resize) -> None:
        if self.show_splash or not self.is_mounted:  # type: ignore[truthy-function]
            return

        try:
            sidebar = self.query_one("#sidebar", Vertical)
            chat_area = self.query_one("#chat_area_container", Vertical)
        except Exception:
            return

        if event.size.width < self.SIDEBAR_MIN_WIDTH:
            sidebar.add_class("-hidden")
            chat_area.add_class("-full-width")
        else:
            sidebar.remove_class("-hidden")
            chat_area.remove_class("-full-width")

    def on_mouse_up(self, _event: events.MouseUp) -> None:
        self.set_timer(0.05, self._auto_copy_selection)

    _ICON_PREFIXES: ClassVar[tuple[str, ...]] = (
        "🐞 ",
        "🌐 ",
        "📋 ",
        "🧠 ",
        "◆ ",
        "◇ ",
        "◈ ",
        "→ ",
        "○ ",
        "● ",
        "✓ ",
        "✗ ",
        "⚠ ",
        "▍ ",
        "▍",
        "┃ ",
        "• ",
        ">_ ",
        "</> ",
        "<~> ",
        "[ ] ",
        "[~] ",
        "[•] ",
    )

    _DECORATIVE_LINES: ClassVar[frozenset[str]] = frozenset(
        {
            "● In progress...",
            "✓ Done",
            "✗ Failed",
            "✗ Error",
            "○ Unknown",
        }
    )

    @staticmethod
    def _clean_copied_text(text: str) -> str:
        lines = text.split("\n")
        cleaned: list[str] = []
        for line in lines:
            stripped = line.lstrip()
            if stripped in prometheusTUIApp._DECORATIVE_LINES:
                continue
            if stripped and all(c == "─" for c in stripped):
                continue
            out = line
            for prefix in prometheusTUIApp._ICON_PREFIXES:
                if stripped.startswith(prefix):
                    leading = line[: len(line) - len(line.lstrip())]
                    out = leading + stripped[len(prefix) :]
                    break
            cleaned.append(out)
        return "\n".join(cleaned)

    def _auto_copy_selection(self) -> None:
        copied = False

        try:
            if self.screen.selections:
                selected = self.screen.get_selected_text()
                self.screen.clear_selection()
                if selected and selected.strip():
                    cleaned = self._clean_copied_text(selected)
                    self.copy_to_clipboard(cleaned if cleaned.strip() else selected)
                    copied = True
        except Exception:
            logger.debug("Failed to copy screen selection", exc_info=True)

        if not copied:
            try:
                chat_input = self.query_one("#chat_input", ChatTextArea)
                selected = chat_input.selected_text
                if selected and selected.strip():
                    self.copy_to_clipboard(selected)
                    chat_input.move_cursor(chat_input.cursor_location)
                    copied = True
            except Exception:
                logger.debug("Failed to copy chat input selection", exc_info=True)

        if copied:
            self.notify("Copied to clipboard", timeout=2)


async def run_tui(args: argparse.Namespace) -> None:
    from prometheus.core.paths import configure_runs_dir
    from prometheus.config import load_settings as _load_settings

    _settings = _load_settings()
    if _settings.runtime.runs_dir:
        configure_runs_dir(_settings.runtime.runs_dir)
    else:
        configure_runs_dir(
            os.environ.get("PROMETHEUS_DATA_DIR") or str(Path.home() / ".prometheus")
        )

    app = prometheusTUIApp(args)
    await app.run_async()
    if app._scan_error is not None:
        raise app._scan_error
