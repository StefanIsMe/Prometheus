"""Findings Library panel — cross-scan vulnerability findings with submission tracking.

Toggle with F2 from the main TUI. Shows all findings across all targets,
filterable by domain, severity, and submission status.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from rich.style import Style
from rich.text import Text
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Select, Static, TextArea


if TYPE_CHECKING:
    from textual import events
    from textual.app import ComposeResult

    from prometheus.interface.tui.app import (
        prometheusTUIApp,  # codeql[py/unsafe-cyclic-import] : suppressed via the security dashboard triage
    )  # codeql[py/unsafe-cyclic-import] : import is in TYPE_CHECKING block and only used for type hints; no runtime cycle

logger = logging.getLogger(__name__)

# Match existing TUI severity colors
SEVERITY_COLORS: dict[str, str] = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#22c55e",
    "info": "#3b82f6",
}

STATUS_COLORS: dict[str, str] = {
    "new": "#737373",
    "needs_review": "#3b82f6",
    "validating": "#06b6d4",
    "verified": "#22c55e",
    "rejected": "#ef4444",
    "archived": "#525252",
    "ready_to_submit": "#a855f7",
    "submitted": "#a855f7",
    "duplicate": "#d97706",
    "accepted": "#22c55e",
}

STATUS_LABELS: dict[str, str] = {
    "new": "NEW",
    "needs_review": "NEEDS REVIEW",
    "validating": "VALIDATING",
    "verified": "VERIFIED",
    "rejected": "REJECTED",
    "archived": "ARCHIVED",
    "ready_to_submit": "READY TO SUBMIT",
    "submitted": "SUBMITTED",
    "duplicate": "DUPLICATE",
    "accepted": "ACCEPTED",
}


class SubmissionStatusDialog(ModalScreen[dict[str, Any] | None]):  # type: ignore[misc]
    """Modal dialog for updating submission status on a finding."""

    def __init__(self, finding: dict[str, Any]) -> None:
        super().__init__()
        self.finding = finding
        self._selected_status = finding.get("status", "new")

    def compose(self) -> ComposeResult:
        title = self.finding.get("finding_title", "Unknown")
        domain = self.finding.get("domain", "")
        current = self.finding.get("status", "new")

        yield Vertical(
            Label(f"Update: {title[:50]}", id="dialog_title"),
            Label(f"Domain: {domain}", id="dialog_domain"),
            Label(f"Current: {STATUS_LABELS.get(current, current.upper())}", id="dialog_current"),
            Label("New status:", id="dialog_status_label"),
            Select(
                [(v, k) for k, v in STATUS_LABELS.items()],
                value=current,
                id="dialog_status_select",
                allow_blank=False,
            ),
            Label("Platform:", id="dialog_platform_label"),
            Select(
                [
                    ("HackerOne", "hackerone"),
                    ("Bugcrowd", "bugcrowd"),
                    ("Intigriti", "intigriti"),
                    ("Internal", "internal"),
                    ("Other", "other"),
                ],
                value=self.finding.get("platform") or Select.NULL,
                id="dialog_platform_select",
                allow_blank=True,
            ),
            Label("Report URL:", id="dialog_url_label"),
            Static(
                self.finding.get("report_url") or "",
                id="dialog_url_display",
            ),
            Label("Notes:", id="dialog_notes_label"),
            Static(
                self.finding.get("notes") or "",
                id="dialog_notes_display",
            ),
            Label("Reason:", id="dialog_reason_label"),
            TextArea("", id="dialog_reason_input"),
            Horizontal(
                Button("Save", variant="primary", id="save_status"),
                Button("Cancel", variant="default", id="cancel_status"),
                id="dialog_buttons",
            ),
            id="submission_dialog_inner",
        )

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel_status":
            self.app.pop_screen()

        elif event.button.id == "save_status":
            try:
                status_select = self.query_one("#dialog_status_select", Select)
                platform_select = self.query_one("#dialog_platform_select", Select)
                reason_input = self.query_one("#dialog_reason_input", TextArea)

                new_status = status_select.value
                platform = platform_select.value if platform_select.value != Select.NULL else None
                reason = reason_input.text.strip()

                # Save to canonical DB and keep report_status as projection.
                from prometheus.core.candidate_store import CandidateStore
                from prometheus.tools.knowledge.store import KnowledgeStore

                store = KnowledgeStore()
                candidate_store = CandidateStore()
                candidate = candidate_store.get_candidate_for_report(self.finding)
                if candidate:
                    candidate_store.transition_status(
                        candidate["id"],
                        str(new_status),
                        actor="tui",
                        reason=reason or None,
                        payload={"platform": platform},
                    )
                else:
                    store.upsert_report_status(
                        domain=self.finding.get("domain", ""),
                        scan_id=self.finding.get("scan_id", "manual"),
                        finding_title=self.finding.get("finding_title", ""),
                        status=str(new_status),
                        platform=platform,
                        endpoint=self.finding.get("endpoint"),
                    )

                self.app.notify(f"Status updated to {STATUS_LABELS.get(new_status, new_status)}")
                self.app.pop_screen()

                # Refresh the library panel if visible
                try:
                    from prometheus.interface.tui.findings_library import (  # noqa: PLC0415  # codeql[py/import-own-module] : suppressed via the security dashboard triage
                        FindingsLibraryPanel,
                    )

                    panel = self.app.query_one("#findings_library", FindingsLibraryPanel)
                    panel.refresh_findings()
                except Exception:
                    logger.debug("could not refresh findings_library panel", exc_info=True)

            except Exception as exc:
                logger.exception("Failed to update status")
                self.app.notify(f"Error: {exc}", severity="error")


class AddNoteDialog(ModalScreen[dict[str, Any] | None]):  # type: ignore[misc]
    """Modal dialog for adding a note/comment to a finding."""

    def __init__(self, finding: dict[str, Any]) -> None:
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        title = self.finding.get("finding_title", "Unknown")

        yield Vertical(
            Label(f"Add Note: {title[:50]}", id="note_title"),
            Label("Type:", id="note_type_label"),
            Select(
                [
                    ("Note", "note"),
                    ("Evidence", "evidence"),
                    ("Verification", "verification"),
                    ("Submission", "submission"),
                    ("Status Change", "status_change"),
                ],
                value="note",
                id="note_type_select",
                allow_blank=False,
            ),
            Label("Comment:", id="note_content_label"),
            TextArea("", id="note_content_input"),
            Horizontal(
                Button("Save", variant="primary", id="save_note"),
                Button("Cancel", variant="default", id="cancel_note"),
                id="note_buttons",
            ),
            id="note_dialog_inner",
        )

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel_note":
            self.app.pop_screen()

        elif event.button.id == "save_note":
            try:
                type_select = self.query_one("#note_type_select", Select)
                content_input = self.query_one("#note_content_input", TextArea)

                comment_type = type_select.value
                content = content_input.text.strip()

                if not content:
                    self.app.notify("Note cannot be empty", severity="warning")
                    return

                # Save to DB
                from prometheus.tools.knowledge.store import KnowledgeStore

                store = KnowledgeStore()
                result = store.add_comment(
                    finding_id=self.finding["id"],
                    content=content,
                    comment_type=comment_type,
                )

                if result.get("success"):
                    self.app.pop_screen()
                    # Refresh the detail view by popping and re-pushing
                    self.app.pop_screen()
                    self.app.push_screen(FindingDetailScreen(self.finding))
                    self.app.notify("Note added", severity="information")
                else:
                    self.app.notify("Failed to save note", severity="error")

            except Exception as exc:
                logger.exception("Failed to add note")
                self.app.notify(f"Error: {exc}", severity="error")


class FindingItem(Static):
    """A single finding row in the library."""

    def __init__(self, finding: dict[str, Any], **kwargs: Any) -> None:
        self.finding = finding
        label = self._build_label(finding)
        super().__init__(label, classes="finding-item", **kwargs)

    @staticmethod
    def _build_label(finding: dict[str, Any]) -> Text:
        severity = (finding.get("severity") or "info").lower()
        title = finding.get("finding_title", "Unknown")
        domain = finding.get("domain", "")
        status = (finding.get("status") or "new").lower()
        platform = finding.get("platform") or ""

        color = SEVERITY_COLORS.get(severity, "#3b82f6")
        status_color = STATUS_COLORS.get(status, "#737373")
        status_label = STATUS_LABELS.get(status, status.upper())

        label = Text()
        label.append("● ", style=Style(color=color))
        # Truncate title to fit
        max_title = 40
        display_title = title[:max_title] + ("..." if len(title) > max_title else "")
        label.append(display_title, style=Style(color="#d4d4d4"))
        label.append("  ", style=Style())
        label.append(f"[{domain}]", style=Style(color="#737373"))
        label.append("  ", style=Style())
        label.append(status_label, style=Style(color=status_color, bold=True))
        if platform:
            label.append(f" {platform}", style=Style(color="#525252"))

        return label

    def on_click(self, _event: events.Click) -> None:
        """Open detail view on click."""
        self.app.push_screen(FindingDetailScreen(self.finding))


class FindingDetailScreen(ModalScreen[None]):  # type: ignore[misc]
    """Detailed view of a finding with actions and comment timeline."""

    BINDINGS = [
        ("escape", "close", "Close"),
    ]

    def __init__(self, finding: dict[str, Any]) -> None:
        super().__init__()
        self.finding = finding

    def action_close(self) -> None:
        """Close the finding detail view."""
        self.app.pop_screen()

    def compose(self) -> ComposeResult:
        yield Vertical(
            VerticalScroll(
                Static(self._build_detail_text(), id="finding_detail_content"),
                Static(self._build_timeline_text(), id="finding_timeline_content"),
                id="finding_detail_scroll",
            ),
            Horizontal(
                Button("Generate H1 Report", variant="primary", id="ask_agent"),
                Button("Copy Latest H1", variant="default", id="copy_h1"),
                Button("Regenerate", variant="default", id="regenerate_h1"),
                Button("Add Note", variant="default", id="add_note"),
                Button("Update Status", variant="default", id="update_status"),
                Button("Export", variant="default", id="export_finding"),
                Button("Copy", variant="default", id="copy_finding"),
                Button("Close", variant="default", id="close_finding"),
                id="finding_detail_buttons",
            ),
            id="finding_detail_dialog",
        )

    def _build_detail_text(self) -> Text:
        f = self.finding
        text = Text()

        # Title
        text.append("Finding Detail\n\n", style="bold #ea580c")

        # Fields
        fields = [
            ("Title", f.get("finding_title", "")),
            ("Domain", f.get("domain", "")),
            ("Severity", (f.get("severity") or "").upper()),
            ("CVSS", str(f.get("cvss") or "N/A")),
            ("Endpoint", f.get("endpoint") or "N/A"),
            ("CWE", f.get("cwe") or "N/A"),
            ("Status", STATUS_LABELS.get(f.get("status", "new"), "NEW")),
            ("Platform", f.get("platform") or "N/A"),
            ("Report URL", f.get("report_url") or "N/A"),
            ("H1 Report ID", f.get("h1_report_id") or "N/A"),
            ("Notes", f.get("notes") or "N/A"),
            ("Submitted", f.get("submitted_at") or "N/A"),
            ("Resolved", f.get("resolved_at") or "N/A"),
            ("Last Verified", f.get("last_verified_at") or "N/A"),
            ("Created", f.get("created_at") or "N/A"),
            ("Scan ID", f.get("scan_id") or "N/A"),
        ]

        for label, value in fields:
            text.append(f"  {label}: ", style="bold #a8a29e")
            # Color severity
            if label == "Severity":
                color = SEVERITY_COLORS.get(value.lower(), "#d4d4d4")
                text.append(value, style=f"bold {color}")
            elif label == "Status":
                color = STATUS_COLORS.get(f.get("status", "new").lower(), "#737373")
                text.append(value, style=f"bold {color}")
            else:
                text.append(value, style="#d4d4d4")
            text.append("\n")

        # Full finding content from full_finding_json
        full_json_str = f.get("full_finding_json")
        if full_json_str:
            try:
                import json as _json

                full = _json.loads(full_json_str)
                text.append("\n  ─── Full Finding Content ───\n", style="bold #3b82f6")

                rich_fields = [
                    ("Description", full.get("description")),
                    ("Impact", full.get("impact")),
                    ("Technical Analysis", full.get("technical_analysis")),
                    ("PoC Description", full.get("poc_description")),
                    ("PoC Script Code", full.get("poc_script_code")),
                    ("Remediation", full.get("remediation_steps")),
                ]

                for label, value in rich_fields:
                    if not value:
                        continue
                    text.append(f"\n  {label}:\n", style="bold #a8a29e")
                    # Indent each line of the content
                    for line in str(value).split("\n"):
                        text.append(f"    {line}\n", style="#d4d4d4")

                # CVSS breakdown if available
                breakdown = full.get("cvss_breakdown")
                if breakdown and isinstance(breakdown, dict):
                    text.append("\n  CVSS Breakdown:\n", style="bold #a8a29e")
                    for metric, val in breakdown.items():
                        text.append(f"    {metric}: {val}\n", style="#d4d4d4")

                # Code locations if available
                locations = full.get("code_locations")
                if locations and isinstance(locations, list):
                    text.append("\n  Code Locations:\n", style="bold #a8a29e")
                    for loc in locations:
                        if isinstance(loc, dict):
                            text.append(
                                f"    {loc.get('file', '?')}:{loc.get('line', '?')}\n",
                                style="#d4d4d4",
                            )
                        else:
                            text.append(f"    {loc}\n", style="#d4d4d4")

                # CVE if available
                cve = full.get("cve")
                if cve:
                    text.append(f"\n  CVE: {cve}\n", style="bold #d97706")

                # Method if available
                method = full.get("method")
                if method:
                    text.append(f"  Method: {method}\n", style="#d4d4d4")

            except Exception:
                text.append("\n  [Could not parse full finding content]\n", style="dim #737373")

        self._append_candidate_evidence_and_artifacts(text, f)
        return text

    def _append_candidate_evidence_and_artifacts(self, text: Text, finding: dict[str, Any]) -> None:
        try:
            from prometheus.core.candidate_store import CandidateStore

            store = CandidateStore()
            candidate = store.get_candidate_for_report(finding)
            if not candidate:
                return
            text.append("\n  ─── Candidate Lifecycle ───\n", style="bold #06b6d4")
            text.append(f"  Candidate ID: {candidate.get('id')}\n", style="#d4d4d4")
            text.append(f"  Lifecycle: {candidate.get('lifecycle_status')}\n", style="#d4d4d4")
            text.append(f"  Fingerprint: {candidate.get('fingerprint')}\n", style="#737373")

            evidence = store.list_evidence(str(candidate.get("id")))
            text.append("\n  Evidence\n", style="bold #3b82f6")
            if not evidence:
                text.append("    No stored evidence yet.\n", style="dim #737373")
            for item in evidence:
                text.append(
                    f"    [{item.get('evidence_kind')}] {item.get('summary') or item.get('id')}\n",
                    style="#d4d4d4",
                )
                if item.get("path"):
                    text.append(f"      {item.get('path')}\n", style="#737373")

            artifacts = store.list_artifacts(str(candidate.get("id")))
            text.append("\n  Artifacts\n", style="bold #a855f7")
            if not artifacts:
                text.append("    No versioned artifacts yet.\n", style="dim #737373")
            for artifact in artifacts[:20]:
                text.append(
                    f"    v{artifact.get('version')} {artifact.get('platform')} {artifact.get('artifact_type')}: {artifact.get('path')}\n",
                    style="#d4d4d4",
                )
        except Exception:
            logger.debug("Failed to load candidate evidence/artifacts", exc_info=True)

    def _build_timeline_text(self) -> Text:
        """Build the comment timeline for this finding."""
        text = Text()

        finding_id = self.finding.get("id")
        if not finding_id:
            return text

        try:
            from prometheus.tools.knowledge.store import KnowledgeStore

            store = KnowledgeStore()
            comments = store.get_comments(finding_id)
        except Exception:
            return text

        if not comments:
            text.append("\n  No timeline entries yet.\n", style="dim #737373")
            return text

        text.append("\n  Timeline\n", style="bold #a8a29e")
        text.append("  " + "─" * 40 + "\n", style="#333333")

        type_colors = {
            "note": "#d4d4d4",
            "evidence": "#3b82f6",
            "verification": "#22c55e",
            "submission": "#a855f7",
            "status_change": "#d97706",
            "h1_draft": "#ea580c",
            "validation": "#06b6d4",
        }
        type_icons = {
            "note": "📝",
            "evidence": "🔍",
            "verification": "✓",
            "submission": "📤",
            "status_change": "●",
            "h1_draft": "📋",
            "validation": "⚖",
        }

        h1_version_counter = 0

        for c in comments:
            ctype = c.get("comment_type", "note")
            content = c.get("content", "")
            created = c.get("created_at", "")
            color = type_colors.get(ctype, "#d4d4d4")
            icon = type_icons.get(ctype, "●")

            # Format timestamp
            try:
                from datetime import datetime

                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                time_str = dt.strftime("%Y-%m-%d %H:%M")
            except (ValueError, AttributeError):
                time_str = created[:16] if created else "?"

            # Track h1_draft versions
            if ctype == "h1_draft":
                h1_version_counter += 1
                ver = c.get("version") or h1_version_counter
                label = f"H1 Draft v{ver}"
                # Truncate long reports for display
                display_content = content[:300] + ("..." if len(content) > 300 else "")
                text.append(f"  {icon} ", style=color)
                text.append(f"[{time_str}] ", style="#737373")
                text.append(f"{label}", style=f"bold {color}")
                text.append(f" — {display_content}\n", style=color)
            elif ctype == "validation":
                text.append(f"  {icon} ", style=color)
                text.append(f"[{time_str}] ", style="#737373")
                text.append(f"Validation — {content}\n", style=color)
            else:
                text.append(f"  {icon} ", style=color)
                text.append(f"[{time_str}] ", style="#737373")
                text.append(content, style=color)
                text.append("\n")

        return text

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        app: prometheusTUIApp = self.app  # type: ignore[assignment]

        if event.button.id == "close_finding":
            app.pop_screen()

        elif event.button.id == "copy_finding":
            self._copy_to_clipboard()

        elif event.button.id == "ask_agent":
            app.pop_screen()
            app.focus_finding_in_chat(self.finding)

        elif event.button.id == "copy_h1":
            self._copy_latest_h1()

        elif event.button.id == "regenerate_h1":
            self._regenerate_h1()

        elif event.button.id == "export_finding":
            self._export_finding()

        elif event.button.id == "update_status":
            app.pop_screen()
            app.show_submission_dialog(self.finding)

        elif event.button.id == "add_note":
            app.push_screen(AddNoteDialog(self.finding))

    def _copy_to_clipboard(self) -> None:
        f = self.finding
        lines = [
            f"# {f.get('finding_title', 'Unknown')}",
            "",
            f"**Domain:** {f.get('domain', '')}",
            f"**Severity:** {(f.get('severity') or '').upper()} (CVSS {f.get('cvss') or 'N/A'})",
            f"**Endpoint:** {f.get('endpoint') or 'N/A'}",
            f"**CWE:** {f.get('cwe') or 'N/A'}",
            f"**Status:** {STATUS_LABELS.get(f.get('status', 'new'), 'NEW')}",
            f"**Platform:** {f.get('platform') or 'N/A'}",
            f"**Report URL:** {f.get('report_url') or 'N/A'}",
            f"**Notes:** {f.get('notes') or 'N/A'}",
        ]

        # Include full finding content if available
        full_json_str = f.get("full_finding_json")
        if full_json_str:
            try:
                import json as _json

                full = _json.loads(full_json_str)
                rich_fields = [
                    ("Description", full.get("description")),
                    ("Impact", full.get("impact")),
                    ("Technical Analysis", full.get("technical_analysis")),
                    ("PoC Description", full.get("poc_description")),
                    ("PoC Script Code", full.get("poc_script_code")),
                    ("Remediation", full.get("remediation_steps")),
                ]
                for label, value in rich_fields:
                    if value:
                        lines.append(f"\n**{label}:**\n{value}")
                if full.get("cve"):
                    lines.append(f"\n**CVE:** {full['cve']}")
            except Exception:
                logger.debug("Failed to extract rich fields for clipboard copy", exc_info=True)

        self.app.copy_to_clipboard("\n".join(lines))
        self.app.notify("Copied to clipboard")

    def _copy_latest_h1(self) -> None:
        """Copy the active (or latest) H1 draft from the finding's timeline to clipboard."""
        finding_id = self.finding.get("id")
        if not finding_id:
            self.app.notify("No finding ID available", severity="warning")
            return

        try:
            from prometheus.tools.knowledge.store import KnowledgeStore

            store = KnowledgeStore()
            draft = store.get_latest_h1_draft(finding_id)

            if not draft:
                self.app.notify("No H1 drafts found for this finding", severity="warning")
                return

            content = draft.get("content", "")
            if not content:
                self.app.notify("H1 draft is empty", severity="warning")
                return

            self.app.copy_to_clipboard(content)
            version = draft.get("version", "?")
            self.app.notify(f"H1 Draft v{version} copied to clipboard")

        except Exception as exc:
            logger.exception("Failed to copy H1 draft")
            self.app.notify(f"Error: {exc}", severity="error")

    def _regenerate_h1(self) -> None:
        """Regenerate H1 report with feedback from the latest validation verdict."""
        finding_id = self.finding.get("id")
        if not finding_id:
            self.app.notify("No finding ID available", severity="warning")
            return

        try:
            from prometheus.tools.knowledge.store import KnowledgeStore

            store = KnowledgeStore()
            comments = store.get_comments(finding_id)

            # Find the latest validation comment
            validations = [c for c in comments if c.get("comment_type") == "validation"]
            if not validations:
                self.app.notify(
                    "No validation found — generate an H1 report first", severity="warning"
                )
                return

            latest_validation = validations[-1]
            content = latest_validation.get("content", "")

            # Extract the "Missing:" guidance
            missing_guidance = ""
            if "Missing:" in content:
                missing_guidance = content.split("Missing:", 1)[1].strip()

            if not missing_guidance:
                self.app.notify(
                    "Latest validation has no missing guidance to address", severity="information"
                )
                return

            # Build regeneration prompt with feedback
            app: prometheusTUIApp = self.app  # type: ignore[assignment]
            app.pop_screen()
            app.focus_finding_in_chat_with_feedback(self.finding, missing_guidance)

        except Exception as exc:
            logger.exception("Failed to regenerate H1")
            self.app.notify(f"Error: {exc}", severity="error")

    def _export_finding(self) -> None:
        """Export finding with all H1 drafts to a markdown file."""
        import json as _json
        import os
        import re

        finding_id = self.finding.get("id")
        if not finding_id:
            self.app.notify("No finding ID available", severity="warning")
            return

        try:
            from prometheus.tools.knowledge.store import KnowledgeStore

            store = KnowledgeStore()
            comments = store.get_comments(finding_id)

            f = self.finding
            title = f.get("finding_title", "Unknown")
            domain = f.get("domain", "unknown")

            # Build markdown content
            lines = [
                f"# {title}",
                "",
                f"**Domain:** {domain}",
                f"**Severity:** {(f.get('severity') or '').upper()} (CVSS {f.get('cvss') or 'N/A'})",
                f"**Endpoint:** {f.get('endpoint') or 'N/A'}",
                f"**CWE:** {f.get('cwe') or 'N/A'}",
                f"**Status:** {STATUS_LABELS.get(f.get('status', 'new'), 'NEW')}",
                f"**Platform:** {f.get('platform') or 'N/A'}",
                f"**Report URL:** {f.get('report_url') or 'N/A'}",
                "",
            ]

            # Original finding content
            full_json_str = f.get("full_finding_json")
            if full_json_str:
                try:
                    full = (
                        _json.loads(full_json_str)
                        if isinstance(full_json_str, str)
                        else full_json_str
                    )
                    for label, key in [
                        ("Description", "description"),
                        ("Impact", "impact"),
                        ("Technical Analysis", "technical_analysis"),
                        ("PoC Description", "poc_description"),
                        ("PoC Code", "poc_script_code"),
                        ("Remediation", "remediation_steps"),
                    ]:
                        val = full.get(key)
                        if val:
                            lines.extend([f"## {label}", "", val, ""])
                except Exception:
                    logger.debug("Failed to extract export fields", exc_info=True)

            # H1 drafts
            h1_drafts = [c for c in comments if c.get("comment_type") == "h1_draft"]
            if h1_drafts:
                lines.extend(["## H1 Report Drafts", ""])
                for i, draft in enumerate(h1_drafts, 1):
                    ver = draft.get("version", i)
                    created = draft.get("created_at", "")
                    lines.append(f"### Draft v{ver} ({created[:16]})")
                    lines.append("")
                    lines.append(draft.get("content", ""))
                    lines.append("")

            # Timeline
            other_comments = [c for c in comments if c.get("comment_type") != "h1_draft"]
            if other_comments:
                lines.extend(["## Timeline", ""])
                for c in other_comments:
                    ctype = c.get("comment_type", "note")
                    created = c.get("created_at", "")[:16]
                    content = c.get("content", "")
                    lines.append(f"- [{created}] **{ctype}:** {content}")
                lines.append("")

            # Write to file
            safe_title = re.sub(r"[^\w\s-]", "", title)[:50].strip().replace(" ", "_")
            safe_domain = domain.replace(".", "_")
            filename = f"{safe_domain}_{safe_title}.md"

            export_dir = os.path.expanduser("~/prometheus-source/reports")
            os.makedirs(export_dir, exist_ok=True)
            filepath = os.path.join(export_dir, filename)

            with open(filepath, "w") as fh:
                fh.write("\n".join(lines))

            self.app.notify(f"Exported to {filepath}")
            logger.info("Exported finding to %s", filepath)

        except Exception as exc:
            logger.exception("Failed to export finding")
            self.app.notify(f"Error: {exc}", severity="error")


class FindingsLibraryPanel(VerticalScroll):
    """Cross-scan findings library with filtering and submission tracking."""

    BINDINGS = [
        ("enter", "open_finding", "Open"),
        ("s", "update_status", "Update Status"),
        ("x", "export_all", "Export All"),
        ("escape", "back_to_live", "Back to Live"),
    ]

    _all_findings: list[dict[str, Any]] = []
    _filtered_findings: list[dict[str, Any]] = []
    _filter_domain: str | None = None
    _filter_status: str | None = None
    _filter_severity: str | None = None
    _selected_index: int = 0

    def compose(self) -> ComposeResult:
        yield Vertical(
            # Filter bar
            Horizontal(
                Select(
                    [("All Domains", "")],
                    value="",
                    id="filter_domain",
                    allow_blank=False,
                ),
                Select(
                    [("All Statuses", "")] + [(v, k) for k, v in STATUS_LABELS.items()],
                    value="",
                    id="filter_status",
                    allow_blank=False,
                ),
                Select(
                    [("All Severities", "")]
                    + [(s.upper(), s) for s in ["critical", "high", "medium", "low", "info"]],
                    value="",
                    id="filter_severity",
                    allow_blank=False,
                ),
                id="filter_bar",
            ),
            # Summary line
            Static("", id="library_summary"),
            # Findings list
            VerticalScroll(id="findings_list"),
            id="library_content",
        )

    def on_mount(self) -> None:
        self._load_findings()

    def _load_findings(self) -> None:
        """Load all findings from the knowledge store."""
        try:
            from prometheus.tools.knowledge.store import KnowledgeStore

            store = KnowledgeStore()
            self._all_findings = store.list_reports()
            self._populate_domain_filter()
            self._apply_filters()
        except Exception:
            logger.exception("Failed to load findings")
            self._all_findings = []
            self._filtered_findings = []

    def refresh_findings(self) -> None:
        """Public method to reload findings from DB."""
        self._load_findings()

    def _populate_domain_filter(self) -> None:
        """Update domain filter dropdown with available domains."""
        try:
            select = self.query_one("#filter_domain", Select)
            domains = sorted({f.get("domain", "") for f in self._all_findings})
            options = [("All Domains", "")] + [(d, d) for d in domains if d]
            select.set_options(options)
        except Exception:
            logger.debug("Domain filter widget not available", exc_info=True)

    def _apply_filters(self) -> None:
        """Apply current filters and re-render the findings list."""
        findings = self._all_findings

        if self._filter_domain:
            findings = [f for f in findings if f.get("domain") == self._filter_domain]
        if self._filter_status:
            findings = [f for f in findings if f.get("status") == self._filter_status]
        if self._filter_severity:
            findings = [
                f for f in findings if (f.get("severity") or "").lower() == self._filter_severity
            ]

        self._filtered_findings = findings
        self._selected_index = min(self._selected_index, max(0, len(findings) - 1))
        self._render_findings()

    def _render_findings(self) -> None:
        """Render the filtered findings list."""
        try:
            findings_scroll = self.query_one("#findings_list", VerticalScroll)
            summary = self.query_one("#library_summary", Static)
        except ValueError:
            return

        # Clear existing items
        for child in list(findings_scroll.children):
            child.remove()

        total = len(self._all_findings)
        filtered = len(self._filtered_findings)

        if total == 0:
            summary.update("No findings tracked yet. Run a scan first.")
            return

        # Summary
        status_counts: dict[str, int] = {}
        for f in self._all_findings:
            s = (f.get("status") or "new").lower()
            status_counts[s] = status_counts.get(s, 0) + 1

        summary_parts = [f"{filtered}/{total} findings"]
        for status, count in sorted(status_counts.items()):
            color = STATUS_COLORS.get(status, "#737373")
            label = STATUS_LABELS.get(status, status.upper())
            summary_parts.append(f"[{color}]{label}:{count}[/{color}]")
        summary.update(" | ".join(summary_parts))

        # Render findings
        if not self._filtered_findings:
            no_match = Static("No findings match filters", classes="no-findings")
            findings_scroll.mount(no_match)
            return

        for i, finding in enumerate(self._filtered_findings):
            item = FindingItem(finding)
            if i == self._selected_index:
                item.add_class("selected")
            findings_scroll.mount(item)

    def _navigate(self, direction: int) -> None:
        """Navigate findings list up/down."""
        if not self._filtered_findings:
            return

        # Remove selected class from current
        try:
            findings_scroll = self.query_one("#findings_list", VerticalScroll)
            children = list(findings_scroll.children)
            if 0 <= self._selected_index < len(children):
                children[self._selected_index].remove_class("selected")
        except (ValueError, IndexError):
            logger.debug(
                "could not remove 'selected' class from finding %d",
                self._selected_index,
                exc_info=True,
            )

        self._selected_index = max(
            0, min(len(self._filtered_findings) - 1, self._selected_index + direction)
        )

        # Add selected class to new
        findings_scroll = None
        try:
            findings_scroll = self.query_one("#findings_list", VerticalScroll)
            children = list(findings_scroll.children)
            if 0 <= self._selected_index < len(children):
                children[self._selected_index].add_class("selected")
                children[self._selected_index].scroll_visible()
        except (ValueError, IndexError):
            logger.debug(
                "could not add 'selected' class to finding %d", self._selected_index, exc_info=True
            )

    def on_key(self, event: events.Key) -> None:
        if event.key == "up":
            self._navigate(-1)
            event.prevent_default()
        elif event.key == "down":
            self._navigate(1)
            event.prevent_default()
        elif event.key == "enter":
            self.action_open_finding()
            event.prevent_default()
        elif event.key == "s":
            self.action_update_status()
            event.prevent_default()
        elif event.key == "escape":
            app: prometheusTUIApp = self.app  # type: ignore[assignment]
            app.action_toggle_tab()
            event.prevent_default()

    def action_open_finding(self) -> None:
        if not self._filtered_findings:
            return
        if 0 <= self._selected_index < len(self._filtered_findings):
            finding = self._filtered_findings[self._selected_index]
            self.app.push_screen(FindingDetailScreen(finding))

    def action_update_status(self) -> None:
        if not self._filtered_findings:
            return
        if 0 <= self._selected_index < len(self._filtered_findings):
            finding = self._filtered_findings[self._selected_index]
            app: prometheusTUIApp = self.app  # type: ignore[assignment]
            app.show_submission_dialog(finding)

    def action_export_all(self) -> None:
        """Export all filtered findings to a single markdown file."""
        import os
        import re
        from datetime import datetime

        if not self._filtered_findings:
            self.app.notify("No findings to export", severity="warning")
            return

        try:
            from prometheus.tools.knowledge.store import KnowledgeStore

            store = KnowledgeStore()

            # Determine domain for filename
            domains = {f.get("domain", "") for f in self._filtered_findings}
            domain_label = "_".join(sorted(d for d in domains if d)) or "all"

            lines = [f"# Prometheus Findings Export — {domain_label}", ""]
            lines.append(f"**Exported:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
            lines.append(f"**Total findings:** {len(self._filtered_findings)}")
            lines.append("")

            # Group by severity
            by_severity: dict[str, list[dict[str, Any]]] = {}
            for f in self._filtered_findings:
                sev = (f.get("severity") or "info").lower()
                by_severity.setdefault(sev, []).append(f)

            for sev in ["critical", "high", "medium", "low", "info"]:
                findings = by_severity.get(sev, [])
                if not findings:
                    continue

                lines.append(f"## {sev.upper()} ({len(findings)})")
                lines.append("")

                for f in findings:
                    title = f.get("finding_title", "Unknown")
                    finding_id = f.get("id")
                    lines.append(f"### {title}")
                    lines.append("")
                    lines.append(f"- **Domain:** {f.get('domain', '')}")
                    lines.append(f"- **Endpoint:** {f.get('endpoint') or 'N/A'}")
                    lines.append(f"- **CVSS:** {f.get('cvss') or 'N/A'}")
                    lines.append(f"- **CWE:** {f.get('cwe') or 'N/A'}")
                    lines.append(
                        f"- **Status:** {STATUS_LABELS.get(f.get('status', 'new'), 'NEW')}"
                    )
                    lines.append("")

                    # Include latest H1 draft if available
                    if finding_id:
                        draft = store.get_latest_h1_draft(finding_id)
                        if draft:
                            lines.append("#### H1 Report")
                            lines.append("")
                            lines.append(draft.get("content", ""))
                            lines.append("")

            # Write to file
            safe_domain = re.sub(r"[^\w-]", "", domain_label)[:50]
            filename = f"{safe_domain}_findings_export.md"

            export_dir = os.path.expanduser("~/prometheus-source/reports")
            os.makedirs(export_dir, exist_ok=True)
            filepath = os.path.join(export_dir, filename)

            with open(filepath, "w") as fh:
                fh.write("\n".join(lines))

            self.app.notify(f"Exported {len(self._filtered_findings)} findings to {filepath}")

        except Exception as exc:
            logger.exception("Failed to export findings")
            self.app.notify(f"Error: {exc}", severity="error")

    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle filter dropdown changes."""
        if event.select.id == "filter_domain":
            self._filter_domain = event.value or None
        elif event.select.id == "filter_status":
            self._filter_status = event.value or None
        elif event.select.id == "filter_severity":
            self._filter_severity = event.value or None
        self._apply_filters()
