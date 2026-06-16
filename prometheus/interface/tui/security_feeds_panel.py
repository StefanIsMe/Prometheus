"""Security threat intelligence feeds panel for the prometheus TUI.

Shows all configured threat feeds, their status, last update time,
record counts, and per-target coverage.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Static


if TYPE_CHECKING:
    from textual.app import ComposeResult


logger = logging.getLogger(__name__)

# Feed metadata — human-readable names, URLs, and what each feed covers
FEED_INFO: dict[str, dict[str, str]] = {
    "nvd_recent": {
        "name": "NVD (National Vulnerability Database)",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "description": "US government CVE repository. Keyword + CPE search. Primary source for CVSS scores.",
        "auth": "None (rate limited)",
        "coverage": "All CVEs",
    },
    "osv": {
        "name": "OSV (Open Source Vulnerabilities)",
        "url": "https://api.osv.dev",
        "description": "Google's unified vulnerability database. Covers 20+ ecosystems (npm, PyPI, Go, Maven, etc.).",
        "auth": "None",
        "coverage": "Open source packages",
    },
    "ghsa_bulk": {
        "name": "GHSA (GitHub Security Advisories)",
        "url": "https://api.github.com/advisories",
        "description": "GitHub's advisory database. Per-ecosystem bulk fetch (npm, pip, go, maven, nuget, rubygems, rust, composer).",
        "auth": "GitHub token (optional, 60 req/hr unauthenticated)",
        "coverage": "GitHub-hosted ecosystems",
    },
    "circl_recent": {
        "name": "CIRCL Vulnerability-Lookup",
        "url": "https://cve.circl.lu/api/search",
        "description": "European CERT's vulnerability lookup. Vendor/product search with CVSS and exploit refs.",
        "auth": "None",
        "coverage": "All CVEs (European perspective)",
    },
    "vulnerablecode": {
        "name": "VulnerableCode",
        "url": "https://public.vulnerablecode.io/api/v3",
        "description": "AboutCode's PURL-based vulnerability database. Package-level matching across ecosystems.",
        "auth": "None",
        "coverage": "Package-level (PURL-based)",
    },
    "npm_advisory": {
        "name": "npm Bulk Advisory",
        "url": "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk",
        "description": "npm's native security advisory endpoint. Package+version specific queries.",
        "auth": "None",
        "coverage": "npm packages only",
    },
    "epss": {
        "name": "EPSS (Exploit Prediction Scoring System)",
        "url": "https://api.first.org/data/v1/epss",
        "description": "FIRST's exploit probability scores (0-1). Predicts likelihood of active exploitation.",
        "auth": "None",
        "coverage": "All CVEs with EPSS scores",
    },
    "cisa_kev": {
        "name": "CISA KEV (Known Exploited Vulnerabilities)",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "description": "CISA's catalog of actively exploited vulnerabilities. All entries are CRITICAL severity.",
        "auth": "None",
        "coverage": "Actively exploited CVEs only",
    },
    "shodan_recent": {
        "name": "Shodan CVEDB",
        "url": "https://cvedb.shodan.io/cve/recent",
        "description": "Shodan's CVE database with recent high/critical vulnerabilities.",
        "auth": "None",
        "coverage": "Recent high/critical CVEs",
    },
    "cisa_advisories": {
        "name": "CISA Cybersecurity Advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "description": "CISA's RSS feed of cybersecurity advisories (ICS, medical, industrial, etc.).",
        "auth": "None",
        "coverage": "US-CERT advisories",
    },
}

# Scan-time query sources (used during every scan, not just bulk ingestion)
SCAN_QUERY_SOURCES = [
    "nvd_recent",
    "osv",
    "ghsa_bulk",
    "circl_recent",
    "vulnerablecode",
    "npm_advisory",
    "epss",
]


class SecurityFeedsPanel(VerticalScroll):
    """Shows all security threat feeds with status, coverage, and stats.

    Data sources:
    - Feed status from ThreatIntelDB.feed_status table
    - DB stats from ThreatIntelDB.get_stats()
    - Per-target tech fingerprints from TargetRegistry
    """

    BINDINGS = [
        ("r", "refresh", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        yield Vertical(
            Horizontal(
                Button("Refresh", id="feeds_refresh_btn", variant="default"),
                Static("", id="feeds_summary"),
                id="feeds_toolbar",
            ),
            VerticalScroll(id="feeds_list"),
            id="feeds_content",
        )

    def on_mount(self) -> None:
        self._load_feeds()

    def _load_feeds(self) -> None:
        """Load feed status from the local threat intel DB."""
        try:
            from prometheus.tools.threat_intel.local_db import ThreatIntelDB

            db = ThreatIntelDB()
            stats = db.get_stats()
            db.close()

            self._render_feeds(stats)
        except Exception as exc:
            logger.exception("Failed to load security feeds")
            try:
                summary = self.query_one("#feeds_summary", Static)
                summary.update(f"[red]Error: {exc}[/red]")
            except Exception:
                logger.debug("could not update feeds_summary widget", exc_info=True)

    def _render_feeds(self, stats: dict[str, Any]) -> None:
        """Render the feed status cards."""
        try:
            summary = self.query_one("#feeds_summary", Static)
            feeds_list = self.query_one("#feeds_list", VerticalScroll)
        except Exception:
            return

        # Clear
        for child in list(feeds_list.children):
            child.remove()

        # DB overview
        total_cves = stats.get("total_cves", 0)
        kev_count = stats.get("cisa_kev_count", 0)
        exploit_count = stats.get("exploit_count", 0)
        epss_count = stats.get("epss_count", 0)

        summary.update(
            f"DB: [bold]{total_cves}[/bold] CVEs  |  "
            f"[red]{kev_count} KEV[/red]  |  "
            f"[yellow]{exploit_count} exploits[/yellow]  |  "
            f"EPSS: {epss_count}"
        )

        # Build feed status map
        feed_status_map: dict[str, dict[str, Any]] = {}
        for feed in stats.get("feeds", []):
            feed_status_map[feed["feed_name"]] = feed

        # Render each feed
        for feed_key, info in FEED_INFO.items():
            status_data = feed_status_map.get(feed_key, {})
            self._render_feed_card(feed_key, info, status_data, feeds_list)

        # Add scan-time sources section
        scan_section = Static("\n[bold]Per-Scan Query Sources[/bold]\n")
        scan_section.styles.margin = (1, 0, 0, 0)
        feeds_list.mount(scan_section)

        scan_desc = Static(
            "These sources are queried live during every scan for each detected technology.\n"
            "Results are cached locally after first query."
        )
        scan_desc.styles.margin = (0, 0, 1, 2)
        feeds_list.mount(scan_desc)

        for feed_key in SCAN_QUERY_SOURCES:
            info = FEED_INFO.get(feed_key, {})
            if info:
                line = Static(
                    f"  [green]●[/green] {info['name']}\n"
                    f"    {info['description']}\n"
                    f"    Auth: {info['auth']}"
                )
                line.styles.margin = (0, 0, 0, 2)
                feeds_list.mount(line)

    def _render_feed_card(
        self,
        feed_key: str,
        info: dict[str, str],
        status_data: dict[str, Any],
        container: VerticalScroll,
    ) -> None:
        """Render a single feed status card."""
        name = info.get("name", feed_key)
        description = info.get("description", "")
        auth = info.get("auth", "None")
        coverage = info.get("coverage", "")

        # Status
        status = status_data.get("status", "not_queried")
        last_updated = status_data.get("last_updated", "")
        record_count = status_data.get("record_count", 0)
        error_message = status_data.get("error_message", "")
        duration = status_data.get("duration_seconds", 0.0)

        # Status badge
        if status == "ok":
            status_badge = "[green]OK[/green]"
        elif status == "error":
            status_badge = "[red]ERROR[/red]"
        elif status == "pending":
            status_badge = "[yellow]PENDING[/yellow]"
        else:
            status_badge = "[dim]NOT QUERIED[/dim]"

        # Format last updated
        last_updated_display = "Never"
        if last_updated:
            try:
                dt = datetime.fromisoformat(last_updated)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                now = datetime.now(UTC)
                delta = now - dt
                if delta.total_seconds() < 60:
                    last_updated_display = "Just now"
                elif delta.total_seconds() < 3600:
                    mins = int(delta.total_seconds() / 60)
                    last_updated_display = f"{mins}m ago"
                elif delta.total_seconds() < 86400:
                    hours = int(delta.total_seconds() / 3600)
                    last_updated_display = f"{hours}h ago"
                else:
                    days = int(delta.total_seconds() / 86400)
                    last_updated_display = f"{days}d ago"
            except (ValueError, TypeError):
                last_updated_display = str(last_updated)

        # Build card
        card_lines = [
            f"[bold]{name}[/bold]  {status_badge}",
            f"  {description}",
            f"  Coverage: {coverage}  |  Auth: {auth}",
            f"  Records: [bold]{record_count:,}[/bold]  |  Last: {last_updated_display}",
        ]

        if duration > 0:
            card_lines[-1] += f"  |  Duration: {duration:.1f}s"

        if error_message:
            card_lines.append(f"  [red]Error: {error_message}[/red]")

        card = Static("\n".join(card_lines))
        card.styles.margin = (0, 0, 1, 2)
        container.mount(card)

    def action_refresh(self) -> None:
        self._load_feeds()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "feeds_refresh_btn":
            self._load_feeds()
