#!/usr/bin/env python3
"""
prometheus Agent Interface
"""

# Apply httpx zstd patch BEFORE any imports that trigger LiteLLM
# (OpenGateway sends zstd-compressed bodies that httpx can't decompress)
from prometheus.config.models import _patch_httpx_no_zstd


_patch_httpx_no_zstd()

import argparse
import asyncio
import atexit
import contextlib
import logging
import os
import shutil
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from agents.models.multi_provider import MultiProvider
from docker.errors import DockerException
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from prometheus.config import (
    apply_config_override,
    load_settings,
    persist_current,
)
from prometheus.config.models import configure_sdk_model_defaults, normalize_model_name
from prometheus.core.paths import run_dir_for, runtime_state_dir
from prometheus.core.rate_limiter import set_rate
from prometheus.interface.cli import run_cli
from prometheus.interface.tui import run_tui
from prometheus.interface.utils import (
    assign_workspace_subdirs,
    build_final_stats_text,
    check_docker_connection,
    clone_repository,
    collect_local_sources,
    generate_run_name,
    image_exists,
    infer_target_type,
    is_whitebox_scan,
    process_pull_line,
    resolve_diff_scope_context,
    rewrite_localhost_targets,
    validate_config_file,
)
from prometheus.report.state import get_global_report_state
from prometheus.report.writer import read_run_record, write_run_record
from prometheus.telemetry import posthog, scarf
from prometheus.telemetry.logging import configure_dependency_logging


HOST_GATEWAY_HOSTNAME = "host.docker.internal"


logger = logging.getLogger(__name__)


def validate_environment() -> None:
    logger.info("Validating environment")
    console = Console()
    missing_required_vars = []
    missing_optional_vars = []

    settings = load_settings()
    resolution = configure_sdk_model_defaults(settings)
    logger.info(
        "Environment model routing: provider=%s model=%s base_url=%s tier=%s",
        resolution.provider_name,
        resolution.model_id,
        resolution.base_url,
        resolution.tier.value,
    )

    # LLM routing comes from ~/.prometheus/llm.yaml and env vars.
    # No Hermes dependency.

    if not settings.llm.api_key:
        missing_optional_vars.append("LLM_API_KEY")

    if not settings.llm.api_base:
        missing_optional_vars.append("LLM_API_BASE")

    # Perplexity removed — web_search now uses free ddgs (DuckDuckGo)

    if missing_required_vars:
        error_text = Text()
        error_text.append("MISSING REQUIRED ENVIRONMENT VARIABLES", style="bold red")
        error_text.append("\n\n", style="white")

        for var in missing_required_vars:
            error_text.append(f"• {var}", style="bold yellow")
            error_text.append(" is not set\n", style="white")

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="dim white")
            for var in missing_optional_vars:
                error_text.append(f"• {var}", style="dim yellow")
                error_text.append(" is not set\n", style="dim white")

        error_text.append("\nRequired environment variables:\n", style="white")
        for var in missing_required_vars:
            if var == "prometheus_LLM":
                error_text.append("• ", style="white")
                error_text.append("prometheus_LLM", style="bold cyan")
                error_text.append(
                    " - Model name to use (e.g., 'gpt-5.4' or 'claude-sonnet-4-6')\n",
                    style="white",
                )

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="white")
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for the LLM provider "
                        "(not needed for local models, Vertex AI, AWS, etc.)\n",
                        style="white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_BASE", style="bold cyan")
                    error_text.append(
                        " - Custom API base URL if using local models (e.g., Ollama, LMStudio)\n",
                        style="white",
                    )
                # PERPLEXITY_API_KEY removed — web_search uses free ddgs
                elif var == "prometheus_REASONING_EFFORT":
                    error_text.append("• ", style="white")
                    error_text.append("prometheus_REASONING_EFFORT", style="bold cyan")
                    error_text.append(
                        " - Reasoning effort level: none, minimal, low, medium, high, xhigh "
                        "(default: high)\n",
                        style="white",
                    )

        error_text.append("\nExample setup:\n", style="white")
        error_text.append("export prometheus_LLM='gpt-5.4'\n", style="dim white")

        if missing_optional_vars:
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append(
                        "export LLM_API_KEY='your-api-key-here'  "
                        "# not needed for local models, Vertex AI, AWS, etc.\n",
                        style="dim white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append(
                        "export LLM_API_BASE='http://localhost:11434'  "
                        "# needed for local models only\n",
                        style="dim white",
                    )
                # PERPLEXITY_API_KEY removed — web_search uses free ddgs
                elif var == "prometheus_REASONING_EFFORT":
                    error_text.append(
                        "export prometheus_REASONING_EFFORT='high'\n",
                        style="dim white",
                    )

        panel = Panel(
            error_text,
            title="[bold white]prometheus",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        logger.error("Missing required env vars: %s", missing_required_vars)
        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)
    logger.info(
        "Environment OK (optional missing: %s)",
        missing_optional_vars or "none",
    )


def check_docker_installed() -> None:
    if shutil.which("docker") is None:
        logger.error("Docker CLI not found in PATH")
        console = Console()
        error_text = Text()
        error_text.append("DOCKER NOT INSTALLED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("The 'docker' CLI was not found in your PATH.\n", style="white")
        error_text.append(
            "Please install Docker and ensure the 'docker' command is available.\n\n", style="white"
        )

        panel = Panel(
            error_text,
            title="[bold white]prometheus",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)
    logger.debug("Docker CLI present")


async def warm_up_llm() -> None:
    console = Console()
    logger.info("Warming up LLM connection")

    try:
        settings = load_settings()
        configure_sdk_model_defaults(settings)
        llm = settings.llm

        # Use unknown_prefix_mode="model_id" so non-SDK prefixed model
        # names (e.g. stepfun/step-3.7-flash:free) reach the OpenAI-compatible
        # gateway verbatim instead of raising UserError: Unknown prefix.
        model = MultiProvider(unknown_prefix_mode="model_id").get_model(
            normalize_model_name(llm.model or "")
        )

        async def _consume_warmup_stream() -> None:
            async for _ in model.stream_response(
                system_instructions="You are a helpful assistant.",
                input="Reply with just 'OK'.",
                model_settings=ModelSettings(store=False),
                tools=[],
                output_schema=None,
                handoffs=[],
                tracing=ModelTracing.DISABLED,
                previous_response_id=None,
                conversation_id=None,
                prompt=None,
            ):
                pass

        await asyncio.wait_for(_consume_warmup_stream(), timeout=llm.timeout)
        logger.info("LLM warm-up succeeded for model %s", normalize_model_name(llm.model or ""))

    except Exception as e:
        logger.exception("LLM warm-up failed")
        error_text = Text()
        error_text.append("LLM CONNECTION FAILED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("Could not establish connection to the language model.\n", style="white")
        error_text.append("Please check your configuration and try again.\n", style="white")
        error_text.append(f"\nError: {e}", style="dim white")

        panel = Panel(
            error_text,
            title="[bold white]prometheus",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


def get_version() -> str:
    try:
        from importlib.metadata import version

        return version("prometheus-agent")
    except Exception:
        return "unknown"


def _positive_float(value: str) -> float:
    """Argparse type: reject negative floats."""
    try:
        f = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid float value: '{value}'")
    if f < 0:
        raise argparse.ArgumentTypeError(f"invalid value: {f} (must be >= 0)")
    return f


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prometheus Multi-Agent Cybersecurity Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Web application penetration test
  prometheus --target https://example.com

  # GitHub repository analysis
  prometheus --target https://github.com/user/repo
  prometheus --target git@github.com:user/repo.git

  # Local code analysis
  prometheus --target ./my-project

  # Domain penetration test
  prometheus --target example.com

  # IP address penetration test
  prometheus --target 192.168.1.42

  # Multiple targets (e.g., white-box testing with source and deployed app)
  prometheus --target https://github.com/user/repo --target https://example.com
  prometheus --target ./my-project --target https://staging.example.com --target https://prod.example.com

  # Custom instructions (inline)
  prometheus --target example.com --instruction "Focus on authentication vulnerabilities"

  # Custom instructions (from file)
  prometheus --target example.com --instruction-file ./instructions.txt
  prometheus --target https://app.com --instruction-file /path/to/detailed_instructions.md
        """,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"prometheus {get_version()}",
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        action="append",
        help="Target to test (URL, repository, local directory path, domain name, or IP address). "
        "Can be specified multiple times for multi-target scans. "
        "Required for fresh runs; loaded from disk when ``--resume`` is set.",
    )
    parser.add_argument(
        "--scans-file",
        type=str,
        help="Path to a JSON file defining multiple scans to launch. "
        "Each scan can have its own targets, instruction, and scan mode. "
        'Example format: [{"targets": ["https://example.com"], "instruction": "focus on auth", "mode": "deep"}]',
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help="Custom instructions for the penetration test. This can be "
        "specific vulnerability types to focus on (e.g., 'Focus on IDOR and XSS'), "
        "testing approaches (e.g., 'Perform thorough authentication testing'), "
        "test credentials (e.g., 'Use the following credentials to access the app: "
        "admin:password123'), "
        "or areas of interest (e.g., 'Check login API endpoint for security issues').",
    )

    parser.add_argument(
        "--instruction-file",
        type=str,
        help="Path to a file containing detailed custom instructions for the penetration test. "
        "Use this option when you have lengthy or complex instructions saved in a file "
        "(e.g., '--instruction-file ./detailed_instructions.txt').",
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help=(
            "Run in non-interactive mode (no TUI, exits on completion). "
            "Default is interactive mode with TUI."
        ),
    )

    parser.add_argument(
        "--scope-mode",
        type=str,
        choices=["auto", "diff", "full"],
        default="auto",
        help=(
            "Scope mode for code targets: "
            "'auto' enables PR diff-scope in CI/headless runs, "
            "'diff' forces changed-files scope, "
            "'full' disables diff-scope."
        ),
    )

    parser.add_argument(
        "--diff-base",
        type=str,
        help=(
            "Target branch or commit to compare against (e.g., origin/main). "
            "Defaults to the repository's default branch."
        ),
    )

    parser.add_argument(
        "--config",
        type=str,
        help="Path to a custom config file (JSON) to use instead of ~/.prometheus/cli-config.json",
    )

    parser.add_argument(
        "--rate-limit",
        type=_positive_float,
        default=5.0,
        help="Max HTTP requests per second to the target (default: 5). "
        "Respects bug bounty program rate limits. Set to 0 to disable.",
    )

    parser.add_argument(
        "--allow-direct",
        action="store_true",
        help="Allow individual HTTP requests to bypass Tor if Tor is unreachable. "
        "By default, all scan traffic routes through Tor. With this flag, "
        "tools will retry requests directly if Tor fails.",
    )

    parser.add_argument(
        "--header",
        "-H",
        type=str,
        action="append",
        dest="custom_headers",
        help="Custom HTTP header to include in ALL requests (e.g., "
        "'X-HackerOne-Handle: your-h1-handle'). Can be specified multiple times. "
        "Headers are injected into the sandbox environment and the system prompt "
        "so every curl/httpx/nuclei request includes them.",
    )

    parser.add_argument(
        "--resume",
        type=str,
        metavar="RUN_NAME",
        help=(
            "Resume a prior scan by its run name (the dir under ./prometheus_runs/). "
            "Picks up the root + every non-terminal subagent's full LLM history "
            "and agent topology. Skips fresh run-name generation."
        ),
    )

    args = parser.parse_args()

    if args.instruction and args.instruction_file:
        parser.error(
            "Cannot specify both --instruction and --instruction-file. Use one or the other."
        )

    if args.instruction_file:
        instruction_path = Path(args.instruction_file)
        try:
            with instruction_path.open(encoding="utf-8") as f:
                args.instruction = f.read().strip()
                if not args.instruction:
                    parser.error(f"Instruction file '{instruction_path}' is empty")
        except Exception as e:
            parser.error(f"Failed to read instruction file '{instruction_path}': {e}")

    args.user_explicit_instruction = args.instruction if args.resume else None

    if args.resume:
        if args.target:
            parser.error(
                "Cannot combine --resume with --target. --resume picks up where "
                "the prior run left off, including the original target list."
            )
        _load_resume_state(args, parser)
        agents_path = runtime_state_dir(run_dir_for(args.resume)) / "agents.json"
        if not agents_path.exists():
            parser.error(
                f"--resume {args.resume}: missing {agents_path}. The run was "
                f"persisted but never reached its first agent snapshot — "
                f"there's nothing to resume from. Pick a fresh --run-name "
                f"or remove --resume to start over with the same targets."
            )
    elif args.scans_file:
        # Scans file mode: validate file exists
        if not Path(args.scans_file).exists():
            parser.error(f"Scans file not found: {args.scans_file}")
        args.targets_info = []
    elif not args.target:
        parser.error(
            "A target is required. Use -t/--target to specify a URL, domain, "
            "IP, or local path to scan."
        )
    else:
        args.targets_info = []
        for target in args.target:
            try:
                target_type, target_dict = infer_target_type(target)

                if target_type == "local_code":
                    display_target = target_dict.get("target_path", target)
                else:
                    display_target = target

                args.targets_info.append(
                    {"type": target_type, "details": target_dict, "original": display_target}
                )
            except ValueError:
                parser.error(f"Invalid target '{target}'")

        assign_workspace_subdirs(args.targets_info)
        rewrite_localhost_targets(args.targets_info, HOST_GATEWAY_HOSTNAME)

    return args


def _persist_run_record(args: argparse.Namespace) -> None:
    run_dir = run_dir_for(args.run_name)
    run_dir.mkdir(parents=True, exist_ok=True)
    run_record = {
        "run_id": args.run_name,
        "run_name": args.run_name,
        "status": "running",
        "start_time": datetime.now(UTC).isoformat(),
        "end_time": None,
        "targets_info": args.targets_info,
        "instruction": args.instruction,
        "non_interactive": args.non_interactive,
        "local_sources": getattr(args, "local_sources", []),
        "diff_scope": getattr(args, "diff_scope", {"active": False}),
        "scope_mode": args.scope_mode,
        "diff_base": args.diff_base,
        "custom_headers": getattr(args, "custom_headers", None) or [],
    }
    write_run_record(run_dir, run_record)


def _load_resume_state(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Populate ``args.targets_info`` and friends from a prior run's run.json."""
    run_dir = run_dir_for(args.resume)
    state_path = run_dir / "run.json"
    state: dict = {}  # codeql[py/uninitialized-local-variable] : initialized to a safe default before the read_run_record() call below
    if not state_path.exists():
        parser.error(
            f"--resume {args.resume}: no such run "
            f"(missing {state_path}; remove --resume for a fresh start)"
        )
    try:
        state = read_run_record(run_dir)
    except RuntimeError as exc:
        parser.error(f"--resume {args.resume}: run.json unreadable: {exc}")

    args.targets_info = state.get("targets_info") or []
    if not args.targets_info:
        parser.error(f"--resume {args.resume}: run.json has no targets_info")

    for target in args.targets_info:
        if not isinstance(target, dict):
            continue
        details = target.get("details") or {}
        if target.get("type") != "repository":
            continue
        cloned = details.get("cloned_repo_path")
        if not cloned:
            continue
        if not Path(cloned).expanduser().exists():
            parser.error(
                f"--resume {args.resume}: cloned repo at {cloned} is missing. "
                f"It was deleted between runs. Pick a fresh --run-name to "
                f"re-clone, or restore the directory before resuming."
            )

    if args.instruction is None:
        args.instruction = state.get("instruction")
    if state.get("local_sources"):
        args.local_sources = state.get("local_sources")
    if state.get("diff_scope"):
        args.diff_scope = state.get("diff_scope")
    if not getattr(args, "custom_headers", None):
        args.custom_headers = state.get("custom_headers") or []


def display_completion_message(args: argparse.Namespace, results_path: Path) -> None:
    console = Console()
    report_state = get_global_report_state()

    scan_completed = False
    if report_state:
        scan_completed = report_state.run_record.get("status") == "completed"

    completion_text = Text()
    if scan_completed:
        completion_text.append("Penetration test completed", style="bold #22c55e")
    else:
        completion_text.append("SESSION ENDED", style="bold #eab308")

    target_text = Text()
    target_text.append("Target", style="dim")
    target_text.append("  ")
    if len(args.targets_info) == 1:
        target_text.append(args.targets_info[0]["original"], style="bold white")
    else:
        target_text.append(f"{len(args.targets_info)} targets", style="bold white")
        for target_info in args.targets_info:
            target_text.append("\n        ")
            target_text.append(target_info["original"], style="white")

    stats_text = build_final_stats_text(report_state)

    panel_parts: list[Text | str] = [completion_text, "\n\n", target_text]

    if stats_text.plain:
        panel_parts.extend(["\n", stats_text])

    results_text = Text()
    results_text.append("\n")
    results_text.append("Output", style="dim")
    results_text.append("  ")
    results_text.append(str(results_path), style="#60a5fa")
    panel_parts.extend(["\n", results_text])

    if not scan_completed:
        resume_text = Text()
        resume_text.append("\n")
        resume_text.append("Resume", style="dim")
        resume_text.append("  ")
        resume_text.append(f"prometheus --resume {args.run_name}", style="#22c55e")
        panel_parts.extend(["\n", resume_text])

    panel_content = Text.assemble(*panel_parts)

    border_style = "#22c55e" if scan_completed else "#eab308"

    panel = Panel(
        panel_content,
        title="[bold white]prometheus",
        title_align="left",
        border_style=border_style,
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()
    console.print("[#60a5fa]prometheus[/]")
    console.print()


def pull_docker_image() -> None:
    console = Console()
    client = check_docker_connection()

    image = load_settings().runtime.image

    if image_exists(client, image):
        logger.debug("Docker image already present locally: %s", image)
        return

    logger.info("Pulling docker image: %s", image)
    console.print()
    console.print(f"[dim]Pulling image[/] {image}")
    console.print("[dim yellow]This only happens on first run and may take a few minutes...[/]")
    console.print()

    with console.status("[bold cyan]Downloading image layers...", spinner="dots") as status:
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            for line in client.api.pull(image, stream=True, decode=True):
                last_update = process_pull_line(line, layers_info, status, last_update)

        except DockerException as e:
            logger.exception("Failed to pull docker image %s", image)
            console.print()
            error_text = Text()
            error_text.append("FAILED TO PULL IMAGE", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(f"Could not download: {image}\n", style="white")
            error_text.append(str(e), style="dim red")

            panel = Panel(
                error_text,
                title="[bold white]prometheus",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print(panel, "\n")
            sys.exit(1)

    logger.info("Docker image %s ready", image)
    success_text = Text()
    success_text.append("Docker image ready", style="#22c55e")
    console.print(success_text)
    console.print()


def _load_scans_file(path: str) -> list[dict[str, Any]]:
    """Load scan definitions from a JSON file.

    Expected format:
    [
        {
            "name": "OpenSea",
            "targets": ["https://opensea.io", "https://wallet.opensea.io"],
            "instruction": "Focus on auth vulnerabilities",
            "instruction_file": "/path/to/file.txt",
            "mode": "deep",
            "headers": ["Authorization: Bearer xxx"]
        },
        {
            "name": "eToro",
            "targets": ["https://sts.etoro.com", "https://kyc.etoro.com"],
            "instruction_file": "/tmp/etoro-instructions.txt",
            "mode": "deep"
        }
    ]

    All fields except "targets" are optional. Defaults:
    - name: derived from first target domain
    - mode: "deep"
    - instruction: none
    - headers: []
    """
    import json as json_mod
    from pathlib import Path

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Scans file not found: {path}")

    with p.open(encoding="utf-8") as f:
        data = json_mod.load(f)

    if not isinstance(data, list):
        raise ValueError("Scans file must be a JSON array of scan objects")

    scans = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise ValueError(f"Scan entry {i} must be an object")
        if "targets" not in entry or not entry["targets"]:
            raise ValueError(f"Scan entry {i} missing 'targets'")

        # Resolve instruction from file if specified
        instruction = entry.get("instruction", "")
        if entry.get("instruction_file"):
            instr_path = Path(entry["instruction_file"])
            if instr_path.exists():
                instruction = instr_path.read_text(encoding="utf-8").strip()

        scans.append(
            {
                "name": entry.get("name") or entry["targets"][0].split("//")[-1].split("/")[0],
                "targets": entry["targets"],
                "instruction": instruction,
                "mode": entry.get("mode", "deep"),
                "headers": entry.get("headers", []),
            }
        )

    return scans


def main() -> None:
    configure_dependency_logging()

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    # Dispatch `prometheus model` before parse_arguments, which expects scan flags
    if len(sys.argv) > 1 and sys.argv[1] == "model":
        from prometheus.interface.model_cli import run_model_cli

        run_model_cli(sys.argv[2:])
        return

    # Dispatch `prometheus xbow` to the XBOW validation-benchmarks
    # harness. Subcommands: list, run, report.
    if len(sys.argv) > 1 and sys.argv[1] == "xbow":
        from prometheus.eval.xbow.runner import main as xbow_main

        # ``sys.exit`` returns the exit code; ``xbow_main`` returns an
        # int, so we forward it directly. The trailing ``return`` is
        # unreachable but kept for symmetry with the model dispatch
        # above.
        rc = xbow_main(sys.argv[2:])
        sys.exit(rc)
        return

    # Dispatch `prometheus realvuln` to the RealVuln-Benchmark harness.
    # Subcommands: list, run, report, score.
    if len(sys.argv) > 1 and sys.argv[1] == "realvuln":
        from prometheus.eval.realvuln.runner import main as realvuln_main

        sys.exit(realvuln_main(sys.argv[2:]))
        return

    args = parse_arguments()

    # Apply rate limit from CLI flag
    if args.rate_limit >= 0:
        set_rate(args.rate_limit)

    if args.config:
        apply_config_override(validate_config_file(args.config))

    check_docker_installed()
    pull_docker_image()

    validate_environment()
    asyncio.run(warm_up_llm())

    persist_current()

    # Initialise the multi-scan orchestrator singleton so it's
    # available to any code that imports it later.
    from prometheus.core.orchestrator import ScanOrchestrator

    ScanOrchestrator()

    # Handle --scans-file: register targets and launch parallel scans
    if args.scans_file:
        import time as _time

        from prometheus.core.comms import get_status_summary
        from prometheus.core.target_registry import TargetRegistry

        scans = _load_scans_file(args.scans_file)

        console = Console()
        console.print(f"\n[bold green]Loaded {len(scans)} scans from {args.scans_file}[/]")

        registry = TargetRegistry()
        target_ids = []

        for scan in scans:
            targets_list = []
            for target in scan["targets"]:
                target_type, target_dict = infer_target_type(target)
                targets_list.append(
                    {
                        "type": target_type,
                        "details": target_dict,
                        "original": target,
                    }
                )

            scan_config = {
                "targets": targets_list,
                "user_instructions": scan["instruction"],
                "custom_headers": scan["headers"],
            }

            domain = scan["targets"][0].split("//")[-1].split("/")[0]

            result = registry.add_target(
                domain=domain,
                target_type="url",
                target_config={
                    "display_name": scan["name"],
                    "all_targets": scan["targets"],
                    "targets_list": targets_list,
                },
                scan_config=scan_config,
            )
            target_ids.append((result["id"], scan["name"], len(scan["targets"])))
            console.print(
                f"  [green]+[/] Registered: [cyan]{scan['name']}[/] -- {len(scan['targets'])} targets"
            )

        console.print(f"\n[bold]Launching {len(target_ids)} scans via orchestrator...[/]")

        orchestrator = ScanOrchestrator()
        scan_map = {}  # scan_id -> (target_id, name)

        for target_id, name, _count in target_ids:
            if orchestrator.get_scan_for_target(target_id) is not None:
                console.print(f"  [yellow]~[/] {name}: already has active scan, skipping")
                continue
            active, max_c = orchestrator.get_capacity()
            if active >= max_c:
                console.print(
                    f"  [yellow]![/] {name}: at capacity ({active}/{max_c}), queuing not yet implemented"
                )
                continue
            try:
                scan_id = orchestrator.launch_scan(target_id)
                scan_map[scan_id] = (target_id, name)
                console.print(f"  [green]>[/] {name}: launched [dim]{scan_id}[/]")
            except Exception as exc:
                console.print(f"  [red]x[/] {name}: launch failed -- {exc}")

        if not scan_map:
            console.print("[red]No scans launched. Check config and try again.[/]")
            sys.exit(1)

        console.print(f"\n[bold]{len(scan_map)} scan(s) running. Monitoring...[/]\n")
        console.print("[dim]Press Ctrl+C to stop all scans and exit.[/]\n")

        # Signal handling: graceful shutdown on Ctrl+C / SIGTERM
        import signal as _signal

        _shutdown_requested = threading.Event()

        def _signal_handler(signum, _frame):
            if not _shutdown_requested.is_set():
                _shutdown_requested.set()
                console.print("\n[yellow]Shutdown requested. Stopping scans...[/]")
                orchestrator.shutdown_all()
            else:
                console.print("[red]Forcing exit.[/]")
                sys.exit(1)

        _prev_sigint = _signal.signal(_signal.SIGINT, _signal_handler)
        _prev_sigterm = _signal.signal(_signal.SIGTERM, _signal_handler)

        # Cleanup on exit: stop scans + orphan container cleanup
        def _cleanup():
            orchestrator.shutdown_all()
            # Kill any orphaned prometheus sandbox containers
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
                    logger.info("Cleaned up %d orphaned containers", len(container_ids))
            except Exception:
                logger.debug("Container cleanup failed", exc_info=True)

        atexit.register(_cleanup)

        # Monitor loop: poll orchestrator status + comms events

        last_event_line = dict.fromkeys(scan_map, 0)

        while not _shutdown_requested.is_set():
            all_done = True
            status_lines = []

            for scan_id, (target_id, name) in scan_map.items():
                instance = orchestrator.get_scan(scan_id)
                if instance is None:
                    status_lines.append(f"  {name}: [dim]unknown[/]")
                    continue

                status = instance.status
                findings = (
                    len(instance.report_state.vulnerability_reports) if instance.report_state else 0
                )

                if status == "running":
                    all_done = False
                    status_icon = "[cyan]*[/]"
                elif status == "starting":
                    all_done = False
                    status_icon = "[yellow]~[/]"
                elif status == "completed":
                    status_icon = "[green]ok[/]"
                elif status == "failed":
                    status_icon = "[red]FAIL[/]"
                else:
                    status_icon = f"[dim]{status}[/]"

                err_suffix = f" -- {instance.error[:80]}" if instance.error else ""
                status_lines.append(
                    f"  {status_icon} {name}: {status} | findings={findings}{err_suffix}"
                )

                # Print new comms events for this scan
                try:
                    comms_summary = get_status_summary(scan_id)
                    events = comms_summary.get("recent_events", [])
                    prev = last_event_line.get(scan_id, 0)
                    if len(events) > prev:
                        for evt in events[prev:]:
                            etype = evt.get("type", "?")
                            edata = evt.get("data", {})
                            if etype == "finding":
                                sev = edata.get("severity", "?")
                                title = edata.get("title", edata.get("description", "?"))
                                console.print(f"  [bold red]VULN[/] [{sev}] {name}: {title}")
                            elif etype == "scan_start":
                                console.print(f"  [dim]{name}: scan started[/]")
                            elif etype == "scan_complete":
                                console.print(f"  [green]{name}: scan complete[/]")
                            elif etype == "tool_call":
                                cmd = str(edata.get("command", ""))[:80]
                                console.print(f"  [dim]{name}: tool: {cmd}[/]")
                        last_event_line[scan_id] = len(events)
                except Exception:
                    logger.debug("scan event tail failed for %s, ignoring", scan_id, exc_info=True)

            # Print status panel
            panel_text = "\n".join(status_lines)
            console.print(
                Panel(
                    panel_text,
                    title="[bold white]SCAN STATUS",
                    title_align="left",
                    border_style="#60a5fa",
                    padding=(0, 1),
                )
            )

            if all_done:
                break

            _time.sleep(5)

        # Restore signal handlers
        _signal.signal(_signal.SIGINT, _prev_sigint)
        _signal.signal(_signal.SIGTERM, _prev_sigterm)

        # FIX: Wait for scan threads to complete before exiting.
        # Python's threading._register_atexit runs _python_exit() which
        # shuts down ALL ThreadPoolExecutor instances (including
        # _DOCKER_EXECUTOR) before joining non-daemon threads. If scan
        # threads are still running cleanup, they crash with:
        #   RuntimeError: cannot schedule new futures after shutdown
        # Solution: explicitly shut down scans and wait for threads here,
        # BEFORE the interpreter exits.
        with contextlib.suppress(Exception):
            orchestrator.shutdown_all()

        # Final summary
        console.print("\n[bold]All scans finished.[/]\n")
        for scan_id, (target_id, name) in scan_map.items():
            instance = orchestrator.get_scan(scan_id)
            if instance is None:
                continue
            findings = (
                len(instance.report_state.vulnerability_reports) if instance.report_state else 0
            )
            status = instance.status
            style = "green" if status == "completed" else "red" if status == "failed" else "yellow"
            console.print(f"  [{style}]{status.upper()}[/] {name}: {findings} finding(s)")
            if instance.error:
                console.print(f"    [dim red]Error: {instance.error}[/]")

        # Set run_name for display_completion_message
        args.run_name = f"multi-scan-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"
        args.targets_info = []
        for scan_id, (target_id, name) in scan_map.items():
            args.targets_info.append({"original": name, "type": "url", "details": {}})

        console.print()
        return

    args.run_name = args.resume or generate_run_name(args.targets_info)

    if not args.resume:
        for target_info in args.targets_info:
            if target_info["type"] == "repository":
                repo_url = target_info["details"]["target_repo"]
                dest_name = target_info["details"].get("workspace_subdir")
                cloned_path = clone_repository(repo_url, args.run_name, dest_name)
                target_info["details"]["cloned_repo_path"] = cloned_path

        args.local_sources = collect_local_sources(args.targets_info)
        try:
            diff_scope = resolve_diff_scope_context(
                local_sources=args.local_sources,
                scope_mode=args.scope_mode,
                diff_base=args.diff_base,
                non_interactive=args.non_interactive,
            )
        except ValueError as e:
            console = Console()
            error_text = Text()
            error_text.append("DIFF SCOPE RESOLUTION FAILED", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(str(e), style="white")

            panel = Panel(
                error_text,
                title="[bold white]prometheus",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print("\n")
            console.print(panel)
            console.print()
            sys.exit(1)

        args.diff_scope = diff_scope.metadata
        if diff_scope.instruction_block:
            if args.instruction:
                args.instruction = f"{diff_scope.instruction_block}\n\n{args.instruction}"
            else:
                args.instruction = diff_scope.instruction_block

        _persist_run_record(args)

    # Browser prescan is now deferred to the TUI/CLI layer so the UI
    # appears immediately. It runs inside _start_scan_thread() for TUI
    # mode or inside run_cli() for non-interactive mode — both call
    # run_browser_prescan as the first step before the Docker sandbox scan.

    _telemetry_start_kwargs = {
        "model": load_settings().llm.model,
        "is_whitebox": is_whitebox_scan(args.targets_info),
        "interactive": not args.non_interactive,
        "has_instructions": bool(args.instruction),
    }
    posthog.start(**_telemetry_start_kwargs)
    scarf.start(**_telemetry_start_kwargs)

    exit_reason = "user_exit"
    try:
        if args.non_interactive:
            asyncio.run(run_cli(args))
        else:
            asyncio.run(run_tui(args))
    except KeyboardInterrupt:
        exit_reason = "interrupted"
    except Exception as e:
        exit_reason = "error"
        posthog.error("unhandled_exception", str(e))
        scarf.error("unhandled_exception", str(e))
        raise
    finally:
        report_state = get_global_report_state()
        if report_state:
            status = {"interrupted": "interrupted", "error": "failed"}.get(
                exit_reason,
                "stopped",
            )
            report_state.cleanup(status=status)
            posthog.end(report_state, exit_reason=exit_reason)
            scarf.end(report_state, exit_reason=exit_reason)

    results_path = run_dir_for(args.run_name)
    display_completion_message(args, results_path)

    if args.non_interactive:
        report_state = get_global_report_state()
        if report_state and report_state.vulnerability_reports:
            sys.exit(2)

    # Force exit: daemon threads and atexit handlers may still be running.
    # os._exit bypasses Python's finalization to guarantee a clean quit.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
