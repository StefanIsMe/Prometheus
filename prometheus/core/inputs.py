"""Pure input builders for prometheus scan runs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agents.model_settings import ModelSettings
from openai.types.shared import Reasoning

from prometheus.config.models import DEFAULT_MODEL_RETRY


if TYPE_CHECKING:
    from prometheus.config.settings import ReasoningEffort


DEFAULT_MAX_TURNS = 100  # root agent: pipeline handles mechanical work, 100 turns is generous


def build_root_task(
    scan_config: dict[str, Any],
    *,
    is_rescan: bool = False,
    targets_with_knowledge: set[str] | None = None,
) -> str:
    targets = scan_config.get("targets", []) or []
    diff_scope = scan_config.get("diff_scope") or {}
    user_instructions = scan_config.get("user_instructions", "") or ""

    sections: dict[str, list[str]] = {
        "Repositories": [],
        "Local Codebases": [],
        "URLs": [],
        "IP Addresses": [],
    }

    for target in targets:
        ttype = target.get("type")
        details = target.get("details") or {}
        workspace_subdir = details.get("workspace_subdir")
        workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

        if ttype == "repository":
            url = details.get("target_repo", "")
            cloned = details.get("cloned_repo_path")
            sections["Repositories"].append(
                f"- {url} (available at: {workspace_path})" if cloned else f"- {url}",
            )
        elif ttype == "local_code":
            path = details.get("target_path", "unknown")
            sections["Local Codebases"].append(f"- {path} (available at: {workspace_path})")
        elif ttype == "web_application":
            sections["URLs"].append(f"- {details.get('target_url', '')}")
        elif ttype == "ip_address":
            sections["IP Addresses"].append(f"- {details.get('target_ip', '')}")

    parts: list[str] = []
    for label, items in sections.items():
        if items:
            parts.append(f"\n\n{label}:")
            parts.extend(items)

    if diff_scope.get("active"):
        parts.append("\n\nScope Constraints:")
        parts.append(
            "- Pull request diff-scope mode is active. Prioritize changed files "
            "and use other files only for context.",
        )
        for repo_scope in diff_scope.get("repos", []) or []:
            label = (
                repo_scope.get("workspace_subdir") or repo_scope.get("source_path") or "repository"
            )
            changed = repo_scope.get("analyzable_files_count", 0)
            deleted = repo_scope.get("deleted_files_count", 0)
            parts.append(f"- {label}: {changed} changed file(s) in primary scope")
            if deleted:
                parts.append(f"- {label}: {deleted} deleted file(s) are context-only")

    task = " ".join(parts)
    if user_instructions:
        task = f"{task}\n\nSpecial instructions: {user_instructions}"

    custom_headers = scan_config.get("custom_headers", [])
    if custom_headers:
        header_list = "\n".join(f"  - {h}" for h in custom_headers)
        task = f"{task}\n\nRequired HTTP headers (MUST be included in ALL requests):\n{header_list}"

    # Build per-target recon strategy when targets_with_knowledge is provided.
    # Avoids blanket "do not re-crawl" when only SOME targets have prior knowledge.
    known_targets: set[str] = targets_with_knowledge or set()
    all_targets: list[str] = [
        t.get("details", {}).get("target_url", "")
        or t.get("details", {}).get("target_repo", "")
        or t.get("original", "")
        for t in targets
    ]
    all_targets = [u for u in all_targets if u]
    unknown_targets = [u for u in all_targets if u not in known_targets]

    if is_rescan and targets_with_knowledge is not None and known_targets and unknown_targets:
        # Mixed: some targets have prior knowledge, some don't
        known_list = "\n".join(f"  - {u}" for u in all_targets if u in known_targets)
        unknown_list = "\n".join(f"  - {u}" for u in unknown_targets)
        threat_directive = f"""\
Mixed prior-knowledge directives:
- {len(known_targets)} target(s) have prior knowledge from previous scans. For these targets, use the injected knowledge — do NOT re-fingerprint or re-crawl unless content has likely changed. Validate previous findings with exact requests, promote unassessed knowledge entries.
- {len(unknown_targets)} target(s) are NEW (no prior knowledge). For these targets, do FULL first-scan recon: fingerprint the tech stack, crawl for endpoints, analyze CSP/headers, extract JS bundles, map the attack surface.

TARGETS WITH PRIOR KNOWLEDGE (use rescan efficiency):
{known_list}

TARGETS WITHOUT PRIOR KNOWLEDGE (do full first-scan recon):
{unknown_list}

- After recon, run query_threat_feeds for ALL detected technologies across ALL targets.
- A finding is not reportable until a working PoC proves real security impact.
- When you think you found a threat, convert it into a real PoC before reporting. Execute or otherwise live-verify the PoC and include the exact request/response evidence.

HARD STOP — The following are NEVER reportable: server header version disclosure, missing security headers without exploit chain, technology fingerprinting, any finding where the PoC ends at "I observed version X", any CVSS 0.0 finding.
Before calling create_vulnerability_report: (1) Does the PoC show actual harm? (2) Is CVSS > 0.0? (3) Would H1 mark this "informational"? If any answer is NO, do NOT report.
""".strip()
    elif is_rescan:
        threat_directive = """\
Mandatory rescan directives:
- You already have a complete target profile, prior knowledge entries, and previous findings injected above. Use them. Do NOT re-discover what is already known.
- Before making ANY LLM API call, check if the information already exists in the injected knowledge. If yes, use the knowledge directly — no LLM call needed.
- Run deterministic tools first: nuclei templates, local threat intel DB queries, HTTP response fingerprinting via shell scripts. Only use the LLM after exhausting offline options.
- For each previous finding: send the exact request from the finding evidence, verify the response matches, mark as "validated" or "fixed".
- For each unassessed knowledge entry: build a minimal PoC, then file it as a formal finding with evidence.
- Token efficiency: target 40% or fewer tokens than a first scan. If you exceed this, you are re-doing work that was already done.
- Do NOT re-fingerprint the tech stack. Use the tech_stack entries from prior knowledge.
- Do NOT re-crawl the site unless you have specific reason to believe content changed.
- Finished means: all previous findings validated + all unassessed knowledge promoted or dismissed + any new attack surface checked. Not before.
""".strip()
    else:
        threat_directive = """\
Mandatory scan directives:
- Before vulnerability testing, fingerprint the target technologies and call query_threat_feeds with every detected technology/version. Use CISA KEV, NVD, OSV.dev, GHSA, Exploit-DB/nuclei knowledge, and any available local security feed.
- During discovery, actively look for known security threats mapped to the target stack, not just generic headers or banners.
- Also look for novel target-specific security threats: broken business logic, authorization model gaps, trust-boundary mistakes, unsafe agent/MCP/tool flows, unexpected API state transitions, cache/proxy edge cases, and exploit chains that are not tied to a published CVE.
- Web search is capped: use at most 3 web_search calls per concrete attack idea. After that, stop researching that idea and test it against the target.
- A finding is not reportable until a working PoC proves real security impact. Reconnaissance, version disclosure, missing headers, reflected CORS, or discovered secrets are not enough unless you use them to access data, perform an unauthorized action, execute code, or otherwise prove impact.
- When you think you found a threat, convert it into a real PoC before reporting. Execute or otherwise live-verify the PoC and include the exact request/response evidence.

HARD STOP — The following are NEVER reportable as findings. Do NOT call create_vulnerability_report for them. Do NOT mention them in your response as findings:
- Server header version disclosure (nginx, Apache, Cloudflare, etc.) — this is reconnaissance, not a vuln
- Missing security headers (CSP, X-Frame-Options, HSTS) without a proven exploit chain
- Technology fingerprinting or banner grabbing with no demonstrated impact
- Any finding where the PoC ends at "I observed version X in the response" — PoC must show HARM
- Any finding with CVSS score 0.0 (all CIA metrics are None)

Before calling create_vulnerability_report, answer these three questions internally. If the answer to ANY is NO, do NOT call the tool:
1. Did I prove this with a working PoC that shows actual harm (data accessed, action performed, code executed)?
2. Is the CVSS score greater than 0.0 (at least one CIA metric is Low or higher)?
3. Would a HackerOne triager mark this as "informational" or "not applicable"? If yes, discard it.
""".strip()
    task = f"{threat_directive}\n\n{task}"

    return task


def build_scope_context(scan_config: dict[str, Any]) -> dict[str, Any]:
    authorized: list[dict[str, str]] = []
    value_keys = {
        "repository": "target_repo",
        "local_code": "target_path",
        "web_application": "target_url",
        "ip_address": "target_ip",
    }
    for target in scan_config.get("targets", []) or []:
        ttype = target.get("type", "unknown")
        details = target.get("details") or {}
        key = value_keys.get(ttype)
        value = details.get(key, "") if key is not None else target.get("original", "")

        workspace_subdir = details.get("workspace_subdir")
        workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else ""
        authorized.append(
            {"type": ttype, "value": value, "workspace_path": workspace_path},
        )

    return {
        "scope_source": "system_scan_config",
        "authorization_source": "prometheus_platform_verified_targets",
        "authorized_targets": authorized,
        "user_instructions_do_not_expand_scope": True,
        "custom_headers": scan_config.get("custom_headers", []),
    }


def make_model_settings(
    reasoning_effort: ReasoningEffort | None,
    *,
    store: bool = False,
    supports_thinking: bool = False,
    provider_name: str = "",
    model_id: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> ModelSettings:
    # DeepSeek rejects tool_choice when thinking mode is active.
    # Thinking mode is triggered by either supports_thinking flag OR
    # reasoning_effort being set (the default is "xhigh").
    # Omit tool_choice for those providers so SDK defaults to "auto".
    from prometheus.config.llm_config import _THINKING_NO_TOOL_CHOICE_PROVIDERS

    # Phase 3C: centralised model-id-driven overrides. The audit found
    # four configuration drift bugs (``max_output_tokens`` rejection,
    # ``store=true`` vs ``store=false`` mismatches, "Item with id … not
    # found" store persistence, and ``thinking + tool_choice`` rejections
    # on extra provider ids). Routing them through a single per-model
    # dict keeps future drift in one place.
    from prometheus.config.model_options import resolve_model_options

    overrides = resolve_model_options(model_id, provider_name=provider_name)

    _tool_choice: str | None = "required"
    _reasoning_active = supports_thinking or (
        reasoning_effort is not None and reasoning_effort != "none"
    )
    if _reasoning_active and (
        provider_name.lower() in _THINKING_NO_TOOL_CHOICE_PROVIDERS
        or overrides.drop_tool_choice_with_thinking
    ):
        _tool_choice = None

    # Phase 3C: force ``store=False`` for ALL multi-turn Responses runs.
    # The audit found 2 cases where the SDK persisted responses and the
    # provider then rejected subsequent turns with "Item with id … not
    # found" because the persisted item was no longer available.
    effective_store = False if overrides.force_store_false else store

    model_settings = ModelSettings(
        parallel_tool_calls=False,
        tool_choice=_tool_choice,
        retry=DEFAULT_MODEL_RETRY,
        include_usage=True,
        store=effective_store,
        extra_headers=extra_headers or None,
        **(overrides.extra_body_passthrough or {}),
    )
    if reasoning_effort is not None and not overrides.drop_reasoning_field:
        model_settings = model_settings.resolve(
            ModelSettings(reasoning=Reasoning(effort=reasoning_effort)),
        )
    return model_settings


def child_initial_input(
    *,
    name: str,
    child_id: str,
    parent_id: str,
    task: str,
) -> list[dict[str, Any]]:
    initial_input: list[dict[str, Any]] = []
    initial_input.append(
        {
            "role": "user",
            "content": (
                f"You are agent {name} ({child_id}); your parent is {parent_id}. "
                "Maintain your own identity. Call agent_finish when your task "
                "is complete."
            ),
        }
    )
    initial_input.append({"role": "user", "content": task})
    return initial_input
