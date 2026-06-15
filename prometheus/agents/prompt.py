"""Jinja-based system-prompt renderer."""

from __future__ import annotations

import logging
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from prometheus.skills import get_available_skills, load_skills
from prometheus.utils.resource_paths import get_prometheus_resource_path


logger = logging.getLogger(__name__)


_PROMPT_DIRNAME = "prompts"


def _resolve_skills(
    *,
    requested: list[str] | None,
    is_whitebox: bool = False,
    is_root: bool = False,
    compress: bool = False,
) -> list[str]:
    """Build the deduped, ordered skills list for the prompt render.

    Order:

    1. Whatever the caller asked for, in order.
    2. ``tooling/agent_browser`` (always — every agent has shell + the
       agent-browser CLI).
    3. ``tooling/browser_harness`` (always — required for the agent-browser).
    4. ``tooling/python`` (always — Python runs through ``exec_command``;
       sandbox scripts can import ``caido_api`` for Caido automation).
    5. ``coordination/root_agent`` for the root agent only — orchestration
       guidance for delegating to specialist subagents.
    6. Whitebox-specific skills if applicable.

    Phase 3: When ``compress`` is True, only load essential skills
    (tooling, coordination). Vulnerability skills are skipped and can
    be loaded on-demand via the ``load_skill`` tool.
    """
    # Essential skills that are always loaded
    _ESSENTIAL_SKILLS = {
        "tooling",
        "coordination",
        "custom",
    }

    ordered: list[str] = list(requested or [])

    if compress:
        # Phase 3: Only load essential skills, skip vulnerability skills
        # Build a lookup of skill name -> category
        skills_dir = get_prometheus_resource_path("skills")
        skill_categories: dict[str, str] = {}
        if skills_dir.exists():
            for category_dir in skills_dir.iterdir():
                if not category_dir.is_dir() or category_dir.name.startswith("__"):
                    continue
                for file_path in category_dir.glob("*.md"):
                    skill_categories[file_path.stem] = category_dir.name

        filtered: list[str] = []
        for skill in ordered:
            # Check category from prefix or from lookup
            category = skill.split("/")[0] if "/" in skill else ""
            if not category:
                category = skill_categories.get(skill, "")
            if category in _ESSENTIAL_SKILLS or not category:
                filtered.append(skill)
        ordered = filtered

    ordered.append("tooling/agent_browser")
    ordered.append("tooling/browser_harness")
    ordered.append("tooling/python")
    if is_root:
        ordered.append("coordination/root_agent")
    if is_whitebox:
        ordered.append("coordination/source_aware_whitebox")
        ordered.append("custom/source_aware_sast")

    deduped: list[str] = []
    seen: set[str] = set()
    for skill in ordered:
        if skill and skill not in seen:
            deduped.append(skill)
            seen.add(skill)
    return deduped


def render_system_prompt(
    *,
    skills: list[str] | None = None,
    is_whitebox: bool = False,
    is_root: bool = False,
    interactive: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
    compress: bool = False,
) -> str:
    """Render the system prompt. Returns empty string on template failure."""
    try:
        prompt_dir = get_prometheus_resource_path("agents", _PROMPT_DIRNAME)
        skills_dir = get_prometheus_resource_path("skills")
        env = Environment(
            loader=FileSystemLoader([prompt_dir, skills_dir]),
            autoescape=select_autoescape(
                enabled_extensions=(),
                default_for_string=False,
            ),
        )

        skills_to_load = _resolve_skills(
            requested=skills,
            is_whitebox=is_whitebox,
            is_root=is_root,
            compress=compress,
        )
        skill_content = load_skills(skills_to_load)
        env.globals["get_skill"] = lambda name: skill_content.get(name, "")

        rendered = env.get_template("system_prompt.jinja").render(
            loaded_skill_names=list(skill_content.keys()),
            available_skills=get_available_skills(),
            interactive=interactive,
            is_root=is_root,
            system_prompt_context=system_prompt_context or {},
            **skill_content,
        )
    except Exception:
        logger.exception("render_system_prompt failed")
        raise
    else:
        logger.debug(
            "render_system_prompt: root=%s whitebox=%s skills=%d prompt_len=%d",
            is_root,
            is_whitebox,
            len(skill_content),
            len(rendered),
        )
        return str(rendered)
