"""Skill self-improvement — agent-facing tools for creating and updating custom skills."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from prometheus.utils.resource_paths import get_prometheus_resource_path


logger = logging.getLogger(__name__)

_CUSTOM_SKILLS_DIR = get_prometheus_resource_path("skills") / "custom"
_SKILL_NAME_RE = re.compile(r"^[a-z][a-z0-9-]*$")
_SUGGESTIONS_PATH = Path.home() / ".prometheus" / "skill_suggestions.json"
_suggestions_lock = threading.Lock()


def _ensure_custom_dir() -> None:
    """Create the custom skills directory if it doesn't exist."""
    _CUSTOM_SKILLS_DIR.mkdir(parents=True, exist_ok=True)


def _validate_skill_name(name: str) -> str | None:
    """Return an error message if the name is invalid, else None."""
    if not name or not name.strip():
        return "Skill name cannot be empty."
    if not _SKILL_NAME_RE.match(name):
        return (
            f"Invalid skill name '{name}'. "
            "Names must be lowercase, start with a letter, and contain only "
            "lowercase letters, digits, and hyphens (no spaces)."
        )
    return None


def _build_frontmatter(name: str, description: str) -> str:
    """Build YAML frontmatter for a skill file."""
    return f"---\nname: {name}\ndescription: {description}\n---\n\n"


def _parse_frontmatter(content: str) -> dict[str, str]:
    """Extract name and description from YAML frontmatter."""
    result: dict[str, str] = {}
    if not content.startswith("---"):
        return result
    end = content.find("---", 3)
    if end == -1:
        return result
    for line in content[3:end].strip().splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            result[key.strip()] = value.strip()
    return result


def _create_custom_skill_impl(
    name: str,
    description: str,
    content: str,
) -> dict[str, Any]:
    _ensure_custom_dir()
    err = _validate_skill_name(name)
    if err:
        return {"success": False, "error": err}

    skill_path = _CUSTOM_SKILLS_DIR / f"{name}.md"
    if skill_path.exists():
        return {
            "success": False,
            "error": f"Skill '{name}' already exists. Use update_custom_skill to modify it.",
        }

    body = _build_frontmatter(name, description) + content.lstrip("\n")
    skill_path.write_text(body, encoding="utf-8")
    logger.info("Created custom skill: %s", skill_path)
    return {
        "success": True,
        "message": f"Custom skill '{name}' created at prometheus/skills/custom/{name}.md",
        "path": str(skill_path),
    }


def _update_custom_skill_impl(
    name: str,
    new_content: str,
    append: bool,
) -> dict[str, Any]:
    _ensure_custom_dir()
    err = _validate_skill_name(name)
    if err:
        return {"success": False, "error": err}

    skill_path = _CUSTOM_SKILLS_DIR / f"{name}.md"
    if not skill_path.exists():
        return {
            "success": False,
            "error": f"Custom skill '{name}' not found at {skill_path}. Use create_custom_skill to create it.",
        }

    existing = skill_path.read_text(encoding="utf-8")

    if append:
        updated = existing.rstrip("\n") + "\n\n" + new_content.lstrip("\n")
    # Preserve frontmatter, replace body
    elif existing.startswith("---"):
        end = existing.find("---", 3)
        if end != -1:
            frontmatter = existing[: end + 3]
            updated = frontmatter + "\n\n" + new_content.lstrip("\n")
        else:
            updated = new_content
    else:
        updated = new_content

    skill_path.write_text(updated, encoding="utf-8")
    logger.info("Updated custom skill: %s (append=%s)", skill_path, append)
    return {
        "success": True,
        "message": f"Custom skill '{name}' {'appended to' if append else 'replaced'} successfully.",
        "path": str(skill_path),
    }


def _list_custom_skills_impl() -> dict[str, Any]:
    _ensure_custom_dir()
    skills: list[dict[str, str]] = []
    for skill_file in sorted(_CUSTOM_SKILLS_DIR.glob("*.md")):
        try:
            content = skill_file.read_text(encoding="utf-8")
        except (OSError, ValueError):
            logger.debug("Failed to read custom skill file %s", skill_file, exc_info=True)
            continue
        meta = _parse_frontmatter(content)
        mtime = datetime.fromtimestamp(skill_file.stat().st_mtime, tz=UTC).isoformat()
        skills.append(
            {
                "name": skill_file.stem,
                "description": meta.get("description", ""),
                "last_modified": mtime,
            }
        )
    return {"success": True, "skills": skills, "count": len(skills)}


def _suggest_skill_update_impl(
    skill_name: str,
    observation: str,
    technique: str,
) -> dict[str, Any]:
    _SUGGESTIONS_PATH.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "skill_name": skill_name,
        "observation": observation,
        "technique": technique,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    with _suggestions_lock:
        suggestions: list[dict[str, Any]] = []
        if _SUGGESTIONS_PATH.exists():
            try:
                suggestions = json.loads(_SUGGESTIONS_PATH.read_text(encoding="utf-8"))
                if not isinstance(suggestions, list):
                    suggestions = []
            except (json.JSONDecodeError, OSError):
                logger.debug("Failed to read skill suggestions file; starting fresh", exc_info=True)
                suggestions = []
        suggestions.append(entry)
        _SUGGESTIONS_PATH.write_text(
            json.dumps(suggestions, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    logger.info("Skill suggestion logged: %s — %s", skill_name, observation[:80])
    return {
        "success": True,
        "message": (
            f"Suggestion for skill '{skill_name}' logged. "
            f"Stored at {_SUGGESTIONS_PATH}. "
            f"Review with list_custom_skills and apply with update_custom_skill when ready."
        ),
        "suggestion_count": len(suggestions),
    }


# ---------------------------------------------------------------------------
# Agent-facing function tools
# ---------------------------------------------------------------------------


@function_tool(timeout=30)
async def create_custom_skill(
    ctx: RunContextWrapper,
    name: str,
    description: str,
    content: str,
) -> str:
    """Create a new custom skill file.

    Skills are markdown files that the agent (and future scans) can load
    via ``load_skill``.  Custom skills live under ``prometheus/skills/custom/``
    and are **never** mixed with built-in skills.

    Use this when you discover a new technique, bypass, or payload that
    works and want to save it permanently for future scans.

    Args:
        name: Skill identifier — lowercase, hyphens only (e.g.
            ``custom-sqli-bypass``).  No spaces or uppercase.
        description: One-line summary shown in skill listings.
        content: Full markdown body of the skill (tips, payloads,
            workflow steps, etc.).
    """
    return json.dumps(
        await asyncio.to_thread(_create_custom_skill_impl, name, description, content),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def update_custom_skill(
    ctx: RunContextWrapper,
    name: str,
    new_content: str,
    append: bool = False,
) -> str:
    """Update an existing custom skill file.

    Only skills in the ``custom`` category may be modified — built-in
    skills are read-only.

    Args:
        name: Skill identifier (must already exist in ``custom/``).
        new_content: Replacement or appended markdown content.
        append: If ``True``, ``new_content`` is appended to the existing
            body.  If ``False`` (default), the body is replaced while
            preserving YAML frontmatter.
    """
    return json.dumps(
        await asyncio.to_thread(_update_custom_skill_impl, name, new_content, append),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def list_custom_skills(
    ctx: RunContextWrapper,
) -> str:
    """List all custom skills in ``prometheus/skills/custom/``.

    Returns each skill's name, description, and last-modified timestamp.
    """
    return json.dumps(
        await asyncio.to_thread(_list_custom_skills_impl),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def suggest_skill_update(
    ctx: RunContextWrapper,
    skill_name: str,
    observation: str,
    technique: str,
) -> str:
    """Log a suggestion for a skill update without modifying any files.

    Use this when you discover something noteworthy but aren't sure yet
    whether to create or update a skill.  Suggestions are stored in
    ``~/.prometheus/skill_suggestions.json`` for later review.

    Args:
        skill_name: The skill this observation relates to (e.g.
            ``xss``, ``sql_injection``, or a custom skill name).
        observation: What you discovered (e.g. "WAF blocks <script>
            but not <img onerror>").
        technique: The technique or payload that worked.
    """
    return json.dumps(
        await asyncio.to_thread(_suggest_skill_update_impl, skill_name, observation, technique),
        ensure_ascii=False,
        default=str,
    )
