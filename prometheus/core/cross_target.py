"""Cross-target intelligence: discover shared technologies across scan targets.

When the agent discovers a new tech stack component, vulnerability pattern,
or attack surface on one target, this module can find other targets that
share the same technology and surface actionable suggestions.

Thread-safe singleton pattern — one ``CrossTargetIntel`` instance per process.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Self

from prometheus.core.target_registry import TargetRegistry
from prometheus.tools.knowledge.store import KnowledgeStore


logger = logging.getLogger(__name__)

_instance: CrossTargetIntel | None = None
_instance_lock = threading.Lock()

# Normalised technology aliases — canonical form on the right.
_TECH_ALIASES: dict[str, str] = {
    "next.js": "nextjs",
    "nextjs": "nextjs",
    "next": "nextjs",
    "nuxt.js": "nuxt",
    "nuxt": "nuxt",
    "express.js": "express",
    "express": "express",
    "vue.js": "vue",
    "vuejs": "vue",
    "react.js": "react",
    "react": "react",
    "angular.js": "angular",
    "angular": "angular",
    "flask": "flask",
    "django": "django",
    "fastapi": "fastapi",
    "laravel": "laravel",
    "spring boot": "spring",
    "spring": "spring",
    "rails": "rails",
    "ruby on rails": "rails",
    "wordpress": "wordpress",
    "wp": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "magento": "magento",
    "shopify": "shopify",
    "nginx": "nginx",
    "apache": "apache",
    "httpd": "apache",
    "iis": "iis",
    "tomcat": "tomcat",
    "gunicorn": "gunicorn",
    "uvicorn": "uvicorn",
    "node": "nodejs",
    "node.js": "nodejs",
    "nodejs": "nodejs",
    "python": "python",
    "php": "php",
    "java": "java",
    "go": "go",
    "golang": "go",
    "rust": "rust",
    "ruby": "ruby",
    ".net": "dotnet",
    "dotnet": "dotnet",
    "asp.net": "dotnet",
    "csharp": "dotnet",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "mongodb": "mongodb",
    "mongo": "mongodb",
    "redis": "redis",
    "elasticsearch": "elasticsearch",
    "elastic": "elasticsearch",
    "graphql": "graphql",
    "rest api": "rest",
    "rest": "rest",
    "grpc": "grpc",
    "docker": "docker",
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    "aws": "aws",
    "azure": "azure",
    "gcp": "gcp",
    "cloudflare": "cloudflare",
    "varnish": "varnish",
    "memcached": "memcached",
    "rabbitmq": "rabbitmq",
    "kafka": "kafka",
    "celery": "celery",
    "oauth": "oauth",
    "oauth2": "oauth",
    "jwt": "jwt",
    "saml": "saml",
    "ldap": "ldap",
}


def _normalise_tech(name: str) -> str:
    """Normalise a technology name to its canonical form."""
    key = name.strip().lower()
    return _TECH_ALIASES.get(key, key)


class CrossTargetIntel:
    """Cross-target intelligence engine.

    Analyses knowledge entries across all registered targets to find
    shared technologies and surface actionable suggestions.

    Use ``CrossTargetIntel()`` — the singleton pattern guarantees one
    instance per process.
    """

    def __new__(cls) -> Self:
        global _instance  # noqa: PLW0603
        if _instance is not None:
            return _instance
        with _instance_lock:
            if _instance is not None:
                return _instance
            inst = super().__new__(cls)
            inst._init()
            _instance = inst
            return inst

    # ------------------------------------------------------------------
    # Internal init
    # ------------------------------------------------------------------

    def _init(self) -> None:
        self._lock = threading.RLock()
        self._knowledge = KnowledgeStore()
        self._registry = TargetRegistry()
        # In-memory cache: domain -> set of normalised tech names
        self._tech_cache: dict[str, set[str]] = {}
        logger.info("CrossTargetIntel initialised")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sync_tech_stack(self, domain: str) -> None:
        """Extract and normalise technology from knowledge entries.

        Reads all ``tech_stack`` entries for *domain* from the knowledge
        store and populates the in-memory tech cache.
        """
        entries = self._knowledge.query(domain, category="tech_stack")
        techs: set[str] = set()
        for entry in entries:
            key = entry.get("key", "")
            value = entry.get("value", "")
            # The key is often the technology name (e.g. "framework")
            # and the value the actual tech (e.g. "Next.js 14")
            for raw in (key, value):
                if raw:
                    # Take first word/phrase as the tech name
                    tech_name = raw.split()[0] if raw.split() else raw
                    normalised = _normalise_tech(tech_name)
                    techs.add(normalised)
                    # Also add the full value if it looks like a tech name
                    full_norm = _normalise_tech(value.strip())
                    if full_norm and len(full_norm) < 60:
                        techs.add(full_norm)

        with self._lock:
            self._tech_cache[domain] = techs
        logger.debug(
            "sync_tech_stack: domain=%s techs=%s",
            domain,
            sorted(techs),
        )

    def get_tech_overlap(self, domain: str) -> list[dict[str, Any]]:
        """Find targets sharing technology with *domain*.

        Returns a list of dicts, each with:
        - ``domain`` — the other target domain
        - ``shared_tech`` — list of technology names in common
        - ``overlap_count`` — how many technologies overlap
        """
        self.sync_tech_stack(domain)
        # Also sync all other active targets
        targets = self._registry.list_targets(status="active")
        for t in targets:
            t_domain = t.get("domain", "")
            if t_domain and t_domain != domain:
                self.sync_tech_stack(t_domain)

        domain_techs = self._tech_cache.get(domain, set())
        if not domain_techs:
            return []

        results: list[dict[str, Any]] = []
        with self._lock:
            for t_domain, t_techs in self._tech_cache.items():
                if t_domain == domain:
                    continue
                shared = sorted(domain_techs & t_techs)
                if shared:
                    results.append(
                        {
                            "domain": t_domain,
                            "shared_tech": shared,
                            "overlap_count": len(shared),
                        }
                    )

        results.sort(key=lambda r: r["overlap_count"], reverse=True)
        return results

    def analyze_new_finding(self, domain: str, finding: dict[str, Any]) -> list[dict[str, Any]]:
        """When a new finding is filed, check other targets for the same tech.

        Extracts technology references from the finding (title, description,
        endpoints) and cross-references against all other targets.

        Returns a list of actionable suggestions for other targets.
        """
        # Extract tech keywords from the finding
        finding_techs: set[str] = set()
        for field in ("title", "description", "endpoint", "technology", "cwe"):
            val = finding.get(field, "")
            if isinstance(val, str) and val:
                for word in val.split():
                    norm = _normalise_tech(word.strip(".,;:()[]{}"))
                    if norm in _TECH_ALIASES.values() or norm in _TECH_ALIASES:
                        finding_techs.add(norm)

        if not finding_techs:
            return []

        suggestions: list[dict[str, Any]] = []
        targets = self._registry.list_targets(status="active")

        for t in targets:
            t_domain = t.get("domain", "")
            if not t_domain or t_domain == domain:
                continue
            self.sync_tech_stack(t_domain)
            t_techs = self._tech_cache.get(t_domain, set())
            overlap = finding_techs & t_techs
            if overlap:
                suggestions.append(
                    {
                        "target_domain": t_domain,
                        "source_domain": domain,
                        "finding_title": finding.get("title", "Unknown"),
                        "severity": finding.get("severity", "info"),
                        "relevant_tech": sorted(overlap),
                        "suggestion": (
                            f"Finding '{finding.get('title', 'Unknown')}' on {domain} "
                            f"targets technology {', '.join(sorted(overlap))}, "
                            f"which is also used by {t_domain}. "
                            f"Consider checking for the same vulnerability pattern."
                        ),
                    }
                )

        suggestions.sort(
            key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                s.get("severity", "info"), 4
            )
        )
        return suggestions

    def get_cross_target_suggestions(self, domain: str) -> list[dict[str, Any]]:
        """Generate suggestions for *domain* based on other targets.

        This looks at:
        1. Vulnerabilities found on other targets that share technology
        2. Successful techniques used on similar targets
        3. Failed approaches to avoid

        Returns a list of suggestion dicts.
        """
        self.sync_tech_stack(domain)
        domain_techs = self._tech_cache.get(domain, set())
        if not domain_techs:
            return []

        suggestions: list[dict[str, Any]] = []
        seen: set[str] = set()

        # Query knowledge for all active targets
        targets = self._registry.list_targets(status="active")
        for t in targets:
            t_domain = t.get("domain", "")
            if not t_domain or t_domain == domain:
                continue

            self.sync_tech_stack(t_domain)
            t_techs = self._tech_cache.get(t_domain, set())
            shared = domain_techs & t_techs
            if not shared:
                continue

            # Look for vulnerabilities on the other target
            vulns = self._knowledge.query(t_domain, category="vulnerability")
            for v in vulns:
                key = v.get("key", "")
                dedup_key = f"vuln:{t_domain}:{key}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                suggestions.append(
                    {
                        "type": "vulnerability_pattern",
                        "source_domain": t_domain,
                        "shared_tech": sorted(shared),
                        "finding": key,
                        "detail": v.get("value", ""),
                        "confidence": v.get("confidence", 0.5),
                        "suggestion": (
                            f"Target {t_domain} (shares {', '.join(sorted(shared))}) "
                            f"had vulnerability: {key}. Check if {domain} is affected."
                        ),
                    }
                )

            # Look for successful techniques
            techniques = self._knowledge.query(t_domain, category="successful_technique")
            for t_entry in techniques:
                key = t_entry.get("key", "")
                dedup_key = f"technique:{t_domain}:{key}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                suggestions.append(
                    {
                        "type": "technique_transfer",
                        "source_domain": t_domain,
                        "shared_tech": sorted(shared),
                        "technique": key,
                        "detail": t_entry.get("value", ""),
                        "confidence": t_entry.get("confidence", 0.5),
                        "suggestion": (
                            f"Technique '{key}' worked on {t_domain} "
                            f"(shares {', '.join(sorted(shared))}). "
                            f"May also work on {domain}."
                        ),
                    }
                )

            # Look for failed approaches to avoid
            failures = self._knowledge.query(t_domain, category="failed_approach")
            for f_entry in failures:
                key = f_entry.get("key", "")
                dedup_key = f"fail:{t_domain}:{key}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                suggestions.append(
                    {
                        "type": "avoid_approach",
                        "source_domain": t_domain,
                        "shared_tech": sorted(shared),
                        "approach": key,
                        "detail": f_entry.get("value", ""),
                        "suggestion": (
                            f"Approach '{key}' FAILED on {t_domain} "
                            f"(shares {', '.join(sorted(shared))}). "
                            f"Likely won't work on {domain} either — skip it."
                        ),
                    }
                )

        # Sort: vulnerability patterns first, then techniques, then avoid
        type_order = {"vulnerability_pattern": 0, "technique_transfer": 1, "avoid_approach": 2}
        suggestions.sort(key=lambda s: type_order.get(s.get("type", ""), 9))
        return suggestions
