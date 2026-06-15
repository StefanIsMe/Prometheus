"""RealVuln-Benchmark harness for prometheus.

Run the kolega-ai/Real-Vuln-Benchmark (26 Python repos, 676 vulns + 120
FP traps, pinned to specific commit SHAs) against prometheus and
write Semgrep-shaped results to ``scan-results/{repo}/<slug>/``.

Entry point: ``prometheus realvuln {list, run, report, score}``.
"""

from __future__ import annotations

__all__: list[str] = []
