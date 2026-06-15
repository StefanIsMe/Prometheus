from __future__ import annotations

import asyncio
import inspect
import os
from pathlib import Path

import pytest


def pytest_pyfunc_call(pyfuncitem):
    testfunction = pyfuncitem.obj
    if not inspect.iscoroutinefunction(testfunction):
        return None
    funcargs = {name: pyfuncitem.funcargs[name] for name in pyfuncitem._fixtureinfo.argnames}
    asyncio.run(testfunction(**funcargs))
    return True


# ---------------------------------------------------------------------------
# Local-data gate
# ---------------------------------------------------------------------------
# A handful of tests are "log replay" tests: they walk
# ``prometheus_runs/*/prometheus.log`` to confirm a fix reproduces against
# a historic run. Those logs are local to the maintainer's dev box and
# are NOT shipped with the repo (``.gitignore`` excludes
# ``prometheus_runs/``).
#
# On a fresh clone, these tests cannot find any logs and either error or
# trivially pass. Either way they are not useful on CI. The maintainer
# sets ``PROMETHEUS_RUNS_DIR`` to opt back in:
#
#     PROMETHEUS_RUNS_DIR=/path/to/prometheus_runs pytest tests/
#
# We add an autouse fixture that skips any test whose name or module
# path indicates a log-replay test unless that env var points to a real
# directory. This keeps CI green without removing the tests.
# ---------------------------------------------------------------------------

_LOG_REPLAY_MARKERS = (
    "log_replay",
    "replay_fix",
    "log_regression",
    "list_requests_would",
    "test_log_replay",
    "test_replay_fix",
    "test_log_regression",
)


def _is_log_replay_test(item) -> bool:
    """Match by test name, module path, or docstring."""
    name = item.name.lower()
    path = str(item.fspath).lower()
    if any(m in name for m in _LOG_REPLAY_MARKERS):
        return True
    if "prometheus_runs" in path:
        return True
    doc = inspect.getdoc(item.obj) or ""
    return "prometheus_runs" in doc and "log-replay" in doc.lower()


@pytest.fixture(autouse=True)
def _skip_log_replay_without_local_data(request):
    runs_dir = os.environ.get("PROMETHEUS_RUNS_DIR")
    if _is_log_replay_test(request.node) and not (
        runs_dir and Path(runs_dir).is_dir()
    ):
        pytest.skip(
            "log-replay test requires local prometheus_runs/ — set "
            "PROMETHEUS_RUNS_DIR=/path/to/prometheus_runs to run"
        )
