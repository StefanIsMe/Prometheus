# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

project_root = Path(SPECPATH)
prometheus_root = project_root / 'prometheus'

datas = []

for md_file in prometheus_root.rglob('skills/**/*.md'):
    rel_path = md_file.relative_to(project_root)
    datas.append((str(md_file), str(rel_path.parent)))

for jinja_file in prometheus_root.rglob('agents/**/*.jinja'):
    rel_path = jinja_file.relative_to(project_root)
    datas.append((str(jinja_file), str(rel_path.parent)))

for xml_file in prometheus_root.rglob('*.xml'):
    rel_path = xml_file.relative_to(project_root)
    datas.append((str(xml_file), str(rel_path.parent)))

for tcss_file in prometheus_root.rglob('*.tcss'):
    rel_path = tcss_file.relative_to(project_root)
    datas.append((str(tcss_file), str(rel_path.parent)))

datas += collect_data_files('textual')

datas += collect_data_files('tiktoken')
datas += collect_data_files('tiktoken_ext')

datas += collect_data_files('litellm')

hiddenimports = [
    # Core dependencies
    'litellm',
    'litellm.llms',
    'litellm.llms.openai',
    'litellm.llms.anthropic',
    'litellm.llms.vertex_ai',
    'litellm.llms.bedrock',
    'litellm.utils',
    'litellm.caching',

    # Textual TUI
    'textual',
    'textual.app',
    'textual.widgets',
    'textual.containers',
    'textual.screen',
    'textual.binding',
    'textual.reactive',
    'textual.css',
    'textual._text_area_theme',

    # Rich console
    'rich',
    'rich.console',
    'rich.panel',
    'rich.text',
    'rich.markup',
    'rich.style',
    'rich.align',
    'rich.live',

    # Pydantic
    'pydantic',
    'pydantic.fields',
    'pydantic_core',
    'email_validator',

    # Docker
    'docker',
    'docker.api',
    'docker.models',
    'docker.errors',

    # HTTP/Networking
    'httpx',
    'httpcore',
    'requests',
    'urllib3',
    'certifi',

    # Jinja2 templating
    'jinja2',
    'jinja2.ext',
    'markupsafe',

    # XML parsing
    'xmltodict',
    'defusedxml',
    'defusedxml.ElementTree',

    # Syntax highlighting
    'pygments',
    'pygments.lexers',
    'pygments.styles',
    'pygments.util',

    # Tiktoken (for token counting)
    'tiktoken',
    'tiktoken_ext',
    'tiktoken_ext.openai_public',

    # Tenacity retry
    'tenacity',

    # CVSS scoring
    'cvss',

    # prometheus modules
    'prometheus',
    'prometheus.interface',
    'prometheus.interface.main',
    'prometheus.interface.cli',
    'prometheus.interface.tui',
    'prometheus.interface.tui.app',
    'prometheus.interface.tui.history',
    'prometheus.interface.tui.live_view',
    'prometheus.interface.tui.messages',
    'prometheus.interface.tui.renderers',
    'prometheus.interface.tui.renderers.agent_message_renderer',
    'prometheus.interface.tui.renderers.agents_graph_renderer',
    'prometheus.interface.tui.renderers.base_renderer',
    'prometheus.interface.tui.renderers.finish_renderer',
    'prometheus.interface.tui.renderers.notes_renderer',
    'prometheus.interface.tui.renderers.proxy_renderer',
    'prometheus.interface.tui.renderers.registry',
    'prometheus.interface.tui.renderers.reporting_renderer',
    'prometheus.interface.tui.renderers.thinking_renderer',
    'prometheus.interface.tui.renderers.todo_renderer',
    'prometheus.interface.tui.renderers.user_message_renderer',
    'prometheus.interface.tui.renderers.web_search_renderer',
    'prometheus.interface.utils',
    'prometheus.agents',
    'prometheus.agents.factory',
    'prometheus.agents.prompt',
    'prometheus.config.models',
    'prometheus.core',
    'prometheus.core.agents',
    'prometheus.core.execution',
    'prometheus.core.inputs',
    'prometheus.core.paths',
    'prometheus.core.runner',
    'prometheus.core.sessions',
    'prometheus.report',
    'prometheus.report.dedupe',
    'prometheus.report.state',
    'prometheus.report.writer',
    'prometheus.runtime',
    'prometheus.runtime.backends',
    'prometheus.runtime.caido_bootstrap',
    'prometheus.runtime.docker_client',
    'prometheus.runtime.session_manager',
    'prometheus.telemetry',
    'prometheus.telemetry.logging',
    'prometheus.telemetry.posthog',
    'prometheus.tools',
    'prometheus.tools.agents_graph.tools',
    'prometheus.tools.finish.tool',
    'prometheus.tools.notes.tools',
    'prometheus.tools.proxy._calls',
    'prometheus.tools.proxy.tools',
    'prometheus.tools.python.tool',
    'prometheus.tools.reporting.tool',
    'prometheus.tools.thinking.tool',
    'prometheus.tools.todo.tools',
    'prometheus.tools.web_search.tool',
    'prometheus.skills',
]

hiddenimports += collect_submodules('litellm')
hiddenimports += collect_submodules('textual')
hiddenimports += collect_submodules('rich')
hiddenimports += collect_submodules('pydantic')
hiddenimports += collect_submodules('pygments')

excludes = [
    # Sandbox-only packages
    'playwright',
    'playwright.sync_api',
    'playwright.async_api',
    'IPython',
    'ipython',
    'libtmux',
    'pyte',
    'openhands_aci',
    'openhands-aci',
    'gql',
    'fastapi',
    'uvicorn',
    'numpydoc',

    # Google Cloud / Vertex AI
    'google.cloud',
    'google.cloud.aiplatform',
    'google.api_core',
    'google.auth',
    'google.oauth2',
    'google.protobuf',
    'grpc',
    'grpcio',
    'grpcio_status',

    # Test frameworks
    'pytest',
    'pytest_asyncio',
    'pytest_cov',
    'pytest_mock',

    # Development tools
    'mypy',
    'ruff',
    'black',
    'isort',
    'pylint',
    'pyright',
    'bandit',
    'pre_commit',

    # Unnecessary for runtime
    'tkinter',
    'matplotlib',
    'numpy',
    'pandas',
    'scipy',
    'PIL',
    'cv2',
]

a = Analysis(
    ['prometheus/interface/main.py'],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='prometheus',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
