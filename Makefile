.PHONY: help install dev-install format lint type-check security check-no-telemetry check-all clean pre-commit setup-dev dev

help:
	@echo "Available commands:"
	@echo "  setup-dev     - Install all development dependencies and setup pre-commit"
	@echo "  install       - Install production dependencies"
	@echo "  dev-install   - Install development dependencies"
	@echo ""
	@echo "Code Quality:"
	@echo "  format              - Format code with ruff"
	@echo "  lint                - Lint code with ruff"
	@echo "  type-check          - Run type checking with mypy and pyright"
	@echo "  security            - Run security checks with bandit"
	@echo "  check-no-telemetry  - Fail if external-telemetry code is in the codebase"
	@echo "  check-all           - Run all code quality checks"
	@echo ""
	@echo "Development:"
	@echo "  pre-commit    - Run pre-commit hooks on all files"
	@echo "  clean         - Clean up cache files and artifacts"

install:
	uv sync --no-dev

dev-install:
	uv sync

setup-dev: dev-install
	uv run pre-commit install
	@echo "✅ Development environment setup complete!"
	@echo "Run 'make check-all' to verify everything works correctly."

format:
	@echo "🎨 Formatting code with ruff..."
	uv run ruff format .
	@echo "✅ Code formatting complete!"

lint:
	@echo "🔍 Linting code with ruff..."
	uv run ruff check . --fix
	@echo "✅ Linting complete!"

type-check:
	@echo "🔍 Type checking with mypy..."
	uv run mypy prometheus/
	@echo "🔍 Type checking with pyright..."
	uv run pyright prometheus/
	@echo "✅ Type checking complete!"

security:
	@echo "🔒 Running security checks with bandit..."
	uv run bandit -r prometheus/ -c pyproject.toml
	@echo "✅ Security checks complete!"

check-no-telemetry:
	@echo "🚫 Checking for external-telemetry code in the codebase..."
	@if command -v uv >/dev/null 2>&1 && [ -d .venv ]; then \
		uv run python tools/check_no_external_telemetry.py; \
	else \
		python3 tools/check_no_external_telemetry.py; \
	fi
	@echo "✅ No external-telemetry code found."

check-all: format lint type-check security check-no-telemetry
	@echo "✅ All code quality checks passed!"

pre-commit:
	@echo "🔧 Running pre-commit hooks..."
	uv run pre-commit run --all-files
	@echo "✅ Pre-commit hooks complete!"

clean:
	@echo "🧹 Cleaning up cache files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	@echo "✅ Cleanup complete!"

dev: format lint type-check
	@echo "✅ Development cycle complete!"
