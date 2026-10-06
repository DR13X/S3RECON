.PHONY: install install-dev test lint format typecheck clean run-help

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

test:
	pytest s3recon/tests -q --tb=short

lint:
	ruff check s3recon

format:
	ruff format s3recon

typecheck:
	mypy s3recon --ignore-missing-imports

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

run-help:
	python -m s3recon --help
