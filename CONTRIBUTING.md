# Contributing to AI Reliability Scanner

AI Reliability Scanner reviews service code for production-readiness risks. Contributions should
stay focused on reliability, operability, and incident-prevention checks.

## Setup

```bash
git clone https://github.com/your-username/ai-reliability-scanner.git
cd ai-reliability-scanner
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
cp .env.example .env
```

## Checks

```bash
pytest
pytest tests/unit/patterns/test_reliability_patterns.py
pytest --cov=ai_security_scanner --cov-report=html

pre-commit run --all-files
black ai_security_scanner/ tests/
isort ai_security_scanner/ tests/
flake8 ai_security_scanner/ tests/
mypy ai_security_scanner/
bandit -r ai_security_scanner/
```

## Adding Reliability Patterns

1. Add a focused module under `ai_security_scanner/core/patterns/`.
2. Implement a `ReliabilityPattern` subclass or use helpers from `reliability_base.py`.
3. Register the pattern in `get_reliability_patterns()`.
4. Add tests under `tests/unit/patterns/`.
5. Add or update examples if the behavior is useful for demos.

Good pattern modules identify one operational failure mode and return actionable remediation.
Prefer precise checks over broad matches that create noisy findings.

## CLI and Output Changes

Test CLI changes with `click.testing.CliRunner` in `tests/functional/test_cli.py`. JSON output
must remain parseable on stdout and should use `findings` for user-facing results. Legacy internal
names such as `VulnerabilityResult` are retained for API compatibility.

## Database Changes

Database persistence uses SQLAlchemy models in `ai_security_scanner/database/models/` and Alembic
migrations in `ai_security_scanner/database/migrations`.

```bash
alembic revision --autogenerate -m "description"
alembic upgrade head
```

Review generated migrations before committing them.
