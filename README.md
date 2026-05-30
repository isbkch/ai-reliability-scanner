# AI Reliability Scanner

AI Reliability Scanner reviews service code for production-readiness risks that commonly appear
in AI-generated applications. It keeps the original CLI and pattern-scanner architecture, but the
rule domain is reliability: timeouts, retries, circuit breakers, database pooling, health checks,
idempotency, queue backpressure, observability, graceful shutdown, and configuration safety.

The scanner is intended as a practical pre-production review tool for generated services and
early-stage internal systems. It does not prove a service is production-ready, but it catches
high-leverage operational gaps before code reaches staging.

## Quick Start

```bash
pip install -e ".[dev]"

ai-reliability-scanner scan /path/to/service --no-ai
ai-reliability-scanner scan /path/to/service --output json --file results.json --no-ai
ai-reliability-scanner scan /path/to/service --output sarif --file results.sarif --no-ai
ai-reliability-scanner analyze "requests.get(url)" -l python
```

`ai-security-scanner` remains as a legacy command alias during the transition.

## Reliability Pattern Domains

- `timeouts.py`: outbound HTTP and subprocess calls without explicit timeouts.
- `retries.py`: retry loops without bounded backoff or jitter.
- `circuit_breakers.py`: external dependency calls without circuit breaker markers.
- `database_pooling.py`: database clients without explicit pool limits and liveness checks.
- `health_checks.py`: service apps without health or readiness endpoints.
- `idempotency.py`: risky mutating endpoints without idempotency-key handling.
- `queue_backpressure.py`: unbounded queues and publishers without flow control.
- `observability.py`: swallowed exceptions without logging or metrics.
- `graceful_shutdown.py`: long-running workers without shutdown handling.
- `config_safety.py`: unsafe production defaults such as debug mode or disabled timeouts.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
cp .env.example .env
```

Run tests:

```bash
pytest
pytest tests/unit/patterns/test_reliability_patterns.py
pytest tests/test_scanner.py::TestSecurityScanner::test_scan_missing_python_http_timeout
pytest -m "not slow"
```

Run quality checks:

```bash
pre-commit run --all-files
black ai_security_scanner/ tests/
isort ai_security_scanner/ tests/
flake8 ai_security_scanner/ tests/
mypy ai_security_scanner/
bandit -r ai_security_scanner/
```

## CLI

```bash
ai-reliability-scanner scan /path/to/repo --no-ai
ai-reliability-scanner scan /path/to/repo --severity HIGH --no-ai
ai-reliability-scanner github owner/repo --branch main
ai-reliability-scanner config-info
ai-reliability-scanner version
```

AI analysis is enabled by configuration by default. Use `--no-ai` for deterministic local scans
and CI checks.

## Configuration

The scanner reads YAML config from these locations first:

- `.ai-reliability-scanner.yml`
- `.ai-reliability-scanner.yaml`
- `ai-reliability-scanner.yml`
- `ai-reliability-scanner.yaml`
- legacy `.ai-security-scanner.*` names

Environment variables use the `AI_RELIABILITY_SCANNER_*` prefix, with legacy `AI_SCANNER_*`
variables still accepted.

```yaml
llm:
  provider: "openai"
  model: "gpt-4"
  api_key_env: "OPENAI_API_KEY"

scanner:
  languages: ["python", "javascript"]
  patterns: ["reliability-readiness"]
  enable_ai_analysis: true
  false_positive_reduction: true

database:
  host: "localhost"
  port: 5432
  database: "ai_reliability_scanner"
  username: "scanner"
  password_env: "DB_PASSWORD"
```

## Database

PostgreSQL persistence is optional and keeps scan history, finding details, comparisons, pattern
usage, and LLM usage metrics.

```bash
createdb ai_reliability_scanner
ai-reliability-scanner db init
ai-reliability-scanner db test-connection
ai-reliability-scanner db history -n 10
ai-reliability-scanner db stats

alembic revision --autogenerate -m "description"
alembic upgrade head
```

Alembic migrations live in `ai_security_scanner/database/migrations`.

## Architecture

- `ai_security_scanner/cli/main.py` owns Click commands and output formatting.
- `ai_security_scanner/core/scanner.py` orchestrates file discovery, language detection, pattern
  execution, and optional LLM analysis.
- `ai_security_scanner/core/patterns/` contains the reliability pattern modules and
  `reliability.py` registry.
- `ai_security_scanner/core/models.py` contains the dataclass result models. Some field names
  retain `vulnerability` for compatibility with the original scanner API.
- `ai_security_scanner/integrations/sarif/` exports reliability findings as SARIF.
- `ai_security_scanner/database/` persists scan history and findings through SQLAlchemy.

## Example

```python
import requests
from fastapi import FastAPI

app = FastAPI()

@app.post("/payments")
def create_payment():
    response = requests.post("https://payments.example/charge")
    return response.json()
```

This code can produce findings for missing HTTP timeout, missing circuit breaker, missing health
check, and missing idempotency controls.
