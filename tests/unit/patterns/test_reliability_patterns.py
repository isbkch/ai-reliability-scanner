"""Tests for production-readiness reliability patterns."""

import pytest

from ai_security_scanner.core.config import Config
from ai_security_scanner.core.models import Severity
from ai_security_scanner.core.patterns.circuit_breakers import CircuitBreakerPattern
from ai_security_scanner.core.patterns.config_safety import ConfigSafetyPattern
from ai_security_scanner.core.patterns.database_pooling import DatabasePoolingPattern
from ai_security_scanner.core.patterns.graceful_shutdown import GracefulShutdownPattern
from ai_security_scanner.core.patterns.health_checks import HealthCheckPattern
from ai_security_scanner.core.patterns.idempotency import IdempotencyPattern
from ai_security_scanner.core.patterns.observability import ObservabilityPattern
from ai_security_scanner.core.patterns.queue_backpressure import QueueBackpressurePattern
from ai_security_scanner.core.patterns.reliability import get_reliability_patterns
from ai_security_scanner.core.patterns.retries import RetryPattern
from ai_security_scanner.core.patterns.timeouts import TimeoutPattern
from ai_security_scanner.core.scanner import SecurityScanner


def finding_ids(results):
    """Return finding identifiers from pattern results."""
    return {result.vulnerability_type for result in results}


def test_reliability_loader_registers_all_domains() -> None:
    """The default reliability loader should cover the production-readiness domains."""
    pattern_names = {pattern.name for pattern in get_reliability_patterns()}

    assert pattern_names == {
        "Timeout Hygiene",
        "Retry Discipline",
        "Circuit Breaker Coverage",
        "Database Pooling",
        "Health Check Coverage",
        "Idempotency Controls",
        "Queue Backpressure",
        "Observability Coverage",
        "Graceful Shutdown",
        "Configuration Safety",
    }


@pytest.mark.parametrize(
    ("pattern", "code", "expected_id"),
    [
        (
            TimeoutPattern(),
            "import requests\nrequests.get(service_url)\n",
            "missing_http_timeout_python",
        ),
        (
            RetryPattern(),
            "for attempt in range(3):\n    try:\n        call_api()\n    except Exception:\n        pass\n",
            "retry_without_backoff_python",
        ),
        (
            CircuitBreakerPattern(),
            "import requests\nresponse = requests.post(payment_url, timeout=5)\n",
            "external_call_without_circuit_breaker_python",
        ),
        (
            DatabasePoolingPattern(),
            "from sqlalchemy import create_engine\nengine = create_engine(DATABASE_URL)\n",
            "sqlalchemy_engine_without_pool_safety",
        ),
        (
            HealthCheckPattern(),
            "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/predict')\ndef predict():\n    return {}\n",
            "service_without_health_check",
        ),
        (
            IdempotencyPattern(),
            "@app.post('/payments')\ndef create_payment():\n    return charge_card()\n",
            "mutating_endpoint_without_idempotency_key",
        ),
        (
            QueueBackpressurePattern(),
            "import asyncio\njobs = asyncio.Queue()\n",
            "unbounded_asyncio_queue",
        ),
        (
            ObservabilityPattern(),
            "try:\n    process_job()\nexcept Exception:\n    pass\n",
            "swallowed_exception_without_logging",
        ),
        (
            GracefulShutdownPattern(),
            "while True:\n    process_next_job()\n",
            "long_running_loop_without_shutdown_hook",
        ),
        (
            ConfigSafetyPattern(),
            "DEBUG = True\nREQUEST_TIMEOUT = 0\n",
            "unsafe_debug_default",
        ),
    ],
)
def test_patterns_detect_reliability_risks(pattern, code: str, expected_id: str) -> None:
    """Each reliability domain should produce a concrete finding."""
    results = pattern.detect(code, "service.py", "python")

    assert expected_id in finding_ids(results)
    assert all(
        result.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL} for result in results
    )


def test_timeout_pattern_ignores_python_request_with_timeout() -> None:
    """Explicit HTTP timeouts should not be flagged."""
    code = "import requests\nrequests.get(service_url, timeout=5)\n"

    results = TimeoutPattern().detect(code, "client.py", "python")

    assert "missing_http_timeout_python" not in finding_ids(results)


def test_scanner_uses_reliability_patterns_by_default() -> None:
    """The scanner should load reliability-readiness patterns without custom config."""
    scanner = SecurityScanner(Config())

    loaded_patterns = scanner.get_loaded_patterns()
    results = scanner.scan_code("import requests\nrequests.get(url)\n", "python", "client.py")

    assert "Timeout Hygiene" in loaded_patterns
    assert "missing_http_timeout_python" in finding_ids(results)
