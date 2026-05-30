"""Reliability-readiness pattern registry."""

from typing import List

from ai_security_scanner.core.patterns.base import VulnerabilityPattern
from ai_security_scanner.core.patterns.circuit_breakers import CircuitBreakerPattern
from ai_security_scanner.core.patterns.config_safety import ConfigSafetyPattern
from ai_security_scanner.core.patterns.database_pooling import DatabasePoolingPattern
from ai_security_scanner.core.patterns.graceful_shutdown import GracefulShutdownPattern
from ai_security_scanner.core.patterns.health_checks import HealthCheckPattern
from ai_security_scanner.core.patterns.idempotency import IdempotencyPattern
from ai_security_scanner.core.patterns.observability import ObservabilityPattern
from ai_security_scanner.core.patterns.queue_backpressure import QueueBackpressurePattern
from ai_security_scanner.core.patterns.retries import RetryPattern
from ai_security_scanner.core.patterns.timeouts import TimeoutPattern


def get_reliability_patterns() -> List[VulnerabilityPattern]:
    """Return all production-readiness reliability patterns."""
    return [
        TimeoutPattern(),
        RetryPattern(),
        CircuitBreakerPattern(),
        DatabasePoolingPattern(),
        HealthCheckPattern(),
        IdempotencyPattern(),
        QueueBackpressurePattern(),
        ObservabilityPattern(),
        GracefulShutdownPattern(),
        ConfigSafetyPattern(),
    ]
