"""Reliability patterns for missing circuit breakers."""

import re
from typing import List

from ai_security_scanner.core.models import Confidence, Severity, VulnerabilityResult
from ai_security_scanner.core.patterns.reliability_base import (
    ReliabilityPattern,
    compile_any,
    first_match_line,
    has_any,
    make_reliability_finding,
)


class CircuitBreakerPattern(ReliabilityPattern):
    """Detect dependency calls without an obvious circuit breaker guard."""

    def __init__(self) -> None:
        super().__init__(
            name="Circuit Breaker Coverage",
            description="Detects external calls that lack circuit breaker protection.",
            severity=Severity.HIGH,
        )
        self.supported_languages = ["python", "javascript"]
        self.call_patterns = compile_any(
            [
                r"\brequests\.(?:get|post|put|patch|delete|request)\s*\(",
                r"\bhttpx\.(?:get|post|put|patch|delete|request)\s*\(",
                r"\bfetch\s*\(",
                r"\baxios\.(?:get|post|put|patch|delete|request)\s*\(",
            ]
        )
        self.breaker_patterns = compile_any(
            [r"circuit[_-]?breaker", r"\bCircuitBreaker\b", r"\bpybreaker\b", r"\bopossum\b"]
        )

    def detect(self, code: str, file_path: str, language: str) -> List[VulnerabilityResult]:
        """Detect external calls without circuit breaker markers."""
        if not self.is_supported_language(language):
            return []

        if has_any(self.call_patterns, code) and not has_any(self.breaker_patterns, code):
            return [
                make_reliability_finding(
                    rule_id=f"external_call_without_circuit_breaker_{language}",
                    title="External dependency call without circuit breaker",
                    description=(
                        "Calls to remote dependencies without circuit breakers can exhaust worker "
                        "capacity and keep hammering degraded services."
                    ),
                    file_path=file_path,
                    code=code,
                    line_number=first_match_line(code, self.call_patterns),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    remediation="Wrap high-volume dependency calls in a circuit breaker or bulkhead.",
                )
            ]

        return []
