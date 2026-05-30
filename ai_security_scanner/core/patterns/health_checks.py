"""Reliability patterns for service health checks."""

from typing import List

from ai_security_scanner.core.models import Confidence, Severity, VulnerabilityResult
from ai_security_scanner.core.patterns.reliability_base import (
    ReliabilityPattern,
    compile_any,
    first_match_line,
    has_any,
    make_reliability_finding,
)


class HealthCheckPattern(ReliabilityPattern):
    """Detect services without obvious health or readiness endpoints."""

    def __init__(self) -> None:
        super().__init__(
            name="Health Check Coverage",
            description="Detects web services missing health/readiness endpoints.",
            severity=Severity.HIGH,
        )
        self.supported_languages = ["python", "javascript"]
        self.service_patterns = compile_any(
            [r"\bFastAPI\s*\(", r"\bFlask\s*\(", r"\bexpress\s*\(", r"\bHono\s*\("]
        )
        self.health_patterns = compile_any(
            [r"['\"]/(?:health|healthz|ready|readyz|live|livez)['\"]", r"\breadiness\b"]
        )

    def detect(self, code: str, file_path: str, language: str) -> List[VulnerabilityResult]:
        """Detect services without health/readiness routes."""
        if not self.is_supported_language(language):
            return []

        if has_any(self.service_patterns, code) and not has_any(self.health_patterns, code):
            return [
                make_reliability_finding(
                    rule_id="service_without_health_check",
                    title="Service without health or readiness endpoint",
                    description=(
                        "Services need health and readiness checks so orchestrators can route "
                        "traffic, restart failed instances, and drain deploys safely."
                    ),
                    file_path=file_path,
                    code=code,
                    line_number=first_match_line(code, self.service_patterns),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    remediation="Add cheap /health and dependency-aware /ready endpoints.",
                )
            ]

        return []
