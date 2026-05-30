"""Reliability patterns for observability coverage."""

import re
from typing import List

from ai_security_scanner.core.models import Confidence, Severity, VulnerabilityResult
from ai_security_scanner.core.patterns.reliability_base import (
    ReliabilityPattern,
    line_number_for_offset,
    make_reliability_finding,
)


class ObservabilityPattern(ReliabilityPattern):
    """Detect code paths that hide failures from telemetry."""

    def __init__(self) -> None:
        super().__init__(
            name="Observability Coverage",
            description="Detects swallowed exceptions and missing failure telemetry.",
            severity=Severity.MEDIUM,
        )
        self.supported_languages = ["python", "javascript"]

    def detect(self, code: str, file_path: str, language: str) -> List[VulnerabilityResult]:
        """Detect failures that are swallowed without logging or metrics."""
        if not self.is_supported_language(language):
            return []

        results: List[VulnerabilityResult] = []
        if language == "python":
            pattern = re.compile(
                r"except\s+(?:Exception|BaseException)?\s*(?:as\s+\w+)?\s*:\s*\n\s*(?:pass|return\s+None)",
                re.IGNORECASE,
            )
            for match in pattern.finditer(code):
                results.append(
                    make_reliability_finding(
                        rule_id="swallowed_exception_without_logging",
                        title="Swallowed exception without logging",
                        description=(
                            "Swallowed exceptions remove the signal needed to debug production "
                            "incidents and can make retries appear successful."
                        ),
                        file_path=file_path,
                        code=code,
                        line_number=line_number_for_offset(code, match.start()),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        remediation="Log the exception with context and emit a metric or error status.",
                    )
                )
        else:
            pattern = re.compile(r"catch\s*\([^)]*\)\s*\{\s*(?:return\s+null\s*;)?\s*\}")
            for match in pattern.finditer(code):
                results.append(
                    make_reliability_finding(
                        rule_id="swallowed_exception_without_logging_javascript",
                        title="Swallowed JavaScript error without logging",
                        description="Empty catch blocks hide production failures from observability.",
                        file_path=file_path,
                        code=code,
                        line_number=line_number_for_offset(code, match.start()),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        remediation="Log with request/job context and emit a failure metric.",
                    )
                )

        return results
