"""Reliability patterns for unsafe retry behavior."""

import re
from typing import List

from ai_security_scanner.core.models import Confidence, Severity, VulnerabilityResult
from ai_security_scanner.core.patterns.reliability_base import (
    ReliabilityPattern,
    line_number_for_offset,
    make_reliability_finding,
)


class RetryPattern(ReliabilityPattern):
    """Detect retry loops that can amplify outages."""

    def __init__(self) -> None:
        super().__init__(
            name="Retry Discipline",
            description="Detects retries without backoff, jitter, or retry limits.",
            severity=Severity.HIGH,
        )
        self.supported_languages = ["python", "javascript"]

    def detect(self, code: str, file_path: str, language: str) -> List[VulnerabilityResult]:
        """Detect retry loops missing production safeguards."""
        if not self.is_supported_language(language):
            return []

        lower_code = code.lower()
        has_retry_loop = bool(
            re.search(r"\bfor\s+\w+\s+in\s+range\s*\(\s*\d+", code)
            or re.search(r"\bwhile\s+true\s*:", code, re.IGNORECASE)
            or re.search(r"\bfor\s*\([^)]*attempt", code, re.IGNORECASE)
        )
        has_retry_context = any(token in lower_code for token in ("retry", "attempt", "retries"))
        has_backoff = any(token in lower_code for token in ("backoff", "jitter", "exponential"))

        if has_retry_loop and has_retry_context and not has_backoff:
            return [
                make_reliability_finding(
                    rule_id=f"retry_without_backoff_{language}",
                    title="Retry loop without backoff or jitter",
                    description=(
                        "Retries without exponential backoff and jitter can turn a dependency "
                        "incident into a traffic amplification event."
                    ),
                    file_path=file_path,
                    code=code,
                    line_number=line_number_for_offset(
                        code, re.search(r"\bfor|\bwhile", code).start()
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    remediation="Add a bounded retry policy with exponential backoff, jitter, and budgets.",
                )
            ]

        return []
