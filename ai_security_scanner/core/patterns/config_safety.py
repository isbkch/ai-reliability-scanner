"""Reliability patterns for unsafe configuration defaults."""

import re
from typing import List

from ai_security_scanner.core.models import Confidence, Severity, VulnerabilityResult
from ai_security_scanner.core.patterns.reliability_base import (
    ReliabilityPattern,
    line_number_for_offset,
    make_reliability_finding,
)


class ConfigSafetyPattern(ReliabilityPattern):
    """Detect configuration defaults that are unsafe for production."""

    def __init__(self) -> None:
        super().__init__(
            name="Configuration Safety",
            description="Detects production-risky defaults such as debug mode and disabled timeouts.",
            severity=Severity.MEDIUM,
        )
        self.supported_languages = ["python", "javascript"]

    def detect(self, code: str, file_path: str, language: str) -> List[VulnerabilityResult]:
        """Detect unsafe config defaults."""
        if not self.is_supported_language(language):
            return []

        results: List[VulnerabilityResult] = []
        debug_pattern = re.compile(r"\b(?:DEBUG|debug)\s*=\s*(?:True|true)\b")
        timeout_zero_pattern = re.compile(
            r"\b(?:REQUEST_)?TIMEOUT\w*\s*=\s*(?:0|None|null)\b", re.IGNORECASE
        )
        env_zero_timeout = re.compile(
            r"os\.getenv\s*\(\s*['\"][^'\"]*TIMEOUT[^'\"]*['\"]\s*,\s*['\"](?:0|None)['\"]",
            re.IGNORECASE,
        )

        for match in debug_pattern.finditer(code):
            results.append(
                make_reliability_finding(
                    rule_id="unsafe_debug_default",
                    title="Debug mode enabled by default",
                    description="Debug defaults can change runtime behavior and expose noisy failure modes.",
                    file_path=file_path,
                    code=code,
                    line_number=line_number_for_offset(code, match.start()),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    remediation="Default debug mode to false and enable it only in local environments.",
                )
            )

        for pattern, rule_id in [
            (timeout_zero_pattern, "disabled_timeout_default"),
            (env_zero_timeout, "environment_timeout_default_disabled"),
        ]:
            for match in pattern.finditer(code):
                results.append(
                    make_reliability_finding(
                        rule_id=rule_id,
                        title="Timeout disabled by default",
                        description="Timeouts defaulting to zero or None make dependency hangs more likely.",
                        file_path=file_path,
                        code=code,
                        line_number=line_number_for_offset(code, match.start()),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        remediation="Use conservative finite defaults and validate config at startup.",
                    )
                )

        return results
