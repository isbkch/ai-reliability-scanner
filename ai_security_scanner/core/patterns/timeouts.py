"""Reliability patterns for missing timeout controls."""

import re
from typing import List

from ai_security_scanner.core.models import Confidence, Severity, VulnerabilityResult
from ai_security_scanner.core.patterns.reliability_base import (
    ReliabilityPattern,
    line_number_for_offset,
    make_reliability_finding,
)


class TimeoutPattern(ReliabilityPattern):
    """Detect outbound calls that can hang indefinitely."""

    def __init__(self) -> None:
        super().__init__(
            name="Timeout Hygiene",
            description="Detects network and subprocess calls without explicit timeout controls.",
            severity=Severity.HIGH,
        )
        self.supported_languages = ["python", "javascript"]

    def detect(self, code: str, file_path: str, language: str) -> List[VulnerabilityResult]:
        """Detect missing timeouts in Python and JavaScript code."""
        if not self.is_supported_language(language):
            return []

        if language == "python":
            return self._detect_python(code, file_path)

        return self._detect_javascript(code, file_path)

    def _detect_python(self, code: str, file_path: str) -> List[VulnerabilityResult]:
        results: List[VulnerabilityResult] = []
        call_pattern = re.compile(
            r"\b(?:requests|httpx)\.(?:get|post|put|patch|delete|request)\s*\((?P<args>[^)]*)\)",
            re.IGNORECASE | re.MULTILINE,
        )
        subprocess_pattern = re.compile(
            r"\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\((?P<args>[^)]*)\)",
            re.IGNORECASE | re.MULTILINE,
        )

        for match in call_pattern.finditer(code):
            if "timeout" in match.group("args").lower():
                continue
            results.append(
                make_reliability_finding(
                    rule_id="missing_http_timeout_python",
                    title="HTTP call without timeout",
                    description=(
                        "Outbound HTTP calls without a timeout can hang request handlers, workers, "
                        "or AI agent loops during dependency stalls."
                    ),
                    file_path=file_path,
                    code=code,
                    line_number=line_number_for_offset(code, match.start()),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    remediation="Pass an explicit timeout and handle timeout exceptions.",
                )
            )

        for match in subprocess_pattern.finditer(code):
            if "timeout" in match.group("args").lower():
                continue
            results.append(
                make_reliability_finding(
                    rule_id="missing_subprocess_timeout_python",
                    title="Subprocess without timeout",
                    description="Subprocess calls without timeouts can leak workers indefinitely.",
                    file_path=file_path,
                    code=code,
                    line_number=line_number_for_offset(code, match.start()),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    remediation="Pass timeout=... and terminate or kill on timeout.",
                )
            )

        return results

    def _detect_javascript(self, code: str, file_path: str) -> List[VulnerabilityResult]:
        results: List[VulnerabilityResult] = []
        timeout_markers = ("AbortController", "AbortSignal.timeout", "timeout:")
        fetch_pattern = re.compile(r"\bfetch\s*\(", re.IGNORECASE | re.MULTILINE)
        axios_pattern = re.compile(r"\baxios\.(?:get|post|put|patch|delete|request)\s*\(")

        for pattern, rule_id, title in [
            (fetch_pattern, "missing_fetch_timeout_javascript", "fetch call without timeout"),
            (axios_pattern, "missing_axios_timeout_javascript", "axios call without timeout"),
        ]:
            for match in pattern.finditer(code):
                window = code[match.start() : match.start() + 300]
                if any(marker in window for marker in timeout_markers):
                    continue
                results.append(
                    make_reliability_finding(
                        rule_id=rule_id,
                        title=title,
                        description=(
                            "Outbound JavaScript calls without cancellation or timeout controls "
                            "can accumulate hung promises under dependency failures."
                        ),
                        file_path=file_path,
                        code=code,
                        line_number=line_number_for_offset(code, match.start()),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        remediation="Use AbortSignal.timeout(), AbortController, or client timeouts.",
                    )
                )

        return results
