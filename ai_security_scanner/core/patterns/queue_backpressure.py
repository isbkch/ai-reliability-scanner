"""Reliability patterns for queue backpressure."""

import re
from typing import List

from ai_security_scanner.core.models import Confidence, Severity, VulnerabilityResult
from ai_security_scanner.core.patterns.reliability_base import (
    ReliabilityPattern,
    line_number_for_offset,
    make_reliability_finding,
)


class QueueBackpressurePattern(ReliabilityPattern):
    """Detect queues and publishers without backpressure limits."""

    def __init__(self) -> None:
        super().__init__(
            name="Queue Backpressure",
            description="Detects unbounded queues and producers without flow-control safeguards.",
            severity=Severity.HIGH,
        )
        self.supported_languages = ["python", "javascript"]

    def detect(self, code: str, file_path: str, language: str) -> List[VulnerabilityResult]:
        """Detect missing queue bounds and flow control."""
        if not self.is_supported_language(language):
            return []

        results: List[VulnerabilityResult] = []
        if language == "python":
            queue_pattern = re.compile(r"\b(?:asyncio\.)?Queue\s*\((?P<args>[^)]*)\)")
            for match in queue_pattern.finditer(code):
                args = match.group("args").lower()
                if "maxsize" in args and not re.search(r"maxsize\s*=\s*0\b", args):
                    continue
                results.append(
                    make_reliability_finding(
                        rule_id="unbounded_asyncio_queue",
                        title="Unbounded queue without backpressure",
                        description="Unbounded in-memory queues can exhaust memory during downstream stalls.",
                        file_path=file_path,
                        code=code,
                        line_number=line_number_for_offset(code, match.start()),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        remediation="Set maxsize and define producer behavior when the queue is full.",
                    )
                )
        else:
            publish_pattern = re.compile(r"\.(?:send|publish)\s*\(")
            for match in publish_pattern.finditer(code):
                window = code[max(0, match.start() - 200) : match.start() + 250].lower()
                if any(token in window for token in ("drain", "backpressure", "buffer")):
                    continue
                results.append(
                    make_reliability_finding(
                        rule_id="publisher_without_backpressure_javascript",
                        title="Publisher without backpressure handling",
                        description="Queue publishers should handle broker pressure and local buffer growth.",
                        file_path=file_path,
                        code=code,
                        line_number=line_number_for_offset(code, match.start()),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        remediation="Check send return values, wait for drain, or use bounded workers.",
                    )
                )

        return results
