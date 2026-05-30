"""Reliability patterns for graceful shutdown."""

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


class GracefulShutdownPattern(ReliabilityPattern):
    """Detect long-running services without shutdown handling."""

    def __init__(self) -> None:
        super().__init__(
            name="Graceful Shutdown",
            description="Detects workers and loops missing SIGTERM/shutdown handling.",
            severity=Severity.HIGH,
        )
        self.supported_languages = ["python", "javascript"]
        self.loop_patterns = compile_any(
            [r"\bwhile\s+True\s*:", r"\bsetInterval\s*\(", r"\bforever\b"]
        )
        self.shutdown_patterns = compile_any(
            [r"\bsignal\.signal\b", r"\bSIGTERM\b", r"\bshutdown\b", r"\bon_shutdown\b"]
        )

    def detect(self, code: str, file_path: str, language: str) -> List[VulnerabilityResult]:
        """Detect long-running loops without shutdown hooks."""
        if not self.is_supported_language(language):
            return []

        if has_any(self.loop_patterns, code) and not has_any(self.shutdown_patterns, code):
            return [
                make_reliability_finding(
                    rule_id="long_running_loop_without_shutdown_hook",
                    title="Long-running loop without graceful shutdown",
                    description=(
                        "Workers without SIGTERM/shutdown handling can drop in-flight work and "
                        "delay deploys or autoscaling events."
                    ),
                    file_path=file_path,
                    code=code,
                    line_number=first_match_line(code, self.loop_patterns),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    remediation="Handle SIGTERM, stop accepting work, drain in-flight tasks, then exit.",
                )
            ]

        return []
