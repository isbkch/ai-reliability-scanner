"""Shared helpers for reliability readiness patterns."""

import re
import uuid
from typing import Any, Dict, Iterable, List, Optional, Pattern

from ai_security_scanner.core.models import Confidence, Location, Severity, VulnerabilityResult
from ai_security_scanner.core.patterns.base import VulnerabilityPattern


class ReliabilityPattern(VulnerabilityPattern):
    """Base class for production-readiness reliability checks."""


def compile_any(patterns: Iterable[str]) -> List[Pattern[str]]:
    """Compile case-insensitive regular expressions."""
    return [re.compile(pattern, re.IGNORECASE | re.MULTILINE) for pattern in patterns]


def has_any(patterns: Iterable[Pattern[str]], code: str) -> bool:
    """Return whether any compiled pattern matches the code."""
    return any(pattern.search(code) for pattern in patterns)


def line_number_for_offset(code: str, offset: int) -> int:
    """Calculate a one-based line number for a character offset."""
    return code.count("\n", 0, max(offset, 0)) + 1


def first_match_line(code: str, patterns: Iterable[Pattern[str]]) -> int:
    """Return the first matching line for a group of patterns."""
    first_offset: Optional[int] = None
    for pattern in patterns:
        match = pattern.search(code)
        if match and (first_offset is None or match.start() < first_offset):
            first_offset = match.start()

    if first_offset is None:
        return 1

    return line_number_for_offset(code, first_offset)


def extract_code_snippet(code: str, line_number: int, context_lines: int = 2) -> str:
    """Extract a formatted snippet around a finding location."""
    lines = code.split("\n")
    start_line = max(0, line_number - context_lines - 1)
    end_line = min(len(lines), line_number + context_lines)

    snippet_lines = []
    for index in range(start_line, end_line):
        current_line = index + 1
        prefix = ">>> " if current_line == line_number else "    "
        snippet_lines.append(f"{prefix}{current_line:4d}: {lines[index]}")

    return "\n".join(snippet_lines)


def make_reliability_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    file_path: str,
    code: str,
    line_number: int,
    severity: Severity,
    confidence: Confidence = Confidence.MEDIUM,
    remediation: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> VulnerabilityResult:
    """Create a reliability finding using the scanner's existing result model."""
    return VulnerabilityResult(
        id=str(uuid.uuid4()),
        vulnerability_type=rule_id,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        location=Location(file_path=file_path, line_number=line_number),
        code_snippet=extract_code_snippet(code, line_number),
        remediation=remediation,
        metadata={"domain": "reliability", **(metadata or {})},
    )
