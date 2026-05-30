"""Reliability patterns for database connection safety."""

import re
from typing import List

from ai_security_scanner.core.models import Confidence, Severity, VulnerabilityResult
from ai_security_scanner.core.patterns.reliability_base import (
    ReliabilityPattern,
    line_number_for_offset,
    make_reliability_finding,
)


class DatabasePoolingPattern(ReliabilityPattern):
    """Detect database clients missing connection-pool safeguards."""

    def __init__(self) -> None:
        super().__init__(
            name="Database Pooling",
            description="Detects database connection setup without explicit pool controls.",
            severity=Severity.HIGH,
        )
        self.supported_languages = ["python", "javascript"]

    def detect(self, code: str, file_path: str, language: str) -> List[VulnerabilityResult]:
        """Detect unsafe database connection configuration."""
        if not self.is_supported_language(language):
            return []

        if language == "python":
            return self._detect_python(code, file_path)

        return self._detect_javascript(code, file_path)

    def _detect_python(self, code: str, file_path: str) -> List[VulnerabilityResult]:
        results: List[VulnerabilityResult] = []
        engine_pattern = re.compile(r"\bcreate_engine\s*\((?P<args>[^)]*)\)", re.IGNORECASE)
        direct_connect = re.compile(r"\b(?:psycopg2|pymysql|mysql\.connector)\.connect\s*\(")

        for match in engine_pattern.finditer(code):
            args = match.group("args").lower()
            has_pool_safety = "pool_pre_ping" in args and (
                "pool_size" in args or "poolclass" in args
            )
            if has_pool_safety:
                continue
            results.append(
                make_reliability_finding(
                    rule_id="sqlalchemy_engine_without_pool_safety",
                    title="SQLAlchemy engine without pool safety",
                    description=(
                        "Database engines without explicit pool sizing and pre-ping can fail "
                        "poorly under stale connections or traffic spikes."
                    ),
                    file_path=file_path,
                    code=code,
                    line_number=line_number_for_offset(code, match.start()),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    remediation="Set pool_size, max_overflow, pool_timeout, and pool_pre_ping=True.",
                )
            )

        for match in direct_connect.finditer(code):
            results.append(
                make_reliability_finding(
                    rule_id="direct_database_connect_without_pool",
                    title="Direct database connection without pool",
                    description="Opening raw database connections in service code bypasses pool controls.",
                    file_path=file_path,
                    code=code,
                    line_number=line_number_for_offset(code, match.start()),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    remediation="Use a managed connection pool with explicit limits and timeouts.",
                )
            )

        return results

    def _detect_javascript(self, code: str, file_path: str) -> List[VulnerabilityResult]:
        pool_pattern = re.compile(r"\bnew\s+(?:Pool|Client)\s*\((?P<args>[^)]*)\)")
        results: List[VulnerabilityResult] = []

        for match in pool_pattern.finditer(code):
            args = match.group("args").lower()
            if "connectiontimeoutmillis" in args and "max" in args:
                continue
            results.append(
                make_reliability_finding(
                    rule_id="javascript_db_client_without_pool_limits",
                    title="Database client without pool limits",
                    description="Node database pools should define max size and connection timeouts.",
                    file_path=file_path,
                    code=code,
                    line_number=line_number_for_offset(code, match.start()),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    remediation="Set max, idleTimeoutMillis, and connectionTimeoutMillis.",
                )
            )

        return results
