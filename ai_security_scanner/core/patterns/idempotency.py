"""Reliability patterns for idempotency controls."""

import re
from typing import List

from ai_security_scanner.core.models import Confidence, Severity, VulnerabilityResult
from ai_security_scanner.core.patterns.reliability_base import (
    ReliabilityPattern,
    line_number_for_offset,
    make_reliability_finding,
)


class IdempotencyPattern(ReliabilityPattern):
    """Detect mutating endpoints without idempotency safeguards."""

    def __init__(self) -> None:
        super().__init__(
            name="Idempotency Controls",
            description="Detects mutating HTTP handlers without idempotency-key handling.",
            severity=Severity.HIGH,
        )
        self.supported_languages = ["python", "javascript"]

    def detect(self, code: str, file_path: str, language: str) -> List[VulnerabilityResult]:
        """Detect mutating endpoints without idempotency key handling."""
        if not self.is_supported_language(language):
            return []

        has_idempotency = "idempotency-key" in code.lower() or "idempotency_key" in code.lower()
        if has_idempotency:
            return []

        mutating_route = re.compile(
            r"(?:@app\.(?:post|put|patch|delete)\s*\(|\bapp\.(?:post|put|patch|delete)\s*\()",
            re.IGNORECASE,
        )
        risky_terms = ("payment", "charge", "create", "provision", "order", "invoice")

        results: List[VulnerabilityResult] = []
        for match in mutating_route.finditer(code):
            window = code[match.start() : match.start() + 400].lower()
            if not any(term in window for term in risky_terms):
                continue
            results.append(
                make_reliability_finding(
                    rule_id="mutating_endpoint_without_idempotency_key",
                    title="Mutating endpoint without idempotency key",
                    description=(
                        "Retrying mutating requests without idempotency controls can duplicate "
                        "payments, orders, jobs, or side effects."
                    ),
                    file_path=file_path,
                    code=code,
                    line_number=line_number_for_offset(code, match.start()),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    remediation="Require and persist an Idempotency-Key for non-idempotent operations.",
                )
            )

        return results
