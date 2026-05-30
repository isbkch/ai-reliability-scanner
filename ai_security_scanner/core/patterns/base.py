"""Base classes for scanner patterns."""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Pattern

from ai_security_scanner.core.models import Confidence, Location, Severity, VulnerabilityResult


class PatternType(Enum):
    """Types of scanner patterns."""

    REGEX = "regex"
    AST = "ast"
    SEMANTIC = "semantic"
    CUSTOM = "custom"


@dataclass
class PatternRule:
    """Individual pattern rule."""

    id: str
    name: str
    pattern: str
    pattern_type: PatternType
    severity: Severity
    confidence: Confidence
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    description: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    languages: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Compile regex patterns."""
        if self.pattern_type == PatternType.REGEX:
            self.compiled_pattern = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        else:
            self.compiled_pattern = None


class VulnerabilityPattern(ABC):
    """Base class for finding detection patterns.

    The class name is retained for compatibility with the original scanner API.
    """

    def __init__(
        self, name: str, description: str, severity: Severity, cwe_id: Optional[str] = None
    ):
        self.name = name
        self.description = description
        self.severity = severity
        self.cwe_id = cwe_id
        self.rules: List[PatternRule] = []
        self.supported_languages: List[str] = []

    @abstractmethod
    def detect(self, code: str, file_path: str, language: str) -> List[VulnerabilityResult]:
        """Detect findings in the given code."""
        pass

    def add_rule(self, rule: PatternRule) -> None:
        """Add a pattern rule."""
        self.rules.append(rule)

    def is_supported_language(self, language: str) -> bool:
        """Check if language is supported."""
        return not self.supported_languages or language in self.supported_languages

    def _create_vulnerability_result(
        self,
        rule: PatternRule,
        location: Location,
        code_snippet: str,
        file_path: str,
        match_text: str = "",
        additional_context: Optional[Dict[str, Any]] = None,
    ) -> VulnerabilityResult:
        """Create a finding result from a pattern rule."""
        import uuid

        metadata = rule.metadata.copy()
        if additional_context:
            metadata.update(additional_context)

        return VulnerabilityResult(
            id=str(uuid.uuid4()),
            vulnerability_type=rule.id,
            title=rule.name,
            description=rule.description,
            severity=rule.severity,
            confidence=rule.confidence,
            location=location,
            code_snippet=code_snippet,
            cwe_id=rule.cwe_id,
            owasp_category=rule.owasp_category,
            remediation=rule.remediation,
            references=rule.references,
            metadata=metadata,
        )

    def _extract_code_snippet(self, code: str, line_number: int, context_lines: int = 3) -> str:
        """Extract code snippet with context."""
        lines = code.split("\n")
        start_line = max(0, line_number - context_lines - 1)
        end_line = min(len(lines), line_number + context_lines)

        snippet_lines = []
        for i in range(start_line, end_line):
            line_num = i + 1
            prefix = ">>> " if line_num == line_number else "    "
            snippet_lines.append(f"{prefix}{line_num:4d}: {lines[i]}")

        return "\n".join(snippet_lines)

    def _find_regex_matches(
        self, rule: PatternRule, code: str, file_path: str
    ) -> List[VulnerabilityResult]:
        """Find matches using regex patterns."""
        if not rule.compiled_pattern:
            return []

        results = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            matches = rule.compiled_pattern.finditer(line)
            for match in matches:
                location = Location(
                    file_path=file_path,
                    line_number=line_num,
                    column_number=match.start() + 1,
                    end_column_number=match.end() + 1,
                )

                code_snippet = self._extract_code_snippet(code, line_num)

                result = self._create_vulnerability_result(
                    rule=rule,
                    location=location,
                    code_snippet=code_snippet,
                    file_path=file_path,
                    match_text=match.group(0),
                    additional_context={"regex_match": match.group(0)},
                )

                results.append(result)

        return results


class RegexPattern(VulnerabilityPattern):
    """Regex-based finding pattern."""

    def detect(self, code: str, file_path: str, language: str) -> List[VulnerabilityResult]:
        """Detect findings using regex patterns."""
        if not self.is_supported_language(language):
            return []

        results = []
        for rule in self.rules:
            if rule.enabled and (not rule.languages or language in rule.languages):
                if rule.pattern_type == PatternType.REGEX:
                    rule_results = self._find_regex_matches(rule, code, file_path)
                    results.extend(rule_results)

        return results


class ASTPattern(VulnerabilityPattern):
    """AST-based finding pattern."""

    def detect(self, code: str, file_path: str, language: str) -> List[VulnerabilityResult]:
        """Detect findings using AST analysis."""
        if not self.is_supported_language(language):
            return []

        # This would be implemented with tree-sitter or language-specific AST parsers
        # For now, return empty list - will be implemented in parsers
        return []


class SemanticPattern(VulnerabilityPattern):
    """Semantic analysis-based finding pattern."""

    def detect(self, code: str, file_path: str, language: str) -> List[VulnerabilityResult]:
        """Detect findings using semantic analysis."""
        if not self.is_supported_language(language):
            return []

        # This would be implemented with CodeBERT embeddings and ML models
        # For now, return empty list - will be implemented in models module
        return []
