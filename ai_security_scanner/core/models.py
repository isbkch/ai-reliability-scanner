"""Core data models for the AI Reliability Scanner."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from dataclasses_json import dataclass_json


class Severity(Enum):
    """Finding severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(Enum):
    """Confidence levels for finding detection."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass_json
@dataclass
class Location:
    """Source code location information."""

    file_path: str
    line_number: int
    column_number: int = 0
    end_line_number: Optional[int] = None
    end_column_number: Optional[int] = None


@dataclass_json
@dataclass
class VulnerabilityResult:
    """Result of a reliability scan.

    The class name is retained for compatibility with the original scanner API.
    """

    id: str
    vulnerability_type: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    location: Location
    code_snippet: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    ai_explanation: Optional[str] = None
    false_positive_likelihood: Optional[float] = None


@dataclass_json
@dataclass
class ScanResult:
    """Complete scan result for a repository or file."""

    scan_id: str
    repository_url: Optional[str]
    repository_name: Optional[str]
    branch: Optional[str]
    commit_hash: Optional[str]
    scan_timestamp: datetime
    vulnerabilities: List[VulnerabilityResult]
    scan_duration: float
    files_scanned: int
    total_lines_scanned: int
    scanner_version: str
    configuration: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass_json
@dataclass
class PatternMatch:
    """A pattern match found during scanning."""

    pattern_id: str
    pattern_name: str
    location: Location
    matched_text: str
    context: str
    confidence_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass_json
@dataclass
class CodeEmbedding:
    """Code embedding representation."""

    code_hash: str
    embedding: List[float]
    model_name: str
    model_version: str
    created_at: datetime


@dataclass_json
@dataclass
class AnalysisContext:
    """Context for code analysis."""

    language: str
    framework: Optional[str] = None
    libraries: List[str] = field(default_factory=list)
    file_type: Optional[str] = None
    project_type: Optional[str] = None
    security_context: Dict[str, Any] = field(default_factory=dict)
