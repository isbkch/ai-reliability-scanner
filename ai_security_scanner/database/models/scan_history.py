"""Database models for scan history tracking."""

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy import (
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

from ai_security_scanner.core.models import Confidence, Severity

Base = declarative_base()


class ScanRecord(Base):
    """Record of a reliability scan."""

    __tablename__ = "scan_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(String(100), unique=True, nullable=False, index=True)

    # Scan metadata
    scan_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    scan_duration = Column(Float, nullable=False)  # Duration in seconds
    scanner_version = Column(String(50))

    # Scan target information
    target_type = Column(String(20))  # 'directory', 'file', 'repository'
    target_path = Column(Text)
    repository_url = Column(Text)
    repository_name = Column(String(200))
    branch = Column(String(100))
    commit_hash = Column(String(40))

    # Scan statistics
    files_scanned = Column(Integer, default=0)
    total_lines_scanned = Column(Integer, default=0)
    languages_detected = Column(JSON)  # List of detected languages

    # Configuration
    ai_analysis_enabled = Column(Boolean, default=False)
    patterns_used = Column(JSON)  # List of pattern names used

    # Results summary
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    # User information (optional)
    user_id = Column(String(100))
    user_email = Column(String(200))

    # Relationships
    vulnerabilities = relationship(
        "VulnerabilityRecord",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<ScanRecord(scan_id='{self.scan_id}', vulnerabilities={self.total_vulnerabilities})>"
        )


class VulnerabilityRecord(Base):
    """Record of a detected reliability finding.

    The class and table names are retained for compatibility with existing migrations.
    """

    __tablename__ = "vulnerability_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_records.id"), nullable=False, index=True)

    # Finding details
    vulnerability_type = Column(String(100), nullable=False)
    severity = Column(SAEnum(Severity), nullable=False, index=True)
    confidence = Column(SAEnum(Confidence), nullable=False)

    # Classification
    cwe_id = Column(String(20), index=True)
    owasp_category = Column(String(50))

    # Description and remediation
    description = Column(Text, nullable=False)
    remediation = Column(Text)
    explanation = Column(Text)  # AI-generated explanation

    # Location information
    file_path = Column(Text, nullable=False)
    line_number = Column(Integer)
    column_number = Column(Integer)
    end_line_number = Column(Integer)
    end_column_number = Column(Integer)

    # Code context
    code_snippet = Column(Text)

    # AI analysis
    ai_analyzed = Column(Boolean, default=False)
    false_positive_probability = Column(Float)  # 0.0 to 1.0
    ai_confidence = Column(Float)  # AI's confidence in the finding

    # References
    references = Column(JSON)  # List of reference URLs

    # Status tracking
    status = Column(String(20), default="open")  # open, fixed, false_positive, ignored
    fixed_at = Column(DateTime)
    fixed_in_commit = Column(String(40))

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scan = relationship("ScanRecord", back_populates="vulnerabilities")

    def __repr__(self) -> str:
        """String representation."""
        return f"<VulnerabilityRecord(type='{self.vulnerability_type}', severity='{self.severity.value}')>"


class ScanComparison(Base):
    """Comparison between two scans for trend analysis."""

    __tablename__ = "scan_comparisons"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Scan references
    baseline_scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_records.id"), nullable=False)
    current_scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_records.id"), nullable=False)

    # Comparison metadata
    comparison_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Comparison results
    new_vulnerabilities = Column(Integer, default=0)
    fixed_vulnerabilities = Column(Integer, default=0)
    persistent_vulnerabilities = Column(Integer, default=0)

    # Severity changes
    severity_increased = Column(Integer, default=0)
    severity_decreased = Column(Integer, default=0)

    # Detailed changes (JSON)
    changes_detail = Column(JSON)

    # Summary
    overall_trend = Column(String(20))  # 'improved', 'degraded', 'stable'
    risk_score_change = Column(Float)  # Change in risk score

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<ScanComparison(trend='{self.overall_trend}', "
            f"new={self.new_vulnerabilities}, fixed={self.fixed_vulnerabilities})>"
        )


class PatternUsage(Base):
    """Track pattern usage and effectiveness."""

    __tablename__ = "pattern_usage"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Pattern information
    pattern_name = Column(String(100), nullable=False, index=True)
    pattern_category = Column(String(50))
    cwe_id = Column(String(20), index=True)

    # Usage statistics
    times_triggered = Column(Integer, default=0)
    true_positives = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)

    # Effectiveness metrics
    accuracy_rate = Column(Float)  # true_positives / (true_positives + false_positives)
    avg_severity = Column(Float)

    # Timestamps
    first_used = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Statistics period
    stats_period_start = Column(DateTime)
    stats_period_end = Column(DateTime)

    def __repr__(self) -> str:
        """String representation."""
        return f"<PatternUsage(pattern='{self.pattern_name}', triggered={self.times_triggered})>"


class LLMUsageMetrics(Base):
    """Track LLM API usage and costs."""

    __tablename__ = "llm_usage_metrics"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_records.id"), nullable=False, index=True)

    # Provider information
    provider = Column(String(50), nullable=False)  # 'openai', 'anthropic', etc.
    model = Column(String(100), nullable=False)

    # Usage statistics
    total_requests = Column(Integer, default=0)
    successful_requests = Column(Integer, default=0)
    failed_requests = Column(Integer, default=0)

    # Token usage
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    total_tokens = Column(Integer, default=0)

    # Cost tracking
    estimated_cost = Column(Float, default=0.0)  # In USD
    cost_per_vulnerability = Column(Float)

    # Performance
    avg_response_time = Column(Float)  # In seconds
    total_api_time = Column(Float)  # Total time spent in API calls

    # Caching
    cache_hits = Column(Integer, default=0)
    cache_misses = Column(Integer, default=0)
    cache_hit_rate = Column(Float)

    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self) -> str:
        """String representation."""
        return f"<LLMUsageMetrics(provider='{self.provider}', cost=${self.estimated_cost:.4f})>"


# Import Boolean type that was missing
from sqlalchemy import Boolean
