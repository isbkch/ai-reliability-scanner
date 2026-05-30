"""Repository layer for database operations."""

import logging
from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy import and_, desc, func
from sqlalchemy.orm import Session

from ai_security_scanner.core.models import Confidence, Severity
from ai_security_scanner.database.models import (
    LLMUsageMetrics,
    PatternUsage,
    ScanComparison,
    ScanRecord,
    VulnerabilityRecord,
)

logger = logging.getLogger(__name__)


class ScanRepository:
    """Repository for scan-related database operations."""

    def __init__(self, session: Session):
        """Initialize repository.

        Args:
            session: SQLAlchemy session
        """
        self.session = session

    def create_scan(
        self,
        scan_id: str,
        target_path: str,
        scan_duration: float,
        files_scanned: int = 0,
        total_lines_scanned: int = 0,
        ai_analysis_enabled: bool = False,
        scanner_version: Optional[str] = None,
        **kwargs,
    ) -> ScanRecord:
        """Create a new scan record.

        Args:
            scan_id: Unique scan identifier
            target_path: Path to scanned target
            scan_duration: Duration of scan in seconds
            files_scanned: Number of files scanned
            total_lines_scanned: Total lines of code scanned
            ai_analysis_enabled: Whether AI analysis was enabled
            scanner_version: Version of the scanner
            **kwargs: Additional scan metadata

        Returns:
            Created ScanRecord instance
        """
        scan_record = ScanRecord(
            scan_id=scan_id,
            target_path=target_path,
            scan_duration=scan_duration,
            files_scanned=files_scanned,
            total_lines_scanned=total_lines_scanned,
            ai_analysis_enabled=ai_analysis_enabled,
            scanner_version=scanner_version,
            **kwargs,
        )

        self.session.add(scan_record)
        self.session.flush()  # Get the ID without committing

        logger.info(f"Created scan record: {scan_id}")
        return scan_record

    def get_scan_by_id(self, scan_id: str) -> Optional[ScanRecord]:
        """Get scan record by scan ID.

        Args:
            scan_id: Scan identifier

        Returns:
            ScanRecord if found, None otherwise
        """
        return self.session.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()

    def get_scan_by_uuid(self, uuid: UUID) -> Optional[ScanRecord]:
        """Get scan record by UUID.

        Args:
            uuid: Scan UUID

        Returns:
            ScanRecord if found, None otherwise
        """
        return self.session.query(ScanRecord).filter(ScanRecord.id == uuid).first()

    def get_recent_scans(
        self, limit: int = 10, target_path: Optional[str] = None
    ) -> List[ScanRecord]:
        """Get recent scan records.

        Args:
            limit: Maximum number of scans to return
            target_path: Optional filter by target path

        Returns:
            List of ScanRecord instances
        """
        query = self.session.query(ScanRecord).order_by(desc(ScanRecord.scan_timestamp))

        if target_path:
            query = query.filter(ScanRecord.target_path == target_path)

        return query.limit(limit).all()

    def update_scan_stats(
        self,
        scan_id: str,
        total_vulnerabilities: int,
        severity_counts: Dict[str, int],
    ) -> Optional[ScanRecord]:
        """Update scan statistics.

        Args:
            scan_id: Scan identifier
            total_vulnerabilities: Total number of findings
            severity_counts: Dictionary mapping severity levels to counts

        Returns:
            Updated ScanRecord if found, None otherwise
        """
        scan = self.get_scan_by_id(scan_id)
        if scan:
            scan.total_vulnerabilities = total_vulnerabilities
            scan.critical_count = severity_counts.get("CRITICAL", 0)
            scan.high_count = severity_counts.get("HIGH", 0)
            scan.medium_count = severity_counts.get("MEDIUM", 0)
            scan.low_count = severity_counts.get("LOW", 0)

            logger.info(f"Updated scan stats for {scan_id}: {total_vulnerabilities} findings")

        return scan

    def add_vulnerability(
        self,
        scan_id: str,
        vulnerability_type: str,
        severity: Severity,
        confidence: Confidence,
        description: str,
        file_path: str,
        line_number: Optional[int] = None,
        **kwargs,
    ) -> Optional[VulnerabilityRecord]:
        """Add a finding to a scan.

        Args:
            scan_id: Scan identifier
            vulnerability_type: Type of finding
            severity: Severity level
            confidence: Confidence level
            description: Finding description
            file_path: Path to finding file
            line_number: Line number of finding
            **kwargs: Additional finding metadata

        Returns:
            Created record if scan found, None otherwise
        """
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            logger.error(f"Scan not found: {scan_id}")
            return None

        vuln_record = VulnerabilityRecord(
            scan_id=scan.id,
            vulnerability_type=vulnerability_type,
            severity=severity,
            confidence=confidence,
            description=description,
            file_path=file_path,
            line_number=line_number,
            **kwargs,
        )

        self.session.add(vuln_record)
        self.session.flush()

        logger.debug(f"Added finding to scan {scan_id}: {vulnerability_type}")
        return vuln_record

    def get_vulnerabilities_by_scan(
        self,
        scan_id: str,
        severity: Optional[Severity] = None,
        status: Optional[str] = None,
    ) -> List[VulnerabilityRecord]:
        """Get findings for a scan.

        Args:
            scan_id: Scan identifier
            severity: Optional filter by severity
            status: Optional filter by status

        Returns:
            List of finding records
        """
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            return []

        query = self.session.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.scan_id == scan.id
        )

        if severity:
            query = query.filter(VulnerabilityRecord.severity == severity)

        if status:
            query = query.filter(VulnerabilityRecord.status == status)

        return query.all()

    def get_vulnerability_by_uuid(self, uuid: UUID) -> Optional[VulnerabilityRecord]:
        """Get finding by UUID.

        Args:
            uuid: Finding UUID

        Returns:
            Finding record if found, None otherwise
        """
        return (
            self.session.query(VulnerabilityRecord).filter(VulnerabilityRecord.id == uuid).first()
        )

    def update_vulnerability_status(
        self,
        vuln_uuid: UUID,
        status: str,
        fixed_at: Optional[datetime] = None,
        fixed_in_commit: Optional[str] = None,
    ) -> Optional[VulnerabilityRecord]:
        """Update finding status.

        Args:
            vuln_uuid: Finding UUID
            status: New status
            fixed_at: Timestamp when fixed
            fixed_in_commit: Commit hash where fixed

        Returns:
            Updated finding record if found, None otherwise
        """
        vuln = self.get_vulnerability_by_uuid(vuln_uuid)
        if vuln:
            vuln.status = status
            if fixed_at:
                vuln.fixed_at = fixed_at
            if fixed_in_commit:
                vuln.fixed_in_commit = fixed_in_commit

            logger.info(f"Updated finding status: {vuln_uuid} -> {status}")

        return vuln

    def create_scan_comparison(
        self,
        baseline_scan_id: str,
        current_scan_id: str,
    ) -> Optional[ScanComparison]:
        """Create a comparison between two scans.

        Args:
            baseline_scan_id: Baseline scan identifier
            current_scan_id: Current scan identifier

        Returns:
            ScanComparison if both scans found, None otherwise
        """
        baseline = self.get_scan_by_id(baseline_scan_id)
        current = self.get_scan_by_id(current_scan_id)

        if not baseline or not current:
            logger.error("One or both scans not found for comparison")
            return None

        # Get findings for both scans.
        baseline_vulns = set(
            (v.vulnerability_type, v.file_path, v.line_number)
            for v in self.get_vulnerabilities_by_scan(baseline_scan_id)
        )

        current_vulns = set(
            (v.vulnerability_type, v.file_path, v.line_number)
            for v in self.get_vulnerabilities_by_scan(current_scan_id)
        )

        # Calculate differences
        new_vulns = current_vulns - baseline_vulns
        fixed_vulns = baseline_vulns - current_vulns
        persistent_vulns = baseline_vulns & current_vulns

        # Determine trend
        if len(new_vulns) > len(fixed_vulns):
            trend = "degraded"
        elif len(new_vulns) < len(fixed_vulns):
            trend = "improved"
        else:
            trend = "stable"

        comparison = ScanComparison(
            baseline_scan_id=baseline.id,
            current_scan_id=current.id,
            new_vulnerabilities=len(new_vulns),
            fixed_vulnerabilities=len(fixed_vulns),
            persistent_vulnerabilities=len(persistent_vulns),
            overall_trend=trend,
        )

        self.session.add(comparison)
        self.session.flush()

        logger.info(
            f"Created scan comparison: {baseline_scan_id} -> {current_scan_id} (trend: {trend})"
        )
        return comparison

    def add_llm_usage_metrics(
        self,
        scan_id: str,
        provider: str,
        model: str,
        total_requests: int = 0,
        successful_requests: int = 0,
        failed_requests: int = 0,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        estimated_cost: float = 0.0,
        **kwargs,
    ) -> Optional[LLMUsageMetrics]:
        """Add LLM usage metrics for a scan.

        Args:
            scan_id: Scan identifier
            provider: LLM provider name
            model: Model name
            total_requests: Total number of requests
            successful_requests: Number of successful requests
            failed_requests: Number of failed requests
            prompt_tokens: Number of prompt tokens used
            completion_tokens: Number of completion tokens used
            estimated_cost: Estimated cost in USD
            **kwargs: Additional metrics

        Returns:
            Created LLMUsageMetrics if scan found, None otherwise
        """
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            logger.error(f"Scan not found: {scan_id}")
            return None

        total_tokens = prompt_tokens + completion_tokens

        metrics = LLMUsageMetrics(
            scan_id=scan.id,
            provider=provider,
            model=model,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            estimated_cost=estimated_cost,
            **kwargs,
        )

        self.session.add(metrics)
        self.session.flush()

        logger.info(f"Added LLM usage metrics for scan {scan_id}")
        return metrics

    def update_pattern_usage(
        self,
        pattern_name: str,
        cwe_id: Optional[str] = None,
        is_true_positive: bool = True,
    ) -> PatternUsage:
        """Update or create pattern usage statistics.

        Args:
            pattern_name: Pattern name
            cwe_id: CWE identifier
            is_true_positive: Whether the detection was a true positive

        Returns:
            PatternUsage record
        """
        # Try to find existing record
        pattern_usage = (
            self.session.query(PatternUsage)
            .filter(PatternUsage.pattern_name == pattern_name)
            .first()
        )

        if not pattern_usage:
            # Create new record
            pattern_usage = PatternUsage(
                pattern_name=pattern_name,
                cwe_id=cwe_id,
                times_triggered=0,
                true_positives=0,
                false_positives=0,
            )
            self.session.add(pattern_usage)

        # Update statistics
        pattern_usage.times_triggered += 1
        pattern_usage.last_used = datetime.utcnow()

        if is_true_positive:
            pattern_usage.true_positives += 1
        else:
            pattern_usage.false_positives += 1

        # Calculate accuracy rate
        total = pattern_usage.true_positives + pattern_usage.false_positives
        if total > 0:
            pattern_usage.accuracy_rate = pattern_usage.true_positives / total

        self.session.flush()
        return pattern_usage

    def get_pattern_statistics(self, limit: int = 50) -> List[PatternUsage]:
        """Get pattern usage statistics.

        Args:
            limit: Maximum number of records to return

        Returns:
            List of PatternUsage records ordered by usage
        """
        return (
            self.session.query(PatternUsage)
            .order_by(desc(PatternUsage.times_triggered))
            .limit(limit)
            .all()
        )

    def get_scan_statistics(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict:
        """Get aggregated scan statistics.

        Args:
            start_date: Start date for filtering
            end_date: End date for filtering

        Returns:
            Dictionary with aggregated statistics
        """
        query = self.session.query(ScanRecord)

        if start_date:
            query = query.filter(ScanRecord.scan_timestamp >= start_date)
        if end_date:
            query = query.filter(ScanRecord.scan_timestamp <= end_date)

        total_scans = query.count()

        if total_scans == 0:
            return {
                "total_scans": 0,
                "total_vulnerabilities": 0,
                "avg_vulnerabilities_per_scan": 0.0,
                "total_files_scanned": 0,
                "avg_scan_duration": 0.0,
            }

        stats = query.with_entities(
            func.count(ScanRecord.id).label("total"),
            func.sum(ScanRecord.total_vulnerabilities).label("total_vulns"),
            func.avg(ScanRecord.total_vulnerabilities).label("avg_vulns"),
            func.sum(ScanRecord.files_scanned).label("total_files"),
            func.avg(ScanRecord.scan_duration).label("avg_duration"),
        ).first()

        return {
            "total_scans": stats.total or 0,
            "total_vulnerabilities": stats.total_vulns or 0,
            "avg_vulnerabilities_per_scan": float(stats.avg_vulns or 0.0),
            "total_files_scanned": stats.total_files or 0,
            "avg_scan_duration": float(stats.avg_duration or 0.0),
        }
