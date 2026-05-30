"""Database service layer for scan persistence."""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from ai_security_scanner.core.models import ScanResult, Severity, VulnerabilityResult
from ai_security_scanner.database.connection import DatabaseManager
from ai_security_scanner.database.repository import ScanRepository

logger = logging.getLogger(__name__)


class ScanPersistenceService:
    """Service for persisting scan results to database."""

    def __init__(self, db_manager: DatabaseManager):
        """Initialize the service.

        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager

    def save_scan_result(
        self,
        scan_result: ScanResult,
        persist_vulnerabilities: bool = True,
    ) -> bool:
        """Save scan result to database.

        Args:
            scan_result: Complete scan result
            persist_vulnerabilities: Whether to persist finding details

        Returns:
            True if successful, False otherwise
        """
        try:
            with self.db_manager.session_scope() as session:
                repository = ScanRepository(session)

                # Calculate severity counts
                severity_counts = self._calculate_severity_counts(scan_result.vulnerabilities)

                # Detect languages from findings.
                languages_detected = self._get_languages_from_vulnerabilities(
                    scan_result.vulnerabilities
                )

                # Create scan record
                scan_record = repository.create_scan(
                    scan_id=scan_result.scan_id,
                    target_path=scan_result.repository_name or "unknown",
                    target_type="directory",
                    scan_duration=scan_result.scan_duration,
                    files_scanned=scan_result.files_scanned,
                    total_lines_scanned=scan_result.total_lines_scanned,
                    scanner_version=scan_result.scanner_version,
                    repository_url=scan_result.repository_url,
                    repository_name=scan_result.repository_name,
                    branch=scan_result.branch,
                    commit_hash=scan_result.commit_hash,
                    languages_detected=languages_detected,
                    ai_analysis_enabled=scan_result.configuration.get("scanner", {}).get(
                        "enable_ai_analysis", False
                    ),
                    patterns_used=scan_result.configuration.get("scanner", {}).get("patterns", []),
                )

                # Update scan statistics
                repository.update_scan_stats(
                    scan_id=scan_result.scan_id,
                    total_vulnerabilities=len(scan_result.vulnerabilities),
                    severity_counts=severity_counts,
                )

                # Persist findings if requested.
                if persist_vulnerabilities:
                    for vuln in scan_result.vulnerabilities:
                        self._save_vulnerability(repository, scan_result.scan_id, vuln)

                session.commit()
                logger.info(
                    f"Saved scan result {scan_result.scan_id} with "
                    f"{len(scan_result.vulnerabilities)} findings"
                )
                return True

        except Exception as e:
            logger.error(f"Failed to save scan result: {e}")
            return False

    def _save_vulnerability(
        self,
        repository: ScanRepository,
        scan_id: str,
        vulnerability: VulnerabilityResult,
    ) -> None:
        """Save a single finding to database.

        Args:
            repository: Repository instance
            scan_id: Scan identifier
            vulnerability: Finding result
        """
        # Extract location information
        line_number = None
        column_number = None
        end_line_number = None
        end_column_number = None

        if vulnerability.location:
            line_number = vulnerability.location.line_number
            column_number = vulnerability.location.column_number
            end_line_number = vulnerability.location.end_line_number
            end_column_number = vulnerability.location.end_column_number

        repository.add_vulnerability(
            scan_id=scan_id,
            vulnerability_type=vulnerability.vulnerability_type,
            severity=vulnerability.severity,
            confidence=vulnerability.confidence,
            description=vulnerability.description,
            file_path=vulnerability.location.file_path if vulnerability.location else "",
            line_number=line_number,
            column_number=column_number,
            end_line_number=end_line_number,
            end_column_number=end_column_number,
            code_snippet=vulnerability.code_snippet,
            cwe_id=vulnerability.cwe_id,
            owasp_category=vulnerability.owasp_category,
            remediation=vulnerability.remediation,
            references=vulnerability.references,
            ai_analyzed=False,  # Set to True when AI analysis is applied
        )

    def _calculate_severity_counts(
        self, vulnerabilities: List[VulnerabilityResult]
    ) -> Dict[str, int]:
        """Calculate counts by severity level.

        Args:
            vulnerabilities: List of findings

        Returns:
            Dictionary mapping severity to count
        """
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for vuln in vulnerabilities:
            severity_str = (
                vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)
            )
            if severity_str in counts:
                counts[severity_str] += 1

        return counts

    def _get_languages_from_vulnerabilities(
        self, vulnerabilities: List[VulnerabilityResult]
    ) -> List[str]:
        """Extract unique languages from findings.

        Args:
            vulnerabilities: List of findings

        Returns:
            List of unique language names
        """
        languages = set()
        for vuln in vulnerabilities:
            # Try to infer language from file extension
            file_path = vuln.location.file_path if vuln.location else ""
            if file_path:
                ext = file_path.split(".")[-1].lower()
                language_map = {
                    "py": "python",
                    "js": "javascript",
                    "ts": "typescript",
                    "jsx": "javascript",
                    "tsx": "typescript",
                    "java": "java",
                    "go": "go",
                    "rb": "ruby",
                    "php": "php",
                }
                if ext in language_map:
                    languages.add(language_map[ext])

        return sorted(list(languages))

    def get_recent_scans(
        self,
        limit: int = 10,
        target_path: Optional[str] = None,
    ) -> List:
        """Get recent scan records.

        Args:
            limit: Maximum number of scans to return
            target_path: Optional filter by target path

        Returns:
            List of scan records
        """
        try:
            with self.db_manager.session_scope() as session:
                repository = ScanRepository(session)
                return repository.get_recent_scans(limit=limit, target_path=target_path)
        except Exception as e:
            logger.error(f"Failed to get recent scans: {e}")
            return []

    def compare_scans(
        self,
        baseline_scan_id: str,
        current_scan_id: str,
    ) -> Optional[Dict]:
        """Compare two scans for trend analysis.

        Args:
            baseline_scan_id: Baseline scan identifier
            current_scan_id: Current scan identifier

        Returns:
            Comparison result or None if failed
        """
        try:
            with self.db_manager.session_scope() as session:
                repository = ScanRepository(session)
                comparison = repository.create_scan_comparison(
                    baseline_scan_id=baseline_scan_id,
                    current_scan_id=current_scan_id,
                )

                if comparison:
                    return {
                        "new_vulnerabilities": comparison.new_vulnerabilities,
                        "fixed_vulnerabilities": comparison.fixed_vulnerabilities,
                        "persistent_vulnerabilities": comparison.persistent_vulnerabilities,
                        "overall_trend": comparison.overall_trend,
                    }

                return None

        except Exception as e:
            logger.error(f"Failed to compare scans: {e}")
            return None

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
        try:
            with self.db_manager.session_scope() as session:
                repository = ScanRepository(session)
                return repository.get_scan_statistics(
                    start_date=start_date,
                    end_date=end_date,
                )
        except Exception as e:
            logger.error(f"Failed to get scan statistics: {e}")
            return {
                "total_scans": 0,
                "total_vulnerabilities": 0,
                "avg_vulnerabilities_per_scan": 0.0,
                "total_files_scanned": 0,
                "avg_scan_duration": 0.0,
            }

    def update_vulnerability_status(
        self,
        vuln_id: str,
        status: str,
        fixed_in_commit: Optional[str] = None,
    ) -> bool:
        """Update finding status.

        Args:
            vuln_id: Finding UUID
            status: New status (open, fixed, false_positive, ignored)
            fixed_in_commit: Optional commit hash where fixed

        Returns:
            True if successful, False otherwise
        """
        try:
            from uuid import UUID

            with self.db_manager.session_scope() as session:
                repository = ScanRepository(session)
                vuln = repository.update_vulnerability_status(
                    vuln_uuid=UUID(vuln_id),
                    status=status,
                    fixed_at=datetime.utcnow() if status == "fixed" else None,
                    fixed_in_commit=fixed_in_commit,
                )

                if vuln:
                    session.commit()
                    logger.info(f"Updated finding {vuln_id} status to {status}")
                    return True

                return False

        except Exception as e:
            logger.error(f"Failed to update finding status: {e}")
            return False
