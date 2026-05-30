"""Tests for database functionality."""

import os
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ai_security_scanner.core.config import DatabaseConfig
from ai_security_scanner.core.models import Confidence, Severity, VulnerabilityResult
from ai_security_scanner.database import (
    DatabaseManager,
    ScanPersistenceService,
    ScanRepository,
)
from ai_security_scanner.database.models import Base, ScanRecord, VulnerabilityRecord


@pytest.fixture
def db_config():
    """Create test database configuration."""
    return DatabaseConfig(
        host="localhost",
        port=5432,
        database="test_ai_security_scanner",
        username="test_user",
        password_env="TEST_DB_PASSWORD",
        ssl_mode="disable",
        pool_size=5,
    )


@pytest.fixture
def in_memory_engine():
    """Create an in-memory SQLite engine for testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def db_session(in_memory_engine):
    """Create a database session for testing."""
    Session = sessionmaker(bind=in_memory_engine)
    session = Session()
    yield session
    session.close()


class TestDatabaseManager:
    """Tests for DatabaseManager class."""

    def test_get_connection_url(self, db_config):
        """Test connection URL generation."""
        with patch.dict(os.environ, {"TEST_DB_PASSWORD": "testpass"}):
            manager = DatabaseManager(db_config)
            url = manager.get_connection_url()

            assert "postgresql://" in url
            assert "test_user:testpass" in url
            assert "localhost:5432" in url
        assert "test_ai_security_scanner" in url

    def test_create_engine(self, db_config):
        """Test engine creation."""
        manager = DatabaseManager(db_config)

        # Mock the connection to avoid actual DB connection
        with patch("ai_security_scanner.database.connection.create_engine") as mock_create:
            mock_engine = MagicMock()
            mock_create.return_value = mock_engine

            engine = manager.create_engine(echo=True)

            assert engine == mock_engine
            mock_create.assert_called_once()

    def test_session_scope(self, db_config):
        """Test session scope context manager."""
        manager = DatabaseManager(db_config)

        # Use in-memory database for testing
        manager._engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(manager._engine)

        manager.create_session_factory()

        # Test successful transaction
        with manager.session_scope() as session:
            assert session is not None

        # Test rollback on error
        with pytest.raises(ValueError):
            with manager.session_scope() as session:
                raise ValueError("Test error")


class TestScanRepository:
    """Tests for ScanRepository class."""

    def test_create_scan(self, db_session):
        """Test creating a scan record."""
        repo = ScanRepository(db_session)

        scan = repo.create_scan(
            scan_id="test-scan-123",
            target_path="/test/path",
            scan_duration=10.5,
            files_scanned=50,
            total_lines_scanned=1000,
            ai_analysis_enabled=True,
            scanner_version="1.0.0",
        )

        db_session.commit()

        assert scan.scan_id == "test-scan-123"
        assert scan.target_path == "/test/path"
        assert scan.scan_duration == 10.5
        assert scan.files_scanned == 50
        assert scan.total_lines_scanned == 1000
        assert scan.ai_analysis_enabled is True
        assert scan.scanner_version == "1.0.0"

    def test_get_scan_by_id(self, db_session):
        """Test retrieving scan by ID."""
        repo = ScanRepository(db_session)

        # Create scan
        created_scan = repo.create_scan(
            scan_id="test-scan-456",
            target_path="/test/path2",
            scan_duration=5.0,
        )
        db_session.commit()

        # Retrieve scan
        retrieved_scan = repo.get_scan_by_id("test-scan-456")

        assert retrieved_scan is not None
        assert retrieved_scan.scan_id == created_scan.scan_id
        assert retrieved_scan.target_path == created_scan.target_path

    def test_update_scan_stats(self, db_session):
        """Test updating scan statistics."""
        repo = ScanRepository(db_session)

        # Create scan
        repo.create_scan(
            scan_id="test-scan-789",
            target_path="/test/path3",
            scan_duration=7.5,
        )
        db_session.commit()

        # Update stats
        severity_counts = {
            "CRITICAL": 2,
            "HIGH": 5,
            "MEDIUM": 10,
            "LOW": 3,
        }

        updated_scan = repo.update_scan_stats(
            scan_id="test-scan-789",
            total_vulnerabilities=20,
            severity_counts=severity_counts,
        )

        assert updated_scan is not None
        assert updated_scan.total_vulnerabilities == 20
        assert updated_scan.critical_count == 2
        assert updated_scan.high_count == 5
        assert updated_scan.medium_count == 10
        assert updated_scan.low_count == 3

    def test_add_vulnerability(self, db_session):
        """Test adding a finding to a scan."""
        repo = ScanRepository(db_session)

        # Create scan
        repo.create_scan(
            scan_id="test-scan-vuln",
            target_path="/test/path",
            scan_duration=5.0,
        )
        db_session.commit()

        # Add finding
        vuln = repo.add_vulnerability(
            scan_id="test-scan-vuln",
            vulnerability_type="missing_http_timeout_python",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="HTTP call without timeout",
            file_path="/test/file.py",
            line_number=42,
        )

        assert vuln is not None
        assert vuln.vulnerability_type == "missing_http_timeout_python"
        assert vuln.severity == Severity.HIGH
        assert vuln.confidence == Confidence.HIGH
        assert vuln.line_number == 42

    def test_get_vulnerabilities_by_scan(self, db_session):
        """Test retrieving findings for a scan."""
        repo = ScanRepository(db_session)

        # Create scan
        repo.create_scan(
            scan_id="test-scan-vulns",
            target_path="/test/path",
            scan_duration=5.0,
        )
        db_session.commit()

        # Add multiple findings
        repo.add_vulnerability(
            scan_id="test-scan-vulns",
            vulnerability_type="service_without_health_check",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description="Service without health check",
            file_path="/test/file1.js",
        )

        repo.add_vulnerability(
            scan_id="test-scan-vulns",
            vulnerability_type="missing_http_timeout_python",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="HTTP call without timeout",
            file_path="/test/file2.js",
        )

        db_session.commit()

        # Retrieve all findings
        vulns = repo.get_vulnerabilities_by_scan("test-scan-vulns")

        assert len(vulns) == 2

        # Filter by severity
        high_vulns = repo.get_vulnerabilities_by_scan("test-scan-vulns", severity=Severity.HIGH)

        assert len(high_vulns) == 1
        assert high_vulns[0].vulnerability_type == "missing_http_timeout_python"

    def test_get_scan_statistics(self, db_session):
        """Test retrieving aggregated scan statistics."""
        repo = ScanRepository(db_session)

        # Create multiple scans
        for i in range(3):
            repo.create_scan(
                scan_id=f"test-scan-stats-{i}",
                target_path=f"/test/path{i}",
                scan_duration=5.0 + i,
                files_scanned=10 * (i + 1),
            )
            repo.update_scan_stats(
                scan_id=f"test-scan-stats-{i}",
                total_vulnerabilities=5 * (i + 1),
                severity_counts={},
            )

        db_session.commit()

        # Get statistics
        stats = repo.get_scan_statistics()

        assert stats["total_scans"] == 3
        assert stats["total_vulnerabilities"] == 30  # 5 + 10 + 15
        assert stats["total_files_scanned"] == 60  # 10 + 20 + 30


class TestScanPersistenceService:
    """Tests for ScanPersistenceService class."""

    def test_save_scan_result(self, db_session, in_memory_engine):
        """Test saving complete scan result."""
        # Create manager with in-memory database
        manager = DatabaseManager(DatabaseConfig())
        manager._engine = in_memory_engine
        manager._session_factory = sessionmaker(bind=in_memory_engine)

        service = ScanPersistenceService(manager)

        # Create mock scan result
        from ai_security_scanner.core.models import Location, ScanResult

        vulnerabilities = [
            VulnerabilityResult(
                id="finding-1",
                vulnerability_type="missing_http_timeout_python",
                title="HTTP call without timeout",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="HTTP call without timeout",
                location=Location(
                    file_path="/test/file.py",
                    line_number=10,
                    column_number=1,
                    end_line_number=10,
                    end_column_number=50,
                ),
                code_snippet="requests.get(url)",
                remediation="Pass timeout=...",
            )
        ]

        scan_result = ScanResult(
            scan_id="test-service-scan",
            repository_name="test-repo",
            repository_url="https://github.com/test/repo",
            branch="main",
            commit_hash="abc123",
            scan_timestamp=datetime.now(),
            vulnerabilities=vulnerabilities,
            scan_duration=10.0,
            files_scanned=5,
            total_lines_scanned=500,
            scanner_version="1.0.0",
            configuration={
                "scanner": {
                    "enable_ai_analysis": True,
                    "patterns": ["reliability-readiness"],
                }
            },
            metrics={},
        )

        # Save to database
        success = service.save_scan_result(scan_result)

        assert success is True

        # Verify scan was saved
        with manager.session_scope() as session:
            repo = ScanRepository(session)
            saved_scan = repo.get_scan_by_id("test-service-scan")

            assert saved_scan is not None
            assert saved_scan.total_vulnerabilities == 1
            assert saved_scan.high_count == 1

            # Verify vulnerability was saved
            vulns = repo.get_vulnerabilities_by_scan("test-service-scan")
            assert len(vulns) == 1
            assert vulns[0].vulnerability_type == "missing_http_timeout_python"

    def test_get_recent_scans(self, in_memory_engine):
        """Test retrieving recent scans."""
        manager = DatabaseManager(DatabaseConfig())
        manager._engine = in_memory_engine
        manager._session_factory = sessionmaker(bind=in_memory_engine)

        service = ScanPersistenceService(manager)

        # Create some test scans directly in database
        with manager.session_scope() as session:
            repo = ScanRepository(session)
            for i in range(5):
                repo.create_scan(
                    scan_id=f"recent-scan-{i}",
                    target_path=f"/test/path{i}",
                    scan_duration=5.0,
                )

        # Get recent scans
        recent_scans = service.get_recent_scans(limit=3)

        assert len(recent_scans) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
