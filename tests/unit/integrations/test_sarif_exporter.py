"""Tests for reliability SARIF exporter."""

from datetime import datetime

import pytest

from ai_security_scanner.core.models import (
    Confidence,
    Location,
    ScanResult,
    Severity,
    VulnerabilityResult,
)
from ai_security_scanner.integrations.sarif.exporter import SARIFExporter


@pytest.fixture
def sample_scan_result() -> ScanResult:
    """Create sample reliability scan result for testing."""
    return ScanResult(
        scan_id="test-123",
        repository_url=None,
        repository_name="service",
        branch=None,
        commit_hash=None,
        files_scanned=2,
        total_lines_scanned=100,
        scan_duration=1.5,
        scan_timestamp=datetime(2024, 1, 1, 12, 0, 0),
        scanner_version="0.1.0",
        vulnerabilities=[
            VulnerabilityResult(
                id="finding-1",
                vulnerability_type="missing_http_timeout_python",
                title="HTTP call without timeout",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="Outbound HTTP call without timeout",
                location=Location(file_path="client.py", line_number=42, column_number=10),
                code_snippet=">>>   42: requests.get(url)",
                remediation="Pass timeout=...",
            ),
            VulnerabilityResult(
                id="finding-2",
                vulnerability_type="service_without_health_check",
                title="Service without health endpoint",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                description="Service does not expose health or readiness checks",
                location=Location(file_path="service.py", line_number=15),
                code_snippet=">>>   15: app = FastAPI()",
            ),
        ],
    )


class TestSARIFExporter:
    """Test SARIF exporter functionality."""

    def test_export_creates_valid_sarif(self, sample_scan_result: ScanResult) -> None:
        """Test that export creates valid SARIF 2.1.0 document."""
        sarif = SARIFExporter().export(sample_scan_result)

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_export_includes_tool_info(self, sample_scan_result: ScanResult) -> None:
        """Test that SARIF includes reliability tool information."""
        sarif = SARIFExporter().export(sample_scan_result)

        tool = sarif["runs"][0]["tool"]["driver"]
        assert tool["name"] == "AI Reliability Scanner"
        assert "version" in tool
        assert "informationUri" in tool

    def test_export_includes_all_results(self, sample_scan_result: ScanResult) -> None:
        """Test that all findings are included as results."""
        sarif = SARIFExporter().export(sample_scan_result)

        results = sarif["runs"][0]["results"]
        assert len(results) == 2

    def test_export_includes_reliability_rules(self, sample_scan_result: ScanResult) -> None:
        """Test that reliability pattern families are exported as rules."""
        sarif = SARIFExporter().export(sample_scan_result)

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [rule["id"] for rule in rules]
        assert "timeouts" in rule_ids
        assert "health_checks" in rule_ids
        assert "sql_injection" not in rule_ids

    def test_export_maps_severity_correctly(self, sample_scan_result: ScanResult) -> None:
        """Test that severity is mapped to SARIF levels."""
        sarif = SARIFExporter().export(sample_scan_result)

        results = sarif["runs"][0]["results"]
        high_result = next(r for r in results if "timeout" in r["message"]["text"])
        medium_result = next(r for r in results if "health" in r["message"]["text"])

        assert high_result["level"] == "error"
        assert medium_result["level"] == "warning"

    def test_export_empty_scan_result(self) -> None:
        """Test exporting scan result with no findings."""
        empty_result = ScanResult(
            scan_id="empty",
            repository_url=None,
            repository_name="service",
            branch=None,
            commit_hash=None,
            files_scanned=10,
            total_lines_scanned=1000,
            scan_duration=0.5,
            scan_timestamp=datetime.now(),
            scanner_version="0.1.0",
            vulnerabilities=[],
        )

        sarif = SARIFExporter().export(empty_result)

        assert len(sarif["runs"][0]["results"]) == 0
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "AI Reliability Scanner"


@pytest.mark.unit
class TestSARIFLocationMapping:
    """Test SARIF location mapping."""

    def test_location_includes_file_path(self, sample_scan_result: ScanResult) -> None:
        """Test that file path is included in location."""
        sarif = SARIFExporter().export(sample_scan_result)

        result = sarif["runs"][0]["results"][0]
        location = result["locations"][0]["physicalLocation"]

        assert "artifactLocation" in location
        assert location["artifactLocation"]["uri"] == "client.py"

    def test_location_includes_line_and_column(self, sample_scan_result: ScanResult) -> None:
        """Test that line and column numbers are included."""
        sarif = SARIFExporter().export(sample_scan_result)

        result = sarif["runs"][0]["results"][0]
        region = result["locations"][0]["physicalLocation"]["region"]

        assert region["startLine"] == 42
        assert region.get("startColumn") == 10
