"""Basic tests for the reliability scanner."""

import asyncio
import os
import tempfile
from unittest.mock import patch

import pytest

from ai_security_scanner import __version__
from ai_security_scanner.core.config import Config
from ai_security_scanner.core.models import Severity
from ai_security_scanner.core.scanner import SecurityScanner


class TestSecurityScanner:
    """Test cases for the scanner orchestrator."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.config = Config()
        self.config.scanner.enable_ai_analysis = False
        self.scanner = SecurityScanner(self.config)

    def test_scan_missing_python_http_timeout(self) -> None:
        """Detect Python outbound calls without timeouts."""
        code = "import requests\nrequests.get(service_url)\n"

        findings = self.scanner.scan_code(code, "python", "client.py")

        assert any(f.vulnerability_type == "missing_http_timeout_python" for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_scan_service_without_health_check(self) -> None:
        """Detect service apps without health or readiness endpoints."""
        code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/predict")
def predict():
    return {"ok": True}
"""

        findings = self.scanner.scan_code(code, "python", "service.py")

        assert any(f.vulnerability_type == "service_without_health_check" for f in findings)

    def test_scan_mutating_endpoint_without_idempotency_key(self) -> None:
        """Detect risky mutating endpoints without idempotency controls."""
        code = """
@app.post("/payments")
def create_payment():
    return charge_card()
"""

        findings = self.scanner.scan_code(code, "python", "payments.py")

        assert any(
            f.vulnerability_type == "mutating_endpoint_without_idempotency_key" for f in findings
        )

    def test_scan_clean_reliability_code(self) -> None:
        """Avoid flagging common reliability controls."""
        code = """
import logging
import requests
from fastapi import FastAPI

app = FastAPI()
logger = logging.getLogger(__name__)

@app.get("/health")
def health():
    return {"ok": True}

def call_dependency():
    return requests.get(service_url, timeout=5)
"""

        findings = self.scanner.scan_code(code, "python", "service.py")
        ids = {finding.vulnerability_type for finding in findings}

        assert "missing_http_timeout_python" not in ids
        assert "service_without_health_check" not in ids

    def test_unsupported_language(self) -> None:
        """Test scanning with unsupported language."""
        with pytest.raises(ValueError, match="Language unsupported_lang not supported"):
            self.scanner.scan_code("some code", "unsupported_lang", "test.txt")

    def test_get_supported_languages(self) -> None:
        """Test getting supported languages."""
        languages = self.scanner.get_supported_languages()
        assert isinstance(languages, list)
        assert "python" in languages
        assert "javascript" in languages

    def test_get_loaded_patterns(self) -> None:
        """Test getting loaded reliability patterns."""
        patterns = self.scanner.get_loaded_patterns()
        assert isinstance(patterns, list)
        assert "Timeout Hygiene" in patterns

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_file")
    def test_scan_nonexistent_file(self, mock_is_file, mock_exists) -> None:
        """Test scanning non-existent file."""
        mock_exists.return_value = False
        mock_is_file.return_value = False

        findings = self.scanner.scan_file("nonexistent.py")
        assert len(findings) == 0

    def test_scan_result_version(self) -> None:
        """Test that sync scan results include the package version."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.py")
            with open(test_file, "w") as f:
                f.write("print('hello world')")

            scan_result = self.scanner.scan_directory(tmpdir)

            assert scan_result.scanner_version == __version__
            assert scan_result.scanner_version == "0.1.0"

    def test_scan_result_version_async(self) -> None:
        """Test that async scan results include the package version."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.py")
            with open(test_file, "w") as f:
                f.write("print('hello world')")

            scan_result = asyncio.run(self.scanner.scan_directory_async(tmpdir))

            assert scan_result.scanner_version == __version__
            assert scan_result.scanner_version == "0.1.0"
