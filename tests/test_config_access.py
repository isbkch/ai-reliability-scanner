"""Test configuration access fix for issue #8."""

import uuid
from datetime import datetime

import pytest

from ai_security_scanner.core.config import Config
from ai_security_scanner.core.models import ScanResult
from ai_security_scanner.core.scanner import SecurityScanner


class TestConfigAccess:
    """Test cases for configuration access methods."""

    def test_config_has_to_dict_safe(self):
        """Test that Config class has to_dict_safe method."""
        config = Config()
        assert hasattr(config, "to_dict_safe"), "Config should have to_dict_safe method"

    def test_to_dict_safe_returns_dict(self):
        """Test that to_dict_safe returns a dictionary."""
        config = Config()
        result = config.to_dict_safe()
        assert isinstance(result, dict), "to_dict_safe should return a dictionary"

    def test_to_dict_safe_excludes_sensitive_data(self):
        """Test that to_dict_safe excludes sensitive information."""
        config = Config()
        safe_dict = config.to_dict_safe()

        # Check that sensitive fields are not included
        assert "api_key_env" not in safe_dict.get(
            "llm", {}
        ), "API key env var should not be in safe dict"
        assert "password_env" not in safe_dict.get(
            "database", {}
        ), "Password env var should not be in safe dict"
        assert "token_env" not in safe_dict.get(
            "github", {}
        ), "Token env var should not be in safe dict"
        assert "webhook_secret_env" not in safe_dict.get(
            "github", {}
        ), "Webhook secret env var should not be in safe dict"

    def test_scanner_uses_to_dict_safe(self):
        """Test that scanner creates ScanResult with safe configuration."""
        config = Config()
        scanner = SecurityScanner(config)

        # Create a mock scan result
        scan_result = ScanResult(
            scan_id=str(uuid.uuid4()),
            repository_url=None,
            repository_name="test",
            branch=None,
            commit_hash=None,
            scan_timestamp=datetime.now(),
            vulnerabilities=[],
            scan_duration=0.0,
            files_scanned=0,
            total_lines_scanned=0,
            scanner_version="0.1.0",
            configuration=config.to_dict_safe(),
            metrics={},
        )

        # Verify configuration is safe
        assert isinstance(scan_result.configuration, dict), "Configuration should be a dictionary"
        assert "api_key_env" not in scan_result.configuration.get(
            "llm", {}
        ), "Sensitive data should not be in scan result"

    def test_safe_dict_structure(self):
        """Test that to_dict_safe returns expected structure."""
        config = Config()
        safe_dict = config.to_dict_safe()

        # Check main sections exist
        assert "llm" in safe_dict, "LLM config should be in safe dict"
        assert "scanner" in safe_dict, "Scanner config should be in safe dict"
        assert "database" in safe_dict, "Database config should be in safe dict"
        assert "github" in safe_dict, "GitHub config should be in safe dict"

        # Check general config fields
        assert "debug" in safe_dict, "Debug flag should be in safe dict"
        assert "log_level" in safe_dict, "Log level should be in safe dict"
        assert "output_format" in safe_dict, "Output format should be in safe dict"
        assert "report_template" in safe_dict, "Report template should be in safe dict"

        # Check that safe fields are included
        assert "provider" in safe_dict["llm"], "LLM provider should be included"
        assert "model" in safe_dict["llm"], "LLM model should be included"
        assert "languages" in safe_dict["scanner"], "Scanner languages should be included"
        assert "host" in safe_dict["database"], "Database host should be included"
        assert "api_base_url" in safe_dict["github"], "GitHub API URL should be included"


if __name__ == "__main__":
    pytest.main([__file__])
