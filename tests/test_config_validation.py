"""Test configuration validation functionality."""

import os
from unittest.mock import MagicMock, patch

import pytest

from ai_security_scanner.core.config import Config
from ai_security_scanner.core.llm.analyzer import VulnerabilityAnalyzer


class TestConfigValidation:
    """Test cases for configuration validation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = Config()

    def test_validate_without_requirements(self):
        """Test that validation passes when no specific requirements are set."""
        # Should not raise any exceptions
        self.config.validate()

    def test_validate_with_ai_disabled(self):
        """Test validation when AI is disabled."""
        self.config.scanner.enable_ai_analysis = False

        # Should not raise any exceptions even if API key is missing
        self.config.validate(require_ai=True)

    def test_validate_with_ai_required_but_missing_key(self):
        """Test validation fails when AI is required but API key is missing."""
        self.config.scanner.enable_ai_analysis = True

        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="LLM API key not found"):
                self.config.validate(require_ai=True)

    def test_validate_with_ai_required_and_key_present(self):
        """Test validation passes when AI is required and API key is present."""
        self.config.scanner.enable_ai_analysis = True

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            # Should not raise any exceptions
            self.config.validate(require_ai=True)

    def test_validate_github_required_but_missing_token(self):
        """Test validation fails when GitHub is required but token is missing."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="GitHub token not found"):
                self.config.validate(require_github=True)

    def test_validate_database_required_but_missing_password(self):
        """Test validation fails when database is required but password is missing."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="Database password not found"):
                self.config.validate(require_db=True)


class TestVulnerabilityAnalyzerInitialization:
    """Test cases for VulnerabilityAnalyzer initialization."""

    def test_analyzer_init_without_ai_key(self):
        """Test that analyzer can be initialized without AI key."""
        config = Config()
        config.scanner.enable_ai_analysis = True

        # Should not raise an exception during initialization
        analyzer = VulnerabilityAnalyzer(config)

        # AI components should not be initialized yet
        assert not analyzer._ai_components_initialized
        assert analyzer.llm_provider is None
        assert analyzer.embedder is None

    def test_analyzer_init_with_ai_disabled(self):
        """Test analyzer initialization when AI is disabled."""
        config = Config()
        config.scanner.enable_ai_analysis = False

        # Should not raise an exception
        analyzer = VulnerabilityAnalyzer(config)

        # AI components should not be initialized
        assert not analyzer._ai_components_initialized
        assert analyzer.llm_provider is None
        assert analyzer.embedder is None

    @patch("ai_security_scanner.core.llm.analyzer.create_llm_provider")
    @patch("ai_security_scanner.core.llm.analyzer.CodeBERTEmbedder")
    def test_analyzer_lazy_initialization(self, mock_embedder, mock_create_provider):
        """Test that AI components are initialized lazily."""
        config = Config()
        config.scanner.enable_ai_analysis = True

        # Mock the LLM provider and embedder
        mock_provider = MagicMock()
        mock_create_provider.return_value = mock_provider
        mock_embedder_instance = MagicMock()
        mock_embedder.return_value = mock_embedder_instance

        analyzer = VulnerabilityAnalyzer(config)

        # Components should not be initialized yet
        assert not analyzer._ai_components_initialized

        # Manually trigger initialization
        analyzer._initialize_ai_components()

        # Now components should be initialized
        assert analyzer._ai_components_initialized
        assert analyzer.llm_provider == mock_provider
        assert analyzer.embedder == mock_embedder_instance

        # Verify the mocks were called
        mock_create_provider.assert_called_once_with(config)
        mock_embedder.assert_called_once_with(config)


if __name__ == "__main__":
    pytest.main([__file__])
