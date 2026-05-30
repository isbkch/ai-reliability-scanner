"""Custom exceptions for AI Reliability Scanner.

This module defines a hierarchy of exceptions for better error handling
and debugging across the application.
"""

from typing import Optional


class SecurityScannerError(Exception):
    """Base exception for all AI Reliability Scanner errors."""

    def __init__(self, message: str, details: Optional[dict] = None) -> None:
        """Initialize the exception.

        Args:
            message: Human-readable error message
            details: Additional context as a dictionary
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        """Return string representation of the error."""
        if self.details:
            details_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            return f"{self.message} ({details_str})"
        return self.message


# Configuration Errors
class ConfigurationError(SecurityScannerError):
    """Raised when there's an issue with configuration."""

    pass


class InvalidConfigError(ConfigurationError):
    """Raised when configuration is invalid or malformed."""

    pass


class MissingConfigError(ConfigurationError):
    """Raised when required configuration is missing."""

    pass


class ConfigValidationError(ConfigurationError):
    """Raised when configuration fails validation."""

    pass


# Scanner Errors
class ScannerError(SecurityScannerError):
    """Base class for scanner-related errors."""

    pass


class FileAccessError(ScannerError):
    """Raised when a file cannot be accessed or read."""

    pass


class DirectoryAccessError(ScannerError):
    """Raised when a directory cannot be accessed."""

    pass


class PatternMatchError(ScannerError):
    """Raised when pattern matching fails."""

    pass


class UnsupportedLanguageError(ScannerError):
    """Raised when attempting to scan an unsupported language."""

    def __init__(self, language: str, supported: Optional[list] = None) -> None:
        """Initialize with language information.

        Args:
            language: The unsupported language
            supported: List of supported languages
        """
        msg = f"Unsupported language: {language}"
        if supported:
            msg += f". Supported languages: {', '.join(supported)}"
        super().__init__(msg, {"language": language, "supported": supported or []})


class ScanTimeoutError(ScannerError):
    """Raised when a scan operation times out."""

    pass


# LLM/AI Errors
class LLMError(SecurityScannerError):
    """Base class for LLM-related errors."""

    pass


class LLMProviderError(LLMError):
    """Raised when there's an issue with the LLM provider."""

    pass


class LLMAPIError(LLMError):
    """Raised when LLM API call fails."""

    def __init__(
        self,
        message: str,
        provider: Optional[str] = None,
        status_code: Optional[int] = None,
        response: Optional[str] = None,
    ) -> None:
        """Initialize with API error details.

        Args:
            message: Error message
            provider: LLM provider name (openai, anthropic, etc.)
            status_code: HTTP status code if applicable
            response: Raw response from the API
        """
        super().__init__(
            message,
            {
                "provider": provider,
                "status_code": status_code,
                "response": response,
            },
        )


class LLMRateLimitError(LLMError):
    """Raised when LLM API rate limit is exceeded."""

    def __init__(
        self, message: str, retry_after: Optional[int] = None, provider: Optional[str] = None
    ) -> None:
        """Initialize with rate limit details.

        Args:
            message: Error message
            retry_after: Seconds to wait before retrying
            provider: LLM provider name
        """
        super().__init__(message, {"retry_after": retry_after, "provider": provider})


class LLMTimeoutError(LLMError):
    """Raised when LLM API call times out."""

    pass


class LLMAuthenticationError(LLMError):
    """Raised when LLM API authentication fails."""

    pass


class AnalysisError(LLMError):
    """Raised when reliability analysis fails."""

    pass


class EmbeddingError(LLMError):
    """Raised when code embedding generation fails."""

    pass


class ModelLoadError(LLMError):
    """Raised when ML model fails to load."""

    def __init__(self, model_name: str, reason: Optional[str] = None) -> None:
        """Initialize with model details.

        Args:
            model_name: Name of the model that failed to load
            reason: Reason for the failure
        """
        msg = f"Failed to load model: {model_name}"
        if reason:
            msg += f" - {reason}"
        super().__init__(msg, {"model_name": model_name, "reason": reason})


# Database Errors
class DatabaseError(SecurityScannerError):
    """Base class for database-related errors."""

    pass


class DatabaseConnectionError(DatabaseError):
    """Raised when database connection fails."""

    pass


class DatabaseQueryError(DatabaseError):
    """Raised when database query fails."""

    pass


class DatabaseMigrationError(DatabaseError):
    """Raised when database migration fails."""

    pass


# Integration Errors
class IntegrationError(SecurityScannerError):
    """Base class for external integration errors."""

    pass


class GitHubIntegrationError(IntegrationError):
    """Raised when GitHub integration fails."""

    pass


class GitHubAPIError(GitHubIntegrationError):
    """Raised when GitHub API call fails."""

    def __init__(
        self, message: str, status_code: Optional[int] = None, endpoint: Optional[str] = None
    ) -> None:
        """Initialize with GitHub API error details.

        Args:
            message: Error message
            status_code: HTTP status code
            endpoint: API endpoint that failed
        """
        super().__init__(message, {"status_code": status_code, "endpoint": endpoint})


class GitHubAuthenticationError(GitHubIntegrationError):
    """Raised when GitHub authentication fails."""

    pass


class RepositoryNotFoundError(GitHubIntegrationError):
    """Raised when GitHub repository is not found."""

    def __init__(self, repo: str) -> None:
        """Initialize with repository name.

        Args:
            repo: Repository name (owner/repo)
        """
        super().__init__(f"Repository not found: {repo}", {"repository": repo})


# Export/Report Errors
class ExportError(SecurityScannerError):
    """Base class for export/report errors."""

    pass


class SARIFExportError(ExportError):
    """Raised when SARIF export fails."""

    pass


class JSONExportError(ExportError):
    """Raised when JSON export fails."""

    pass


class ReportGenerationError(ExportError):
    """Raised when report generation fails."""

    pass


# Pattern Errors
class PatternError(SecurityScannerError):
    """Base class for pattern-related errors."""

    pass


class InvalidPatternError(PatternError):
    """Raised when a reliability pattern is invalid."""

    def __init__(self, pattern_name: str, reason: Optional[str] = None) -> None:
        """Initialize with pattern details.

        Args:
            pattern_name: Name of the invalid pattern
            reason: Reason why the pattern is invalid
        """
        msg = f"Invalid pattern: {pattern_name}"
        if reason:
            msg += f" - {reason}"
        super().__init__(msg, {"pattern_name": pattern_name, "reason": reason})


class PatternLoadError(PatternError):
    """Raised when loading patterns fails."""

    pass


class PatternRegistryError(PatternError):
    """Raised when pattern registry operations fail."""

    pass


# Plugin Errors
class PluginError(SecurityScannerError):
    """Base class for plugin-related errors."""

    pass


class PluginLoadError(PluginError):
    """Raised when plugin loading fails."""

    def __init__(self, plugin_name: str, reason: Optional[str] = None) -> None:
        """Initialize with plugin details.

        Args:
            plugin_name: Name of the plugin that failed to load
            reason: Reason for the failure
        """
        msg = f"Failed to load plugin: {plugin_name}"
        if reason:
            msg += f" - {reason}"
        super().__init__(msg, {"plugin_name": plugin_name, "reason": reason})


class PluginValidationError(PluginError):
    """Raised when plugin validation fails."""

    pass


# Parsing Errors
class ParsingError(SecurityScannerError):
    """Base class for code parsing errors."""

    pass


class ASTParsingError(ParsingError):
    """Raised when AST parsing fails."""

    def __init__(
        self, file_path: str, language: Optional[str] = None, reason: Optional[str] = None
    ) -> None:
        """Initialize with parsing details.

        Args:
            file_path: Path to the file that failed to parse
            language: Programming language
            reason: Reason for the parsing failure
        """
        msg = f"Failed to parse file: {file_path}"
        if language:
            msg += f" (language: {language})"
        if reason:
            msg += f" - {reason}"
        super().__init__(msg, {"file_path": file_path, "language": language, "reason": reason})


class TreeSitterError(ParsingError):
    """Raised when tree-sitter operations fail."""

    pass


# Validation Errors
class ValidationError(SecurityScannerError):
    """Base class for validation errors."""

    pass


class InputValidationError(ValidationError):
    """Raised when input validation fails."""

    pass


class OutputValidationError(ValidationError):
    """Raised when output validation fails."""

    pass


# Cache Errors
class CacheError(SecurityScannerError):
    """Base class for cache-related errors."""

    pass


class CacheWriteError(CacheError):
    """Raised when writing to cache fails."""

    pass


class CacheReadError(CacheError):
    """Raised when reading from cache fails."""

    pass


class CacheInvalidationError(CacheError):
    """Raised when cache invalidation fails."""

    pass
