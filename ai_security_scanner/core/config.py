"""Configuration management for the AI Reliability Scanner."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from dataclasses_json import dataclass_json


@dataclass_json
@dataclass
class LLMConfig:
    """Configuration for LLM integration."""

    provider: str = "openai"
    model: str = "gpt-4"
    api_key_env: str = "OPENAI_API_KEY"
    api_base_url: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 1000
    timeout: int = 30
    retry_attempts: int = 3
    rate_limit_requests_per_minute: int = 60


@dataclass_json
@dataclass
class ScannerConfig:
    """Configuration for the scanner engine."""

    languages: List[str] = field(default_factory=lambda: ["python", "javascript"])
    patterns: List[str] = field(default_factory=lambda: ["reliability-readiness"])
    false_positive_reduction: bool = True
    max_file_size_mb: int = 10
    max_files_per_scan: int = 10000
    include_patterns: List[str] = field(
        default_factory=lambda: ["*.py", "*.js", "*.ts", "*.jsx", "*.tsx"]
    )
    exclude_patterns: List[str] = field(
        default_factory=lambda: [
            "*/node_modules/*",
            "*/venv/*",
            "*/env/*",
            "*/.git/*",
            "*/dist/*",
            "*/build/*",
        ]
    )
    confidence_threshold: float = 0.5
    enable_ai_analysis: bool = True


@dataclass_json
@dataclass
class DatabaseConfig:
    """Configuration for database connection."""

    host: str = "localhost"
    port: int = 5432
    database: str = "ai_reliability_scanner"
    username: str = "scanner"
    password_env: str = "DB_PASSWORD"
    ssl_mode: str = "prefer"
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30


@dataclass_json
@dataclass
class GitHubConfig:
    """Configuration for GitHub integration."""

    token_env: str = "GITHUB_TOKEN"
    webhook_secret_env: str = "GITHUB_WEBHOOK_SECRET"
    api_base_url: str = "https://api.github.com"
    timeout: int = 30
    max_file_size: int = 1000000  # 1MB
    clone_depth: int = 1


@dataclass_json
@dataclass
class Config:
    """Main configuration class."""

    llm: LLMConfig = field(default_factory=LLMConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    github: GitHubConfig = field(default_factory=GitHubConfig)
    debug: bool = False
    log_level: str = "INFO"
    output_format: str = "json"
    report_template: str = "default"

    @classmethod
    def from_file(cls, config_path: str) -> "Config":
        """Load configuration from YAML file."""
        config_file = Path(config_path)
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(config_file, "r") as f:
            config_data = yaml.safe_load(f)

        return cls.from_dict(config_data)

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        config = cls()

        def env(primary: str, legacy: str) -> Optional[str]:
            return os.getenv(primary) or os.getenv(legacy)

        # Override with environment variables
        if env("AI_RELIABILITY_SCANNER_DEBUG", "AI_SCANNER_DEBUG"):
            config.debug = env("AI_RELIABILITY_SCANNER_DEBUG", "AI_SCANNER_DEBUG").lower() == "true"

        if env("AI_RELIABILITY_SCANNER_LOG_LEVEL", "AI_SCANNER_LOG_LEVEL"):
            config.log_level = env("AI_RELIABILITY_SCANNER_LOG_LEVEL", "AI_SCANNER_LOG_LEVEL")

        # LLM configuration
        if env("AI_RELIABILITY_SCANNER_LLM_PROVIDER", "AI_SCANNER_LLM_PROVIDER"):
            config.llm.provider = env(
                "AI_RELIABILITY_SCANNER_LLM_PROVIDER", "AI_SCANNER_LLM_PROVIDER"
            )

        if env("AI_RELIABILITY_SCANNER_LLM_MODEL", "AI_SCANNER_LLM_MODEL"):
            config.llm.model = env("AI_RELIABILITY_SCANNER_LLM_MODEL", "AI_SCANNER_LLM_MODEL")

        # Database configuration
        if env("AI_RELIABILITY_SCANNER_DB_HOST", "AI_SCANNER_DB_HOST"):
            config.database.host = env("AI_RELIABILITY_SCANNER_DB_HOST", "AI_SCANNER_DB_HOST")

        if env("AI_RELIABILITY_SCANNER_DB_PORT", "AI_SCANNER_DB_PORT"):
            config.database.port = int(env("AI_RELIABILITY_SCANNER_DB_PORT", "AI_SCANNER_DB_PORT"))

        if env("AI_RELIABILITY_SCANNER_DB_NAME", "AI_SCANNER_DB_NAME"):
            config.database.database = env("AI_RELIABILITY_SCANNER_DB_NAME", "AI_SCANNER_DB_NAME")

        if env("AI_RELIABILITY_SCANNER_DB_USER", "AI_SCANNER_DB_USER"):
            config.database.username = env("AI_RELIABILITY_SCANNER_DB_USER", "AI_SCANNER_DB_USER")

        return config

    def get_api_key(self, env_var: str) -> Optional[str]:
        """Get API key from environment variable."""
        return os.getenv(env_var)

    def validate(
        self, require_db: bool = False, require_github: bool = False, require_ai: bool = False
    ) -> None:
        """Validate configuration.

        Args:
            require_db: Whether database configuration is required
            require_github: Whether GitHub configuration is required
            require_ai: Whether AI/LLM configuration is required
        """
        errors = []

        # Validate LLM configuration only if required
        if require_ai and self.scanner.enable_ai_analysis:
            if not self.get_api_key(self.llm.api_key_env):
                errors.append(
                    f"LLM API key not found in environment variable: {self.llm.api_key_env}"
                )

        # Validate database configuration only if required
        if require_db and not self.get_api_key(self.database.password_env):
            errors.append(
                f"Database password not found in environment variable: {self.database.password_env}"
            )

        # Validate GitHub configuration only if required
        if require_github and not self.get_api_key(self.github.token_env):
            errors.append(
                f"GitHub token not found in environment variable: {self.github.token_env}"
            )

        if errors:
            raise ValueError(f"Configuration validation failed: {', '.join(errors)}")

    def to_dict_safe(self) -> Dict[str, Any]:
        """Convert configuration to dictionary, excluding sensitive data.

        Returns:
            Safe configuration dictionary
        """
        safe_config = {}

        # LLM config (excluding API key)
        safe_config["llm"] = {
            "provider": self.llm.provider,
            "model": self.llm.model,
            "temperature": self.llm.temperature,
            "max_tokens": self.llm.max_tokens,
            "timeout": self.llm.timeout,
            "retry_attempts": self.llm.retry_attempts,
            "rate_limit_requests_per_minute": self.llm.rate_limit_requests_per_minute,
        }

        # Scanner config (all safe)
        safe_config["scanner"] = {
            "languages": self.scanner.languages,
            "patterns": self.scanner.patterns,
            "false_positive_reduction": self.scanner.false_positive_reduction,
            "max_file_size_mb": self.scanner.max_file_size_mb,
            "max_files_per_scan": self.scanner.max_files_per_scan,
            "include_patterns": self.scanner.include_patterns,
            "exclude_patterns": self.scanner.exclude_patterns,
            "confidence_threshold": self.scanner.confidence_threshold,
            "enable_ai_analysis": self.scanner.enable_ai_analysis,
        }

        # Database config (excluding password)
        safe_config["database"] = {
            "host": self.database.host,
            "port": self.database.port,
            "database": self.database.database,
            "username": self.database.username,
            "ssl_mode": self.database.ssl_mode,
            "pool_size": self.database.pool_size,
            "max_overflow": self.database.max_overflow,
            "pool_timeout": self.database.pool_timeout,
        }

        # GitHub config (excluding token and webhook secret)
        safe_config["github"] = {
            "api_base_url": self.github.api_base_url,
            "timeout": self.github.timeout,
            "max_file_size": self.github.max_file_size,
            "clone_depth": self.github.clone_depth,
        }

        # General config
        safe_config["debug"] = self.debug
        safe_config["log_level"] = self.log_level
        safe_config["output_format"] = self.output_format
        safe_config["report_template"] = self.report_template

        return safe_config


def load_config(config_path: Optional[str] = None) -> Config:
    """Load configuration from file or environment."""
    if config_path and Path(config_path).exists():
        return Config.from_file(config_path)

    # Look for config file in standard locations
    standard_locations = [
        ".ai-reliability-scanner.yml",
        ".ai-reliability-scanner.yaml",
        "ai-reliability-scanner.yml",
        "ai-reliability-scanner.yaml",
        ".ai-security-scanner.yml",
        ".ai-security-scanner.yaml",
        "ai-security-scanner.yml",
        "ai-security-scanner.yaml",
        os.path.expanduser("~/.ai-reliability-scanner.yml"),
        os.path.expanduser("~/.ai-reliability-scanner.yaml"),
        os.path.expanduser("~/.ai-security-scanner.yml"),
        os.path.expanduser("~/.ai-security-scanner.yaml"),
    ]

    for location in standard_locations:
        if Path(location).exists():
            return Config.from_file(location)

    # Fall back to environment variables
    return Config.from_env()
