"""Functional tests for CLI."""

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from ai_security_scanner.cli.main import cli


@pytest.fixture
def runner() -> CliRunner:
    """Provide CLI test runner."""
    return CliRunner()


@pytest.fixture
def sample_unreliable_code(tmp_path: Path) -> Path:
    """Create sample production-readiness risk code."""
    code_file = tmp_path / "unreliable.py"
    code_file.write_text("""
import requests
from fastapi import FastAPI

app = FastAPI()

@app.post("/payments")
def create_payment():
    requests.post(payment_url)
    return charge_card()
""")
    return tmp_path


class TestCLIScan:
    """Test CLI scan command."""

    def test_scan_help(self, runner: CliRunner) -> None:
        """Test scan command help."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "Scan" in result.output or "scan" in result.output

    def test_scan_directory(self, runner: CliRunner, sample_unreliable_code: Path) -> None:
        """Test scanning a directory."""
        result = runner.invoke(cli, ["scan", str(sample_unreliable_code), "--no-ai"])
        assert result.exit_code == 0

    def test_scan_with_json_output(
        self, runner: CliRunner, sample_unreliable_code: Path, tmp_path: Path
    ) -> None:
        """Test scan with JSON output."""
        output_file = tmp_path / "results.json"
        result = runner.invoke(
            cli,
            [
                "scan",
                str(sample_unreliable_code),
                "--output",
                "json",
                "--file",
                str(output_file),
                "--no-ai",
            ],
        )
        assert result.exit_code == 0
        if output_file.exists():
            data = json.loads(output_file.read_text())
            assert "findings" in data or "scan_id" in data

    def test_scan_with_json_stdout_is_parseable(
        self, runner: CliRunner, sample_unreliable_code: Path
    ) -> None:
        """Test scan with JSON output to stdout."""
        result = runner.invoke(
            cli,
            ["scan", str(sample_unreliable_code), "--output", "json", "--no-ai"],
        )

        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        assert "findings" in data

    def test_scan_nonexistent_directory(self, runner: CliRunner) -> None:
        """Test scanning non-existent directory."""
        result = runner.invoke(cli, ["scan", "/nonexistent/path"])
        assert result.exit_code != 0


class TestCLIVersion:
    """Test CLI version command."""

    def test_version_command(self, runner: CliRunner) -> None:
        """Test version command."""
        result = runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "version" in result.output.lower() or "." in result.output
