"""GitHub integration for repository scanning."""

import logging
import os
import shutil
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from github import Github, GithubException

from ai_security_scanner.core.config import Config
from ai_security_scanner.core.llm.analyzer import VulnerabilityAnalyzer
from ai_security_scanner.core.models import ScanResult
from ai_security_scanner.core.scanner import SecurityScanner

logger = logging.getLogger(__name__)


class GitHubIntegration:
    """GitHub integration for repository scanning and analysis."""

    def __init__(self, config: Config):
        """Initialize GitHub integration.

        Args:
            config: Configuration object
        """
        self.config = config
        self.github_token = config.get_api_key(config.github.token_env)

        if not self.github_token:
            raise ValueError(
                f"GitHub token not found in environment variable: {config.github.token_env}"
            )

        # Initialize GitHub client
        self.github = Github(
            self.github_token, base_url=config.github.api_base_url, timeout=config.github.timeout
        )

        # Initialize scanner
        self.scanner = SecurityScanner(config)

        # Initialize AI analyzer if enabled
        self.analyzer = VulnerabilityAnalyzer(config) if config.scanner.enable_ai_analysis else None

    async def scan_repository(self, repo_name: str, branch: Optional[str] = None) -> ScanResult:
        """Scan a GitHub repository for reliability risks.

        Args:
            repo_name: Repository name in format "owner/repo"
            branch: Branch to scan (default: repository default branch)

        Returns:
            Scan result
        """
        try:
            # Get repository
            repo = self.github.get_repo(repo_name)

            # Use default branch if none specified
            if not branch:
                branch = repo.default_branch

            logger.info(f"Scanning repository {repo_name} on branch {branch}")

            # Download repository content
            temp_dir = await self._download_repository(repo, branch)

            try:
                # Scan the downloaded repository
                scan_result = await self.scanner.scan_directory_async(temp_dir)

                # Update scan result with repository information
                scan_result.repository_url = repo.clone_url
                scan_result.repository_name = repo_name
                scan_result.branch = branch

                # Get commit hash
                try:
                    commit = repo.get_branch(branch).commit
                    scan_result.commit_hash = commit.sha
                except Exception as e:
                    logger.warning(f"Could not get commit hash: {e}")

                # Run AI analysis if enabled
                if self.analyzer and scan_result.vulnerabilities:
                    logger.info("Running AI analysis on detected reliability findings")

                    context = {
                        "repository": repo_name,
                        "branch": branch,
                        "commit_hash": scan_result.commit_hash,
                        "language": (
                            self.scanner.get_supported_languages()[0]
                            if self.scanner.get_supported_languages()
                            else "unknown"
                        ),
                    }

                    # Get source code for context from the first file with findings.
                    source_code = ""
                    if scan_result.vulnerabilities:
                        first_vuln_file = scan_result.vulnerabilities[0].location.file_path
                        try:
                            file_path = Path(temp_dir) / first_vuln_file
                            if file_path.exists():
                                import aiofiles

                                async with aiofiles.open(file_path, "r", encoding="utf-8") as f:
                                    source_code = await f.read()
                        except Exception as e:
                            logger.warning(f"Could not read source file for AI analysis: {e}")

                    scan_result.vulnerabilities = await self.analyzer.analyze_vulnerabilities(
                        scan_result.vulnerabilities, source_code, context
                    )

                return scan_result

            finally:
                # Clean up temporary directory
                shutil.rmtree(temp_dir, ignore_errors=True)

        except GithubException as e:
            logger.error(f"GitHub API error: {e}")
            raise
        except Exception as e:
            logger.error(f"Error scanning repository: {e}")
            raise

    async def _download_repository(self, repo, branch: str) -> str:
        """Download repository content to temporary directory.

        Args:
            repo: GitHub repository object
            branch: Branch to download

        Returns:
            Path to temporary directory with repository content
        """
        temp_dir = tempfile.mkdtemp(prefix="ai-scanner-")
        logger.info(f"Downloading repository to {temp_dir}")

        try:
            # Get repository contents
            contents = repo.get_contents("", ref=branch)

            # Download files recursively
            await self._download_contents(repo, contents, temp_dir, branch)

            return temp_dir

        except Exception as e:
            # Clean up on error
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise e

    async def _download_contents(self, repo, contents, base_path: str, branch: str) -> None:
        """Recursively download repository contents.

        Args:
            repo: GitHub repository object
            contents: Contents to download
            base_path: Base directory path
            branch: Branch name
        """
        for content in contents:
            # Sanitize path to prevent directory traversal
            sanitized_path = self._sanitize_path(content.path)
            if not sanitized_path:
                logger.warning(f"Skipping potentially malicious path: {content.path}")
                continue

            file_path = Path(base_path) / sanitized_path

            # Ensure the resolved path is still within base_path (additional safety check)
            try:
                resolved_path = file_path.resolve()
                base_path_resolved = Path(base_path).resolve()
                if not str(resolved_path).startswith(str(base_path_resolved)):
                    logger.warning(f"Path traversal attempt detected, skipping: {content.path}")
                    continue
            except Exception as e:
                logger.warning(f"Error resolving path {content.path}: {e}")
                continue

            if content.type == "dir":
                # Create directory and download contents
                file_path.mkdir(parents=True, exist_ok=True)

                try:
                    subcontents = repo.get_contents(content.path, ref=branch)
                    await self._download_contents(repo, subcontents, base_path, branch)
                except Exception as e:
                    logger.warning(f"Error downloading directory {content.path}: {e}")

            elif content.type == "file":
                # Check file size limit
                if content.size > self.config.github.max_file_size:
                    logger.warning(f"Skipping large file: {content.path} ({content.size} bytes)")
                    continue

                # Create parent directories
                file_path.parent.mkdir(parents=True, exist_ok=True)

                try:
                    # Download file content
                    file_content = repo.get_contents(content.path, ref=branch)

                    # Decode content
                    if file_content.encoding == "base64":
                        import base64

                        decoded_content = base64.b64decode(file_content.content)

                        # Try to decode as text
                        try:
                            text_content = decoded_content.decode("utf-8")
                            with open(file_path, "w", encoding="utf-8") as f:
                                f.write(text_content)
                        except UnicodeDecodeError:
                            # Binary file, skip
                            logger.debug(f"Skipping binary file: {content.path}")
                            continue
                    else:
                        # Text content
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(file_content.decoded_content.decode("utf-8"))

                except Exception as e:
                    logger.warning(f"Error downloading file {content.path}: {e}")

    def create_check_run(self, repo_name: str, commit_sha: str, scan_result: ScanResult) -> None:
        """Create a GitHub check run with scan results.

        Args:
            repo_name: Repository name
            commit_sha: Commit SHA
            scan_result: Scan result
        """
        try:
            repo = self.github.get_repo(repo_name)

            # Create check run
            check_run = repo.create_check_run(
                name="AI Reliability Scanner",
                head_sha=commit_sha,
                status="completed",
                conclusion=self._get_check_conclusion(scan_result),
                started_at=scan_result.scan_timestamp,
                completed_at=datetime.now(),
                output={
                    "title": "Reliability Scan Results",
                    "summary": self._create_check_summary(scan_result),
                    "text": self._create_check_details(scan_result),
                },
            )

            logger.info(f"Created check run: {check_run.html_url}")

        except Exception as e:
            logger.error(f"Error creating check run: {e}")

    def _get_check_conclusion(self, scan_result: ScanResult) -> str:
        """Get check conclusion based on scan results.

        Args:
            scan_result: Scan result

        Returns:
            Check conclusion
        """
        if not scan_result.vulnerabilities:
            return "success"

        # Check for high/critical findings.
        from ai_security_scanner.core.models import Severity

        critical_count = sum(
            1 for v in scan_result.vulnerabilities if v.severity == Severity.CRITICAL
        )
        high_count = sum(1 for v in scan_result.vulnerabilities if v.severity == Severity.HIGH)

        if critical_count > 0:
            return "failure"
        elif high_count > 0:
            return "failure"
        else:
            return "neutral"

    def _create_check_summary(self, scan_result: ScanResult) -> str:
        """Create check summary text.

        Args:
            scan_result: Scan result

        Returns:
            Summary text
        """
        total_vulns = len(scan_result.vulnerabilities)

        if total_vulns == 0:
            return "No reliability risks found."

        # Count by severity
        from ai_security_scanner.core.models import Severity

        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
        }

        for vuln in scan_result.vulnerabilities:
            severity_counts[vuln.severity] += 1

        summary_parts = [f"Found {total_vulns} reliability finding(s):"]

        if severity_counts[Severity.CRITICAL] > 0:
            summary_parts.append(f"🔴 {severity_counts[Severity.CRITICAL]} Critical")
        if severity_counts[Severity.HIGH] > 0:
            summary_parts.append(f"🟠 {severity_counts[Severity.HIGH]} High")
        if severity_counts[Severity.MEDIUM] > 0:
            summary_parts.append(f"🟡 {severity_counts[Severity.MEDIUM]} Medium")
        if severity_counts[Severity.LOW] > 0:
            summary_parts.append(f"🟢 {severity_counts[Severity.LOW]} Low")

        return " | ".join(summary_parts)

    def _create_check_details(self, scan_result: ScanResult) -> str:
        """Create detailed check results.

        Args:
            scan_result: Scan result

        Returns:
            Detailed results text
        """
        if not scan_result.vulnerabilities:
            return "No reliability risks detected in the scanned code."

        details = []
        details.append("## Reliability Scan Results")
        details.append("")
        details.append(f"- **Files Scanned:** {scan_result.files_scanned}")
        details.append(f"- **Lines Scanned:** {scan_result.total_lines_scanned}")
        details.append(f"- **Scan Duration:** {scan_result.scan_duration:.2f}s")
        details.append("")

        # Group findings by file.
        vuln_by_file = {}
        for vuln in scan_result.vulnerabilities:
            file_path = vuln.location.file_path
            if file_path not in vuln_by_file:
                vuln_by_file[file_path] = []
            vuln_by_file[file_path].append(vuln)

        details.append("## Findings by File")
        details.append("")

        for file_path, vulns in vuln_by_file.items():
            details.append(f"### {file_path}")
            details.append("")

            for vuln in vulns:
                details.append(
                    f"- **{vuln.severity.value}: {vuln.vulnerability_type}** "
                    f"(Line {vuln.location.line_number})"
                )
                details.append(f"  - **Severity:** {vuln.severity.value}")
                details.append(f"  - **Confidence:** {vuln.confidence.value}")
                details.append(f"  - **Description:** {vuln.description}")

                if vuln.remediation:
                    details.append(f"  - **Remediation:** {vuln.remediation}")

                details.append("")

        return "\n".join(details)

    def _sanitize_path(self, file_path: str) -> Optional[str]:
        """Sanitize file path to prevent directory traversal attacks.

        Args:
            file_path: Raw file path from repository

        Returns:
            Sanitized file path or None if malicious
        """
        if not file_path:
            return None

        # Normalize path separators
        normalized_path = file_path.replace("\\", "/")

        # Split path into components
        path_parts = normalized_path.split("/")

        # Check for malicious components
        for part in path_parts:
            if part in ("..", ".", "") or part.startswith("."):
                if part != ".git" and part != ".github":  # Allow some common hidden dirs
                    return None

        # Reconstruct safe path
        safe_path = "/".join(part for part in path_parts if part)

        # Additional checks
        if "../" in safe_path or "/.." in safe_path or safe_path.startswith("./"):
            return None

        return safe_path

    def get_repository_info(self, repo_name: str) -> Dict[str, Any]:
        """Get repository information.

        Args:
            repo_name: Repository name

        Returns:
            Repository information dictionary
        """
        try:
            repo = self.github.get_repo(repo_name)

            return {
                "name": repo.name,
                "full_name": repo.full_name,
                "description": repo.description,
                "url": repo.html_url,
                "clone_url": repo.clone_url,
                "default_branch": repo.default_branch,
                "language": repo.language,
                "languages": repo.get_languages(),
                "size": repo.size,
                "stars": repo.stargazers_count,
                "forks": repo.forks_count,
                "created_at": repo.created_at.isoformat(),
                "updated_at": repo.updated_at.isoformat(),
                "private": repo.private,
            }

        except GithubException as e:
            logger.error(f"Error getting repository info: {e}")
            raise
