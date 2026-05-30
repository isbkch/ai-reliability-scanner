"""Main CLI interface for the AI Reliability Scanner."""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from ai_security_scanner.core.config import Config, load_config
from ai_security_scanner.core.llm.analyzer import VulnerabilityAnalyzer
from ai_security_scanner.core.scanner import SecurityScanner
from ai_security_scanner.database import (
    DatabaseManager,
    ScanPersistenceService,
    create_database_manager,
)
from ai_security_scanner.integrations.github import GitHubIntegration
from ai_security_scanner.integrations.sarif import SARIFExporter
from ai_security_scanner.utils.logging import setup_logging

console = Console()


@click.group()
@click.option("--config", "-c", type=click.Path(exists=True), help="Configuration file path")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], verbose: bool, debug: bool) -> None:
    """AI Reliability Scanner.

    Reviews services for production-readiness and reliability risks.
    """
    # Ensure that ctx.obj exists and is a dict
    ctx.ensure_object(dict)

    # Load configuration
    try:
        ctx.obj["config"] = load_config(config)

        # Override debug setting if provided
        if debug:
            ctx.obj["config"].debug = True
            ctx.obj["config"].log_level = "DEBUG"
        elif verbose:
            ctx.obj["config"].log_level = "INFO"

    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)

    # Setup logging
    setup_logging(ctx.obj["config"].log_level, ctx.obj["config"].debug)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "sarif", "table"]),
    default="table",
    help="Output format",
)
@click.option("--file", "-f", type=click.Path(), help="Output file path")
@click.option(
    "--severity",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    help="Minimum severity level",
)
@click.option(
    "--language", "-l", multiple=True, help="Languages to scan (can be specified multiple times)"
)
@click.option("--no-ai", is_flag=True, help="Disable AI analysis")
@click.option("--save-db", is_flag=True, help="Save scan results to database")
@click.option("--github-repo", help="GitHub repository (owner/repo)")
@click.option("--branch", help="Git branch to scan")
@click.pass_context
def scan(
    ctx: click.Context,
    path: str,
    output: str,
    file: Optional[str],
    severity: Optional[str],
    language: tuple,
    no_ai: bool,
    save_db: bool,
    github_repo: Optional[str],
    branch: Optional[str],
) -> None:
    """Scan a directory or file for reliability risks."""
    config: Config = ctx.obj["config"]

    # Override AI analysis setting
    if no_ai:
        config.scanner.enable_ai_analysis = False

    # Override languages if specified
    if language:
        config.scanner.languages = list(language)

    try:
        # Run scan
        result = asyncio.run(_run_scan(config, path, github_repo, branch))

        # Filter by severity if specified
        if severity:
            from ai_security_scanner.core.models import Severity

            min_severity = Severity(severity)
            severity_order = {
                Severity.LOW: 0,
                Severity.MEDIUM: 1,
                Severity.HIGH: 2,
                Severity.CRITICAL: 3,
            }
            min_level = severity_order[min_severity]

            result.vulnerabilities = [
                vuln
                for vuln in result.vulnerabilities
                if severity_order[vuln.severity] >= min_level
            ]

        # Save to database if requested
        if save_db:
            try:
                db_manager = create_database_manager(config.database)
                service = ScanPersistenceService(db_manager)

                with console.status("[bold green]Saving scan results to database..."):
                    success = service.save_scan_result(result)

                if success:
                    console.print(
                        f"[green]Scan results saved to database (ID: {result.scan_id})[/green]"
                    )
                else:
                    console.print("[yellow]Failed to save scan results to database[/yellow]")
            except Exception as db_error:
                console.print(f"[yellow]Warning: Could not save to database: {db_error}[/yellow]")

        # Output results
        if output == "json":
            output_json(result, file)
        elif output == "sarif":
            output_sarif(result, file)
        else:
            output_table(result)

    except Exception as e:
        console.print(f"[red]Error during scan: {e}[/red]")
        if config.debug:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)


async def _run_scan(
    config: Config, path: str, github_repo: Optional[str], branch: Optional[str]
) -> "ScanResult":
    """Run the security scan asynchronously."""
    scanner = SecurityScanner(config)

    # Show scan progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        scan_task = progress.add_task("Scanning for reliability risks...", total=None)

        # Scan directory
        if Path(path).is_dir():
            result = await scanner.scan_directory_async(path)
        else:
            vulnerabilities = scanner.scan_file(path)
            import uuid
            from datetime import datetime

            from ai_security_scanner.core.models import ScanResult

            result = ScanResult(
                scan_id=str(uuid.uuid4()),
                repository_url=None,
                repository_name=Path(path).name,
                branch=branch,
                commit_hash=None,
                scan_timestamp=datetime.now(),
                vulnerabilities=vulnerabilities,
                scan_duration=0.0,
                files_scanned=1,
                total_lines_scanned=0,
                scanner_version="0.1.0",
                configuration=config.to_dict_safe(),
                metrics={},
            )

        progress.update(scan_task, description="Running AI analysis...")

        # Run AI analysis if enabled
        if config.scanner.enable_ai_analysis and result.vulnerabilities:
            analyzer = VulnerabilityAnalyzer(config)

            # Get source code for context
            source_code = ""
            if Path(path).is_file():
                with open(path, "r", encoding="utf-8") as f:
                    source_code = f.read()

            context = {
                "language": config.scanner.languages[0] if config.scanner.languages else "unknown",
                "file_path": path,
                "github_repo": github_repo,
                "branch": branch,
            }

            result.vulnerabilities = await analyzer.analyze_vulnerabilities(
                result.vulnerabilities, source_code, context
            )

        progress.update(scan_task, completed=True)

    return result


def output_json(result: "ScanResult", file: Optional[str]) -> None:
    """Output results in JSON format."""
    output_data = result.to_dict()
    output_data["findings"] = output_data.pop("vulnerabilities", [])

    if file:
        with open(file, "w") as f:
            json.dump(output_data, f, indent=2, default=str)
        console.print(f"[green]Results saved to {file}[/green]")
    else:
        click.echo(json.dumps(output_data, indent=2, default=str))


def output_sarif(result: "ScanResult", file: Optional[str]) -> None:
    """Output results in SARIF format."""
    exporter = SARIFExporter()
    sarif_data = exporter.export(result)

    if file:
        with open(file, "w") as f:
            json.dump(sarif_data, f, indent=2)
        console.print(f"[green]SARIF report saved to {file}[/green]")
    else:
        console.print(json.dumps(sarif_data, indent=2))


def output_table(result: "ScanResult") -> None:
    """Output results in table format."""
    # Summary panel
    summary_text = Text()
    summary_text.append(f"Files Scanned: {result.files_scanned}\n")
    summary_text.append(f"Lines Scanned: {result.total_lines_scanned}\n")
    summary_text.append(f"Reliability Findings: {len(result.vulnerabilities)}\n")
    summary_text.append(f"Scan Duration: {result.scan_duration:.2f}s\n")

    console.print(Panel(summary_text, title="Scan Summary", border_style="blue"))

    if not result.vulnerabilities:
        console.print("[green]No reliability risks found![/green]")
        return

    # Findings table
    table = Table(title="Reliability Findings")
    table.add_column("Severity", style="bold")
    table.add_column("Finding", style="cyan")
    table.add_column("File", style="magenta")
    table.add_column("Line", justify="right")
    table.add_column("Description", style="white")
    table.add_column("Confidence", style="yellow")

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_vulnerabilities = sorted(
        result.vulnerabilities, key=lambda v: severity_order.get(v.severity.value, 4)
    )

    for vuln in sorted_vulnerabilities:
        # Color severity based on level
        severity_color = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green"}

        severity_text = Text(vuln.severity.value)
        severity_text.stylize(severity_color.get(vuln.severity.value, "white"))

        table.add_row(
            severity_text,
            vuln.vulnerability_type,
            vuln.location.file_path,
            str(vuln.location.line_number),
            vuln.description[:100] + "..." if len(vuln.description) > 100 else vuln.description,
            vuln.confidence.value,
        )

    console.print(table)

    # Show AI analysis if available
    ai_analyzed = sum(1 for vuln in result.vulnerabilities if vuln.ai_explanation)
    if ai_analyzed > 0:
        console.print(
            f"\n[blue]AI Analysis: {ai_analyzed}/{len(result.vulnerabilities)} findings analyzed with AI[/blue]"
        )


@cli.command()
@click.argument("repo")
@click.option("--branch", help="Branch to scan (default: main)")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "sarif", "table"]),
    default="table",
    help="Output format",
)
@click.option("--file", "-f", type=click.Path(), help="Output file path")
@click.pass_context
def github(
    ctx: click.Context, repo: str, branch: Optional[str], output: str, file: Optional[str]
) -> None:
    """Scan a GitHub repository for reliability risks."""
    config: Config = ctx.obj["config"]

    try:
        # Initialize GitHub integration
        github_integration = GitHubIntegration(config)

        # Download and scan repository
        with console.status("[bold green]Downloading repository..."):
            result = asyncio.run(github_integration.scan_repository(repo, branch))

        # Output results
        if output == "json":
            output_json(result, file)
        elif output == "sarif":
            output_sarif(result, file)
        else:
            output_table(result)

    except Exception as e:
        console.print(f"[red]Error scanning GitHub repository: {e}[/red]")
        if config.debug:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)


@cli.command()
@click.pass_context
def config_info(ctx: click.Context) -> None:
    """Display configuration information."""
    config: Config = ctx.obj["config"]

    # Configuration table
    table = Table(title="Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Debug Mode", str(config.debug))
    table.add_row("Log Level", config.log_level)
    table.add_row("LLM Provider", config.llm.provider)
    table.add_row("LLM Model", config.llm.model)
    table.add_row("Supported Languages", ", ".join(config.scanner.languages))
    table.add_row("AI Analysis", str(config.scanner.enable_ai_analysis))
    table.add_row("False Positive Reduction", str(config.scanner.false_positive_reduction))
    table.add_row("Confidence Threshold", str(config.scanner.confidence_threshold))

    console.print(table)


@cli.command()
@click.argument("code")
@click.option("--language", "-l", required=True, help="Programming language")
@click.option("--type", "-t", help="Reliability finding type to check for")
@click.pass_context
def analyze(ctx: click.Context, code: str, language: str, type: Optional[str]) -> None:
    """Analyze a code snippet for reliability risks."""
    config: Config = ctx.obj["config"]

    try:
        scanner = SecurityScanner(config)
        vulnerabilities = scanner.scan_code(code, language)

        if type:
            vulnerabilities = [v for v in vulnerabilities if v.vulnerability_type == type]

        if not vulnerabilities:
            console.print("[green]No reliability risks found in the code snippet![/green]")
            return

        # Display findings
        for vuln in vulnerabilities:
            panel_content = Text()
            panel_content.append(f"Finding: {vuln.vulnerability_type}\n")
            panel_content.append(f"Severity: {vuln.severity.value}\n")
            panel_content.append(f"Confidence: {vuln.confidence.value}\n")
            panel_content.append(f"Description: {vuln.description}\n")

            if vuln.remediation:
                panel_content.append(f"Remediation: {vuln.remediation}\n")

            if vuln.ai_explanation:
                panel_content.append(f"AI Analysis: {vuln.ai_explanation}\n")

            console.print(Panel(panel_content, title="Reliability Finding", border_style="red"))

    except Exception as e:
        console.print(f"[red]Error analyzing code: {e}[/red]")
        if config.debug:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)


@cli.command()
@click.pass_context
def version(ctx: click.Context) -> None:
    """Display version information."""
    from ai_security_scanner import __version__

    console.print(f"AI Reliability Scanner v{__version__}")


@cli.group()
@click.pass_context
def db(ctx: click.Context) -> None:
    """Database management commands."""
    pass


@db.command()
@click.pass_context
def init(ctx: click.Context) -> None:
    """Initialize the database schema."""
    config: Config = ctx.obj["config"]

    try:
        from ai_security_scanner.database.models import Base

        db_manager = create_database_manager(config.database)

        with console.status("[bold green]Creating database schema..."):
            # Create engine and all tables
            engine = db_manager.create_engine()
            Base.metadata.create_all(engine)

        console.print("[green]Database schema created successfully![/green]")

    except Exception as e:
        console.print(f"[red]Error initializing database: {e}[/red]")
        if config.debug:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)


@db.command()
@click.pass_context
def test_connection(ctx: click.Context) -> None:
    """Test database connection."""
    config: Config = ctx.obj["config"]

    try:
        db_manager = create_database_manager(config.database)

        with console.status("[bold green]Testing database connection..."):
            success = db_manager.test_connection()

        if success:
            console.print("[green]Database connection successful![/green]")
        else:
            console.print("[red]Database connection failed![/red]")
            sys.exit(1)

    except Exception as e:
        console.print(f"[red]Error testing connection: {e}[/red]")
        if config.debug:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)


@db.command()
@click.option("--limit", "-n", default=10, help="Number of recent scans to show")
@click.pass_context
def history(ctx: click.Context, limit: int) -> None:
    """Show scan history."""
    config: Config = ctx.obj["config"]

    try:
        db_manager = create_database_manager(config.database)
        service = ScanPersistenceService(db_manager)

        scans = service.get_recent_scans(limit=limit)

        if not scans:
            console.print("[yellow]No scans found in database.[/yellow]")
            return

        # Create history table
        table = Table(title=f"Recent Scans (last {limit})")
        table.add_column("Scan ID", style="cyan")
        table.add_column("Timestamp", style="white")
        table.add_column("Target", style="magenta")
        table.add_column("Files", justify="right")
        table.add_column("Findings", justify="right")
        table.add_column("Duration", justify="right")

        for scan in scans:
            table.add_row(
                scan.scan_id[:8] + "...",
                scan.scan_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                (scan.target_path[:30] + "...") if len(scan.target_path) > 30 else scan.target_path,
                str(scan.files_scanned),
                str(scan.total_vulnerabilities),
                f"{scan.scan_duration:.2f}s",
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error retrieving scan history: {e}[/red]")
        if config.debug:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)


@db.command()
@click.argument("scan_id")
@click.pass_context
def show(ctx: click.Context, scan_id: str) -> None:
    """Show details of a specific scan."""
    config: Config = ctx.obj["config"]

    try:
        db_manager = create_database_manager(config.database)

        with db_manager.session_scope() as session:
            from ai_security_scanner.database.repository import ScanRepository

            repository = ScanRepository(session)
            scan = repository.get_scan_by_id(scan_id)

            if not scan:
                console.print(f"[red]Scan not found: {scan_id}[/red]")
                sys.exit(1)

            # Display scan details
            scan_info = Text()
            scan_info.append(f"Scan ID: {scan.scan_id}\n")
            scan_info.append(f"Timestamp: {scan.scan_timestamp}\n")
            scan_info.append(f"Target: {scan.target_path}\n")
            scan_info.append(f"Files Scanned: {scan.files_scanned}\n")
            scan_info.append(f"Lines Scanned: {scan.total_lines_scanned}\n")
            scan_info.append(f"Duration: {scan.scan_duration:.2f}s\n")
            scan_info.append(f"Scanner Version: {scan.scanner_version}\n")

            console.print(Panel(scan_info, title="Scan Details", border_style="blue"))

            # Finding summary
            summary_table = Table(title="Reliability Finding Summary")
            summary_table.add_column("Severity", style="bold")
            summary_table.add_column("Count", justify="right")

            summary_table.add_row("CRITICAL", f"[red]{scan.critical_count}[/red]")
            summary_table.add_row("HIGH", f"[orange1]{scan.high_count}[/orange1]")
            summary_table.add_row("MEDIUM", f"[yellow]{scan.medium_count}[/yellow]")
            summary_table.add_row("LOW", f"[green]{scan.low_count}[/green]")
            summary_table.add_row("TOTAL", str(scan.total_vulnerabilities))

            console.print(summary_table)

            # Get findings
            vulnerabilities = repository.get_vulnerabilities_by_scan(scan_id)

            if vulnerabilities:
                vuln_table = Table(title="Reliability Findings")
                vuln_table.add_column("Finding", style="cyan")
                vuln_table.add_column("Severity", style="bold")
                vuln_table.add_column("File", style="magenta")
                vuln_table.add_column("Line", justify="right")

                for vuln in vulnerabilities[:20]:  # Show first 20
                    vuln_table.add_row(
                        vuln.vulnerability_type,
                        vuln.severity.value,
                        vuln.file_path.split("/")[-1],
                        str(vuln.line_number) if vuln.line_number else "N/A",
                    )

                if len(vulnerabilities) > 20:
                    vuln_table.add_row("...", "...", f"({len(vulnerabilities) - 20} more)", "...")

                console.print(vuln_table)

    except Exception as e:
        console.print(f"[red]Error retrieving scan details: {e}[/red]")
        if config.debug:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)


@db.command()
@click.pass_context
def stats(ctx: click.Context) -> None:
    """Show aggregated scan statistics."""
    config: Config = ctx.obj["config"]

    try:
        db_manager = create_database_manager(config.database)
        service = ScanPersistenceService(db_manager)

        statistics = service.get_scan_statistics()

        # Display statistics
        table = Table(title="Scan Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Total Scans", str(statistics["total_scans"]))
        table.add_row("Total Findings", str(statistics["total_vulnerabilities"]))
        table.add_row("Avg Findings per Scan", f"{statistics['avg_vulnerabilities_per_scan']:.2f}")
        table.add_row("Total Files Scanned", str(statistics["total_files_scanned"]))
        table.add_row("Avg Scan Duration", f"{statistics['avg_scan_duration']:.2f}s")

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error retrieving statistics: {e}[/red]")
        if config.debug:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)


def main() -> None:
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
