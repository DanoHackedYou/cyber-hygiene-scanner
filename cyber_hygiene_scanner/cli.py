import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cyber_hygiene_scanner import __version__
from cyber_hygiene_scanner.services.http_checks import HttpScanError
from cyber_hygiene_scanner.services.scanner import scan_target

app = typer.Typer(help="Cyber Hygiene Scanner - basic and safe web security hygiene checks.")
console = Console()


@app.callback()
def callback(
    version: bool = typer.Option(False, "--version", help="Show the application version."),
) -> None:
    if version:
        console.print(f"Cyber Hygiene Scanner {__version__}")
        raise typer.Exit()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain or URL. Example: https://example.com"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Export scan result to JSON."),
    skip_ports: bool = typer.Option(False, "--skip-ports", help="Skip common port checks."),
) -> None:
    """Run a safe hygiene scan against a web target."""
    try:
        result = scan_target(target, skip_ports=skip_ports)
    except (ValueError, HttpScanError) as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    render_report(result)

    if output:
        output.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"\n[green]JSON report saved to:[/green] {output}")


def render_report(result) -> None:
    console.print(
        Panel.fit(
            f"[bold]Target:[/bold] {result.target}\n"
            f"[bold]Score:[/bold] {result.score}/100\n"
            f"[bold]Risk level:[/bold] {result.risk_level}\n"
            f"[bold]HTTPS:[/bold] {'Yes' if result.https_enabled else 'No'}",
            title="Cyber Hygiene Summary",
            border_style="blue",
        )
    )

    headers_table = Table(title="Security Headers")
    headers_table.add_column("Header", style="cyan")
    headers_table.add_column("Status")
    headers_table.add_column("Value / Recommendation")

    for header in result.headers:
        status = "[green]Present[/green]" if header.present else "[red]Missing[/red]"
        detail = header.value if header.present else header.recommendation
        headers_table.add_row(header.name, status, detail or "-")

    console.print(headers_table)

    if result.ports:
        ports_table = Table(title="Common Ports")
        ports_table.add_column("Port", justify="right")
        ports_table.add_column("Service")
        ports_table.add_column("Status")

        for port in result.ports:
            status = "[yellow]Open[/yellow]" if port.open else "Closed"
            ports_table.add_row(str(port.port), port.service, status)

        console.print(ports_table)

    console.print("\n[bold]Recommendations[/bold]")
    for index, recommendation in enumerate(result.recommendations, start=1):
        console.print(f"{index}. {recommendation}")


if __name__ == "__main__":
    app()
