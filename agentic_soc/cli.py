"""
Command-Line Interface (CLI) for AgenticSOC-Toolkit.
"""

import sys
import json
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

from agentic_soc import __version__
from agentic_soc.config import SOCConfig, default_config
from agentic_soc.ingestion import TelemetryParser
from agentic_soc.simulator import AttackScenarioGenerator
from agentic_soc.orchestrator import SOCOrchestrator

console = Console()


@click.group()
def cli():
    """🛡️ AgenticSOC-Toolkit: Autonomous Multi-Agent Security Operations Framework."""
    pass


@cli.command()
def version():
    """Print the version and framework configuration."""
    console.print(Panel(f"[bold green]AgenticSOC-Toolkit[/bold green] v{__version__}\n"
                        f"Autonomous Multi-Agent SOC Framework", title="System Info"))


@cli.command()
@click.option("--hostname", default="FINANCE-WS-09", help="Target hostname to simulate attack on.")
@click.option("--output-report", type=click.Path(), help="Path to save the generated markdown report.")
def simulate(hostname, output_report):
    """Run an end-to-end simulated cyber attack scenario through the multi-agent pipeline."""
    console.print(f"\n[bold yellow]⚡ Launching Cyber Attack Simulation on Target: {hostname}[/bold yellow]\n")

    # Generate telemetry chain
    events = AttackScenarioGenerator.generate_phishing_ransomware_chain(hostname=hostname)

    # Initialize Orchestrator
    config = SOCConfig(dry_run_mode=True)
    orchestrator = SOCOrchestrator(config=config)

    # Process Telemetry Stream through Multi-Agent System
    console.print("[cyan]🤖 Invoking Multi-Agent Pipeline (Triage -> Intel -> Forensic -> Remediation)...[/cyan]")
    incident = orchestrator.process_telemetry_stream(events)

    # Display Incident Summary Table in Terminal
    table = Table(title=f"Incident Analysis Summary: {incident.incident_id}")
    table.add_column("Property", style="bold cyan")
    table.add_column("Value", style="bold white")

    table.add_row("Incident Title", incident.title)
    table.add_row("Severity Level", f"[bold red]{incident.severity.value}[/bold red]")
    table.add_row("Target Host", incident.hostname)
    table.add_row("Observed User", incident.username)
    table.add_row("Telemetry Events Processed", str(len(incident.telemetry_events)))
    table.add_row("Extracted IoCs", str(len(incident.iocs)))
    table.add_row("MITRE ATT&CK Techniques", str(len(incident.mitre_ttps)))
    table.add_row("Containment Actions Executed", str(len([a for a in incident.remediation_actions if a.executed])))
    table.add_row("Containment Status", "[green]🟢 CONTAINED[/green]" if incident.is_contained else "[yellow]🟡 HITL REQUIRED[/yellow]")

    console.print(table)

    # Generate Markdown Incident Report
    report_md = orchestrator.generate_report(incident)

    if output_report:
        with open(output_report, "w", encoding="utf-8") as f:
            f.write(report_md)
        console.print(f"\n[bold green]✅ Full Incident Report saved to: {output_report}[/bold green]")
    else:
        console.print("\n[bold underline]Generated Incident Report Preview:[/bold underline]\n")
        console.print(Markdown(report_md[:1500] + "\n\n*(Report truncated in terminal preview. Pass --output-report to save full report)*"))


@cli.command()
@click.option("--file", "-f", required=True, type=click.Path(exists=True), help="Path to JSON telemetry log file.")
@click.option("--output-report", type=click.Path(), help="Path to save markdown incident report.")
def scan(file, output_report):
    """Scan and analyze a telemetry log file using the multi-agent pipeline."""
    console.print(f"\n[cyan]🔍 Scanning Telemetry File: {file}[/cyan]")

    with open(file, "r", encoding="utf-8") as f:
        raw_content = f.read()

    events = TelemetryParser.parse_json_events(raw_content)
    console.print(f"Parsed {len(events)} telemetry events.")

    orchestrator = SOCOrchestrator(config=default_config)
    incident = orchestrator.process_telemetry_stream(events)

    report_md = orchestrator.generate_report(incident)

    if output_report:
        with open(output_report, "w", encoding="utf-8") as f:
            f.write(report_md)
        console.print(f"[bold green]✅ Incident Report saved to: {output_report}[/bold green]")
    else:
        console.print(Markdown(report_md))


def main():
    cli()


if __name__ == "__main__":
    main()
