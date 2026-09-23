"""
Tests for full Orchestrator end-to-end processing and report generation.
"""

from agentic_soc.simulator import AttackScenarioGenerator
from agentic_soc.orchestrator import SOCOrchestrator
from agentic_soc.config import SOCConfig


def test_orchestrator_end_to_end():
    events = AttackScenarioGenerator.generate_phishing_ransomware_chain(hostname="WORKSTATION-42")
    config = SOCConfig(dry_run_mode=True)
    orchestrator = SOCOrchestrator(config=config)

    incident = orchestrator.process_telemetry_stream(events, incident_id="INC-2026-TEST")

    assert incident.incident_id == "INC-2026-TEST"
    assert incident.is_contained is True
    assert len(incident.mitre_ttps) > 0

    report_md = orchestrator.generate_report(incident)
    assert "# 🚨 AUTONOMOUS INCIDENT RESPONSE REPORT" in report_md
    assert "WORKSTATION-42" in report_md
    assert "```mermaid" in report_md
