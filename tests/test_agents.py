"""
Tests for individual sub-agents (Triage, Intel, Forensic, Remediation).
"""

from agentic_soc.simulator import AttackScenarioGenerator
from agentic_soc.models.schemas import Incident, SeverityLevel
from agentic_soc.agents import (
    TriageAgent,
    ThreatIntelAgent,
    ForensicAgent,
    RemediationAgent
)


def test_triage_agent():
    events = AttackScenarioGenerator.generate_phishing_ransomware_chain()
    incident = Incident(
        incident_id="INC-TEST-01",
        title="Test",
        severity=SeverityLevel.LOW,
        hostname="FINANCE-WS-09",
        username="m.pemhiwa",
        telemetry_events=events
    )

    triage = TriageAgent()
    incident = triage.process(incident)
    assert incident.severity == SeverityLevel.CRITICAL
    assert incident.hostname == "FINANCE-WS-09"


def test_intel_agent():
    events = AttackScenarioGenerator.generate_phishing_ransomware_chain()
    incident = Incident(
        incident_id="INC-TEST-02",
        title="Test Intel",
        severity=SeverityLevel.HIGH,
        hostname="FINANCE-WS-09",
        username="m.pemhiwa",
        telemetry_events=events
    )

    intel = ThreatIntelAgent()
    incident = intel.process(incident)
    assert len(incident.iocs) >= 2
    malicious_iocs = [ioc for ioc in incident.iocs if ioc.is_malicious]
    assert len(malicious_iocs) > 0


def test_remediation_agent_guardrails():
    events = AttackScenarioGenerator.generate_phishing_ransomware_chain(hostname="DC-01")
    incident = Incident(
        incident_id="INC-TEST-03",
        title="DC Attack",
        severity=SeverityLevel.CRITICAL,
        hostname="DC-01",
        username="admin",
        telemetry_events=events
    )

    remediation = RemediationAgent()
    incident = remediation.process(incident)

    host_isolate_actions = [a for a in incident.remediation_actions if a.action_type.value == "ISOLATE_HOST"]
    assert len(host_isolate_actions) > 0
    # DC-01 is protected, must require HitL approval
    assert host_isolate_actions[0].requires_hitl_approval is True
