"""
Core Multi-Agent Orchestrator managing the 4-phase SOC lifecycle: Sense -> Analyze -> Act -> Report.
"""

from typing import List, Optional
from datetime import datetime
from agentic_soc.config import SOCConfig, default_config
from agentic_soc.models.schemas import TelemetryEvent, Incident, SeverityLevel
from agentic_soc.agents import (
    TriageAgent,
    ThreatIntelAgent,
    ForensicAgent,
    RemediationAgent
)
from agentic_soc.execution import ExecutionEngine
from agentic_soc.reporting import ReportGenerator


class SOCOrchestrator:
    """Coordinates specialized sub-agents and execution engines for autonomous threat response."""

    def __init__(self, config: SOCConfig = default_config):
        self.config = config
        self.triage_agent = TriageAgent()
        self.intel_agent = ThreatIntelAgent()
        self.forensic_agent = ForensicAgent()
        self.remediation_agent = RemediationAgent(config=config)
        self.execution_engine = ExecutionEngine(config=config)

    def process_telemetry_stream(self, telemetry_events: List[TelemetryEvent], incident_id: Optional[str] = None) -> Incident:
        inc_id = incident_id or f"INC-{datetime.utcnow().strftime('%Y%m%d')}-001"

        # Initialize Incident Entity
        incident = Incident(
            incident_id=inc_id,
            title="Unanalyzed Security Incident",
            severity=SeverityLevel.LOW,
            hostname="UNKNOWN",
            username="UNKNOWN",
            telemetry_events=telemetry_events
        )

        # Step 1: Triage Agent (Entity Correlation & Noise Reduction)
        incident = self.triage_agent.process(incident)

        # Step 2: Threat Intel Agent (IoC Extraction & Reputation Enrichment)
        incident = self.intel_agent.process(incident)

        # Step 3: Forensic Agent (Process Graph Reconstruction & MITRE ATT&CK Mapping)
        incident = self.forensic_agent.process(incident)

        # Step 4: Remediation Agent (Safety Guardrail Evaluation & Action Planning)
        incident = self.remediation_agent.process(incident)

        # Step 5: Containment Execution
        executed_actions = self.execution_engine.execute_actions(incident.remediation_actions)
        incident.remediation_actions = executed_actions
        incident.is_contained = any(a.executed for a in executed_actions)

        return incident

    def generate_report(self, incident: Incident) -> str:
        return ReportGenerator.generate_markdown_report(incident)
