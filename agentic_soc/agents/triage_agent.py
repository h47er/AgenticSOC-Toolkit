"""
Triage Agent: Normalizes raw telemetry, correlates events by hostname/user, and assigns initial severity scores.
"""

from typing import Dict, Any, List
from agentic_soc.agents.base_agent import BaseAgent
from agentic_soc.models.schemas import Incident, SeverityLevel, TelemetryEvent, EventCategory


class TriageAgent(BaseAgent):
    """Responsible for initial log ingestion, entity correlation, and threat triaging."""

    def __init__(self):
        super().__init__(
            agent_name="TriageAgent",
            role_description="Ingests telemetry, correlates host/user entities, and calculates initial threat severity."
        )

    def process(self, incident: Incident, context: Dict[str, Any] = None) -> Incident:
        events: List[TelemetryEvent] = incident.telemetry_events
        if not events:
            incident.severity = SeverityLevel.LOW
            return incident

        # Correlate entities
        incident.hostname = events[0].hostname
        incident.username = events[0].username

        # Calculate severity based on event categories and indicators
        has_lsass = any(e.category == EventCategory.LSASS_MEMORY_ACCESS for e in events)
        has_c2_net = any(e.category == EventCategory.NETWORK_CONNECTION and e.destination_ip for e in events)
        has_powershell = any(e.process_name == "powershell.exe" and "-enc" in (e.command_line or "") for e in events)

        if has_lsass and has_c2_net and has_powershell:
            incident.severity = SeverityLevel.CRITICAL
            incident.title = f"Critical Multi-Stage Malware & Credential Dumping on {incident.hostname}"
        elif has_lsass or has_c2_net:
            incident.severity = SeverityLevel.HIGH
            incident.title = f"High Severity Threat Activity Detected on {incident.hostname}"
        else:
            incident.severity = SeverityLevel.MEDIUM
            incident.title = f"Suspicious Activity Logged on {incident.hostname}"

        return incident
