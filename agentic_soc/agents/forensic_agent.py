"""
Forensic Agent: Reconstructs process tree execution and maps attack steps to MITRE ATT&CK.
"""

from typing import Dict, Any, List
from agentic_soc.agents.base_agent import BaseAgent
from agentic_soc.models.schemas import Incident, MitreTTP, EventCategory


class ForensicAgent(BaseAgent):
    """Analyzes telemetry chains and correlates findings with the MITRE ATT&CK framework."""

    def __init__(self):
        super().__init__(
            agent_name="ForensicAgent",
            role_description="Reconstructs attack execution timelines and maps techniques to MITRE ATT&CK framework."
        )

    def process(self, incident: Incident, context: Dict[str, Any] = None) -> Incident:
        ttps: List[MitreTTP] = []

        for event in incident.telemetry_events:
            # Map Office Macro Execution
            if event.process_name and "EXCEL.EXE" in event.process_name and ".docm" in (event.command_line or ""):
                ttps.append(
                    MitreTTP(
                        tactic="Initial Access",
                        technique_id="T1566.001",
                        technique_name="Phishing: Spearphishing Attachment",
                        evidence=f"Execution of macro-enabled document via {event.command_line}"
                    )
                )

            # Map Encoded PowerShell Execution
            if event.process_name == "powershell.exe" and "-enc" in (event.command_line or ""):
                ttps.append(
                    MitreTTP(
                        tactic="Execution",
                        technique_id="T1059.001",
                        technique_name="Command and Scripting Interpreter: PowerShell",
                        evidence=f"Obfuscated PowerShell stager executed (PID: {event.process_id})"
                    )
                )

            # Map LSASS Memory Access
            if event.category == EventCategory.LSASS_MEMORY_ACCESS:
                ttps.append(
                    MitreTTP(
                        tactic="Credential Access",
                        technique_id="T1003.001",
                        technique_name="OS Credential Dumping: LSASS Memory",
                        evidence=f"Read handle requested on lsass.exe process by PID {event.process_id}"
                    )
                )

            # Map C2 Beaconing
            if event.category == EventCategory.NETWORK_CONNECTION and event.destination_ip:
                ttps.append(
                    MitreTTP(
                        tactic="Command & Control",
                        technique_id="T1071.001",
                        technique_name="Application Layer Protocol: Web Protocols",
                        evidence=f"Outbound C2 connection to {event.destination_ip}:{event.destination_port}"
                    )
                )

        incident.mitre_ttps = ttps
        return incident
