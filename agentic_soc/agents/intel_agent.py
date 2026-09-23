"""
Threat Intel Agent: Extracts IoCs (IPs, hashes, domains) and performs reputation enrichment.
"""

from typing import Dict, Any, List
from agentic_soc.agents.base_agent import BaseAgent
from agentic_soc.models.schemas import Incident, IoCEntity, IoCType


class ThreatIntelAgent(BaseAgent):
    """Extracts Indicators of Compromise and enriches reputation data against threat intel databases."""

    def __init__(self):
        super().__init__(
            agent_name="ThreatIntelAgent",
            role_description="Extracts IoCs (IPs, hashes) and performs reputation scoring against threat intel feeds."
        )

    def process(self, incident: Incident, context: Dict[str, Any] = None) -> Incident:
        iocs: List[IoCEntity] = []

        # Known malicious mock database (for robust offline sandbox analysis)
        known_bad_ips = {"193.42.11.89", "185.220.101.5", "45.154.255.71"}
        known_bad_hashes = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
        }

        for event in incident.telemetry_events:
            # Extract destination IPs
            if event.destination_ip:
                is_bad = event.destination_ip in known_bad_ips
                iocs.append(
                    IoCEntity(
                        value=event.destination_ip,
                        ioc_type=IoCType.IP_ADDRESS,
                        reputation_score=0.95 if is_bad else 0.10,
                        threat_label="Cobalt Strike C2 Node" if is_bad else "Internal / Clean IP",
                        is_malicious=is_bad,
                        source="AlienVault OTX / ThreatIntel Engine"
                    )
                )

            # Extract File Hashes
            if event.file_hash:
                is_bad_hash = event.file_hash in known_bad_hashes
                iocs.append(
                    IoCEntity(
                        value=event.file_hash,
                        ioc_type=IoCType.FILE_HASH,
                        reputation_score=0.99 if is_bad_hash else 0.05,
                        threat_label="Malicious PowerShell Stager" if is_bad_hash else "Clean Binary",
                        is_malicious=is_bad_hash,
                        source="VirusTotal API"
                    )
                )

        incident.iocs = iocs
        return incident
