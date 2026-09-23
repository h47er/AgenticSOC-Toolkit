"""
Attack Simulator: Generates realistic multi-stage cyber attack telemetry scenarios for demonstration and benchmarking.
"""

from typing import List
from datetime import datetime, timedelta
from agentic_soc.models.schemas import TelemetryEvent, EventCategory


class AttackScenarioGenerator:
    """Generates synthetic telemetry datasets representing real-world attack chains."""

    @staticmethod
    def generate_phishing_ransomware_chain(hostname: str = "FINANCE-WS-09", username: str = "m.pemhiwa") -> List[TelemetryEvent]:
        base_time = datetime.utcnow() - timedelta(minutes=10)

        events = [
            # 1. Initial Access: Malicious doc execution
            TelemetryEvent(
                event_id="EVT-1001",
                timestamp=base_time,
                hostname=hostname,
                username=username,
                category=EventCategory.PROCESS_EXECUTION,
                process_name="EXCEL.EXE",
                process_id=3120,
                parent_process_name="explorer.exe",
                command_line="EXCEL.EXE /e Invoice_Q3.docm",
                file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
            # 2. Execution: Obfuscated PowerShell stager
            TelemetryEvent(
                event_id="EVT-1002",
                timestamp=base_time + timedelta(seconds=5),
                hostname=hostname,
                username=username,
                category=EventCategory.PROCESS_EXECUTION,
                process_name="powershell.exe",
                process_id=5120,
                parent_process_name="EXCEL.EXE",
                command_line="powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ...==",
                file_hash="7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
            ),
            # 3. Credential Access: LSASS Memory Dump
            TelemetryEvent(
                event_id="EVT-1003",
                timestamp=base_time + timedelta(seconds=12),
                hostname=hostname,
                username=username,
                category=EventCategory.LSASS_MEMORY_ACCESS,
                process_name="powershell.exe",
                process_id=5120,
                command_line="lsass.exe dump requested handle 0x1010",
                raw_payload={"target_process": "lsass.exe", "access_mask": "0x1010"}
            ),
            # 4. Command & Control: Beaconing to Malicious C2 IP
            TelemetryEvent(
                event_id="EVT-1004",
                timestamp=base_time + timedelta(seconds=18),
                hostname=hostname,
                username=username,
                category=EventCategory.NETWORK_CONNECTION,
                process_name="powershell.exe",
                process_id=5120,
                destination_ip="193.42.11.89",
                destination_port=8443,
                raw_payload={"protocol": "HTTPS", "bytes_sent": 1420}
            )
        ]
        return events
