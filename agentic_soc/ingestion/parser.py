"""
Telemetry Parser for Sysmon, EDR JSON files, and SIEM logs.
"""

import json
from typing import List, Dict, Any
from datetime import datetime
from agentic_soc.models.schemas import TelemetryEvent, EventCategory


class TelemetryParser:
    """Parses raw log feeds into normalized TelemetryEvent schemas."""

    @staticmethod
    def parse_json_events(raw_data: str) -> List[TelemetryEvent]:
        parsed_events = []
        events_list = json.loads(raw_data)
        if isinstance(events_list, dict):
            events_list = [events_list]

        for item in events_list:
            category_str = item.get("category", "PROCESS_EXECUTION").upper()
            try:
                category = EventCategory[category_str]
            except KeyError:
                category = EventCategory.PROCESS_EXECUTION

            ts_str = item.get("timestamp")
            timestamp = datetime.fromisoformat(ts_str) if ts_str else datetime.utcnow()

            event = TelemetryEvent(
                event_id=item.get("event_id", f"EVT-{len(parsed_events)+1:04d}"),
                timestamp=timestamp,
                hostname=item.get("hostname", "UNKNOWN-HOST"),
                username=item.get("username", "UNKNOWN-USER"),
                category=category,
                process_name=item.get("process_name"),
                process_id=item.get("process_id"),
                parent_process_name=item.get("parent_process_name"),
                command_line=item.get("command_line"),
                destination_ip=item.get("destination_ip"),
                destination_port=item.get("destination_port"),
                file_hash=item.get("file_hash"),
                raw_payload=item.get("raw_payload", item)
            )
            parsed_events.append(event)
            
        return parsed_events
