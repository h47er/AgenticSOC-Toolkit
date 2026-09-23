"""
Tests for telemetry ingestion and log parsing.
"""

from agentic_soc.ingestion import TelemetryParser
from agentic_soc.models.schemas import EventCategory


def test_parse_json_events():
    json_data = """[
        {
            "event_id": "EVT-999",
            "hostname": "TEST-HOST",
            "username": "test.user",
            "category": "PROCESS_EXECUTION",
            "process_name": "cmd.exe",
            "process_id": 1234
        }
    ]"""

    events = TelemetryParser.parse_json_events(json_data)
    assert len(events) == 1
    assert events[0].hostname == "TEST-HOST"
    assert events[0].username == "test.user"
    assert events[0].category == EventCategory.PROCESS_EXECUTION
    assert events[0].process_id == 1234
