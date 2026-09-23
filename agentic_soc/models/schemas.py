"""
Pydantic schemas for Telemetry, Incidents, IoCs, MITRE TTPs, Actions, and Reports.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventCategory(str, Enum):
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    LSASS_MEMORY_ACCESS = "LSASS_MEMORY_ACCESS"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    FILE_MODIFICATION = "FILE_MODIFICATION"
    IDENTITY_AUTH = "IDENTITY_AUTH"


class TelemetryEvent(BaseModel):
    event_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    hostname: str
    username: str
    category: EventCategory
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    command_line: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    file_hash: Optional[str] = None
    raw_payload: Dict[str, Any] = Field(default_factory=dict)


class IoCType(str, Enum):
    IP_ADDRESS = "IP_ADDRESS"
    DOMAIN = "DOMAIN"
    FILE_HASH = "FILE_HASH"
    URL = "URL"


class IoCEntity(BaseModel):
    value: str
    ioc_type: IoCType
    reputation_score: float = 0.0  # 0.0 (Clean) to 1.0 (Confirmed Malicious)
    threat_label: str = "Unknown"
    is_malicious: bool = False
    source: str = "Internal Analysis"


class MitreTTP(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
    evidence: str


class RemediationType(str, Enum):
    ISOLATE_HOST = "ISOLATE_HOST"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    BLOCK_IP = "BLOCK_IP"
    REVOKE_USER_SESSION = "REVOKE_USER_SESSION"
    QUARANTINE_FILE = "QUARANTINE_FILE"


class RemediationAction(BaseModel):
    action_id: str
    action_type: RemediationType
    target: str
    params: Dict[str, Any] = Field(default_factory=dict)
    confidence_score: float = 0.90
    requires_hitl_approval: bool = False
    executed: bool = False
    status_message: str = "Pending Execution"


class Incident(BaseModel):
    incident_id: str
    title: str
    severity: SeverityLevel
    created_at: datetime = Field(default_factory=datetime.utcnow)
    hostname: str
    username: str
    telemetry_events: List[TelemetryEvent] = Field(default_factory=list)
    iocs: List[IoCEntity] = Field(default_factory=list)
    mitre_ttps: List[MitreTTP] = Field(default_factory=list)
    remediation_actions: List[RemediationAction] = Field(default_factory=list)
    is_contained: bool = False
    executive_summary: str = ""
