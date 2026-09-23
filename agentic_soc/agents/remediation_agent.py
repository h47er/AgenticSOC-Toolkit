"""
Remediation Agent: Evaluates risk safety scores and generates containment action plans.
"""

from typing import Dict, Any, List
from agentic_soc.agents.base_agent import BaseAgent
from agentic_soc.config import SOCConfig, default_config
from agentic_soc.models.schemas import (
    Incident,
    RemediationAction,
    RemediationType,
    SeverityLevel
)


class RemediationAgent(BaseAgent):
    """Evaluates incident threat severity against risk guardrails to build a containment plan."""

    def __init__(self, config: SOCConfig = default_config):
        super().__init__(
            agent_name="RemediationAgent",
            role_description="Evaluates containment options, applies risk safety guardrails, and schedules remediation API actions."
        )
        self.config = config

    def process(self, incident: Incident, context: Dict[str, Any] = None) -> Incident:
        actions: List[RemediationAction] = []
        guardrails = self.config.guardrails

        # Check Host Isolation Guardrail
        is_critical_host = incident.hostname in guardrails.protected_critical_hosts
        requires_hitl = is_critical_host or incident.severity == SeverityLevel.CRITICAL

        # 1. Endpoint Isolation Action
        actions.append(
            RemediationAction(
                action_id=f"ACT-{len(actions)+1:03d}",
                action_type=RemediationType.ISOLATE_HOST,
                target=incident.hostname,
                params={"host_id": incident.hostname, "network_quarantine": True},
                confidence_score=0.95,
                requires_hitl_approval=requires_hitl,
                status_message="Host isolation scheduled" if not requires_hitl else "Pending Analyst HitL Approval (Protected Host)"
            )
        )

        # 2. Process Termination Actions
        for event in incident.telemetry_events:
            if event.process_id and event.process_name in ["powershell.exe", "cmd.exe", "mshta.exe"]:
                actions.append(
                    RemediationAction(
                        action_id=f"ACT-{len(actions)+1:03d}",
                        action_type=RemediationType.TERMINATE_PROCESS,
                        target=f"PID_{event.process_id}",
                        params={"process_id": event.process_id, "process_name": event.process_name},
                        confidence_score=0.98,
                        requires_hitl_approval=False,
                        status_message=f"Process tree kill scheduled for PID {event.process_id}"
                    )
                )

        # 3. Firewall Block Actions
        for ioc in incident.iocs:
            if ioc.is_malicious and ioc.ioc_type.value == "IP_ADDRESS":
                actions.append(
                    RemediationAction(
                        action_id=f"ACT-{len(actions)+1:03d}",
                        action_type=RemediationType.BLOCK_IP,
                        target=ioc.value,
                        params={"ip_address": ioc.value, "direction": "INBOUND_OUTBOUND"},
                        confidence_score=0.90,
                        requires_hitl_approval=False,
                        status_message=f"Firewall Deny rule scheduled for IP {ioc.value}"
                    )
                )

        # 4. Identity Session Revocation Action
        if incident.username:
            actions.append(
                RemediationAction(
                    action_id=f"ACT-{len(actions)+1:03d}",
                    action_type=RemediationType.REVOKE_USER_SESSION,
                    target=incident.username,
                    params={"user_principal": incident.username, "revoke_tokens": True},
                    confidence_score=0.92,
                    requires_hitl_approval=False,
                    status_message=f"OAuth session revocation scheduled for user {incident.username}"
                )
            )

        incident.remediation_actions = actions
        return incident
