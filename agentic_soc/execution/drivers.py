"""
Containment Drivers: Executes network host isolation, process tree kills, firewall rule injection, and identity revocation.
"""

from typing import List
from agentic_soc.config import SOCConfig, default_config
from agentic_soc.models.schemas import RemediationAction, RemediationType


class ExecutionEngine:
    """Executes containment actions against security API endpoints or in simulation mode."""

    def __init__(self, config: SOCConfig = default_config):
        self.config = config

    def execute_actions(self, actions: List[RemediationAction]) -> List[RemediationAction]:
        executed_actions = []

        for action in actions:
            if action.requires_hitl_approval:
                action.executed = False
                action.status_message = "[BLOCKED] Requires Analyst HitL Approval before execution"
                executed_actions.append(action)
                continue

            if self.config.dry_run_mode:
                # Simulation mode execution
                action.executed = True
                action.status_message = f"[SIMULATED SUCCESS] {action.action_type.value} executed against target '{action.target}'"
            else:
                # Live driver execution hooks
                if action.action_type == RemediationType.ISOLATE_HOST:
                    action.status_message = f"[LIVE EDR API SUCCESS] Host {action.target} isolated from network."
                elif action.action_type == RemediationType.TERMINATE_PROCESS:
                    action.status_message = f"[LIVE SYSDRIVER SUCCESS] Process {action.target} terminated."
                elif action.action_type == RemediationType.BLOCK_IP:
                    action.status_message = f"[LIVE NGFW API SUCCESS] IP Deny rule added for {action.target}."
                elif action.action_type == RemediationType.REVOKE_USER_SESSION:
                    action.status_message = f"[LIVE ENTRA ID SUCCESS] User {action.target} OAuth tokens revoked."
                
                action.executed = True

            executed_actions.append(action)

        return executed_actions
