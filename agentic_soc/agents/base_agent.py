"""
Base Agent class defining shared interface and memory for SOC agents.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
from agentic_soc.models.schemas import Incident


class BaseAgent(ABC):
    """Abstract base class for specialized SOC agents."""

    def __init__(self, agent_name: str, role_description: str):
        self.agent_name = agent_name
        self.role_description = role_description

    @abstractmethod
    def process(self, incident: Incident, context: Dict[str, Any] = None) -> Incident:
        """Process the incident, update its state, and return the modified Incident object."""
        pass
