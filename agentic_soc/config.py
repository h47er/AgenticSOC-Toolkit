"""
Configuration settings for AgenticSOC framework including risk guardrails, API settings, and confidence thresholds.
"""

from typing import List, Set
from pydantic import BaseModel


class RiskGuardrailsConfig(BaseModel):
    # Minimum confidence score required to auto-isolate non-critical endpoints (0.0 - 1.0)
    auto_isolation_confidence_threshold: float = 0.85
    
    # Minimum confidence score to auto-block malicious C2 IP on firewall
    auto_firewall_block_threshold: float = 0.80
    
    # Critical hostnames that must NEVER be isolated automatically without Human-in-the-Loop (HitL) confirmation
    protected_critical_hosts: Set[str] = {
        "DC-01", "DC-02", "DOMAIN-CONTROLLER", "EXECUTIVE-HOST-01", "PROD-DB-PRIMARY"
    }
    
    # High risk operations that force HitL approval
    force_hitl_for_actions: List[str] = [
        "SUB_NET_SHUTDOWN", "DOMAIN_CONTROLLER_ISOLATION", "MASS_ACCOUNT_DISABLE"
    ]


class SOCConfig(BaseModel):
    app_name: str = "AgenticSOC-Toolkit"
    environment: str = "production"
    dry_run_mode: bool = True  # Default to dry-run simulation mode for safety
    guardrails: RiskGuardrailsConfig = RiskGuardrailsConfig()
    
    # Threat Intelligence API Keys (Optional defaults)
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""


# Default global configuration instance
default_config = SOCConfig()
