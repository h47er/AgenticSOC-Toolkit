"""
Incident Report Synthesizer: Synthesizes Markdown reports complete with Mermaid attack timelines, MITRE matrices, and IoC inventories.
"""

from datetime import datetime
from agentic_soc.models.schemas import Incident


class ReportGenerator:
    """Generates standardized Markdown Incident Response reports."""

    @staticmethod
    def generate_markdown_report(incident: Incident) -> str:
        report = []
        report.append(f"# 🚨 AUTONOMOUS INCIDENT RESPONSE REPORT: {incident.incident_id}\n")
        report.append(f"**Title**: {incident.title}  ")
        report.append(f"**Severity**: 🔴 `{incident.severity.value}`  ")
        report.append(f"**Target Host**: `{incident.hostname}`  ")
        report.append(f"**Associated User**: `{incident.username}`  ")
        report.append(f"**Report Generated**: `{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}`  ")
        report.append(f"**Containment Status**: {'🟢 CONTAINED' if incident.is_contained else '🟡 IN PROGRESS / HITL REQUIRED'}\n")
        report.append("---\n")

        # Section 1: Executive Summary
        report.append("## 1. Executive Summary\n")
        summary_text = incident.executive_summary or (
            f"The Autonomous SOC Agent detected multi-stage threat activity targeting host `{incident.hostname}` "
            f"associated with user `{incident.username}`. Suspicious activities included obfuscated script execution, "
            f"credential access attempts against LSASS memory, and command-and-control beaconing. "
            f"Machine-speed containment actions were evaluated and executed according to risk guardrails."
        )
        report.append(f"{summary_text}\n\n")

        # Section 2: MITRE ATT&CK Mapping
        report.append("## 2. MITRE ATT&CK Framework Mapping\n")
        if incident.mitre_ttps:
            report.append("| Tactic | Technique ID | Technique Name | Observed Evidence |")
            report.append("| :--- | :--- | :--- | :--- |")
            for ttp in incident.mitre_ttps:
                report.append(f"| **{ttp.tactic}** | `{ttp.technique_id}` | {ttp.technique_name} | {ttp.evidence} |")
            report.append("\n")
        else:
            report.append("No specific MITRE ATT&CK techniques mapped for this incident.\n\n")

        # Section 3: Attack Chronology & Mermaid Timeline
        report.append("## 3. Incident Timeline & Attack Reconstruction\n")
        if incident.telemetry_events:
            report.append("```mermaid")
            report.append("timeline")
            report.append(f"    title Incident Timeline ({incident.incident_id})")
            for evt in incident.telemetry_events:
                time_str = evt.timestamp.strftime("%H:%M:%S")
                desc = evt.command_line or evt.process_name or evt.category.value
                # Clean description for Mermaid syntax
                clean_desc = desc.replace(":", " - ").replace('"', "'")[:60]
                report.append(f"    {time_str} : {clean_desc}")
            report.append("```\n\n")

        # Section 4: Indicators of Compromise (IoCs)
        report.append("## 4. Indicators of Compromise (IoCs)\n")
        if incident.iocs:
            report.append("| Type | Value | Threat Label | Reputation Score | Malicious |")
            report.append("| :--- | :--- | :--- | :--- | :--- |")
            for ioc in incident.iocs:
                is_mal = "YES 🔴" if ioc.is_malicious else "NO 🟢"
                report.append(f"| `{ioc.ioc_type.value}` | `{ioc.value}` | {ioc.threat_label} | {ioc.reputation_score:.2f} | {is_mal} |")
            report.append("\n")
        else:
            report.append("No extracted IoCs found.\n\n")

        # Section 5: Remediation & Mitigation Actions
        report.append("## 5. Automated Remediation & Mitigation Log\n")
        if incident.remediation_actions:
            report.append("| Action ID | Action Type | Target | Confidence | Executed | Status Message |")
            report.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for act in incident.remediation_actions:
                exec_str = "✅ YES" if act.executed else "⏳ HITL BLOCKED"
                report.append(f"| `{act.action_id}` | `{act.action_type.value}` | `{act.target}` | {act.confidence_score:.2f} | {exec_str} | {act.status_message} |")
            report.append("\n")
        else:
            report.append("No remediation actions scheduled.\n\n")

        # Section 6: Recommended Human Analyst Follow-Up
        report.append("## 6. Recommended Analyst Follow-Up\n")
        report.append("- [ ] Perform forensic memory inspection on target host to confirm no secondary persistence.")
        report.append("- [ ] Audit active directory logs for secondary user accounts associated with host login.")
        report.append("- [ ] Verify firewall block rule status across edge router infrastructure.\n")

        return "\n".join(report)
