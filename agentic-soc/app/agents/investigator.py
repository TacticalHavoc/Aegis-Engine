import logging
import os
from typing import List, Optional, Set
from datetime import datetime, timezone

from app.models.alert import Alert
from app.models.investigation import Evidence, InvestigationResult, NetworkEvent, ProcessEvent
from app.tools.network_tools import get_network_logs
from app.tools.process_tools import get_process_logs

logger = logging.getLogger(__name__)


class InvestigationAgent:
    """
    Investigation Agent responsible for answering: 'What actually happened?'
    
    Interacts with telemetry via read-only tools to retrieve process and network logs,
    correlate multi-source activity, and synthesize structured evidence.
    """

    def __init__(self, model: Optional[str] = None):
        self.agent_name = "HostInvestigator"
        self.model = model or os.getenv("AGENT_MODEL")

    async def investigate(self, alert: Alert) -> InvestigationResult:
        """
        Asynchronously investigate a security alert across multi-source telemetry.
        """
        logger.info(f"[{self.agent_name}] Commencing investigation for alert {alert.alert_id} on {alert.host}")

        # 1. Query relevant process logs using read-only tool
        process_logs: List[ProcessEvent] = get_process_logs(
            host=alert.host,
            timestamp=alert.timestamp,
            window_minutes=15,
        )

        evidence_list: List[Evidence] = []
        is_suspicious = False
        summary_points: List[str] = []
        suspicious_pids: Set[int] = set()

        if not process_logs:
            summary_points.append(f"No process telemetry found for host {alert.host} within the ±15m window.")
            return InvestigationResult(
                alert_id=alert.alert_id,
                host=alert.host,
                verdict="inconclusive",
                summary=" ".join(summary_points),
                evidence=evidence_list,
            )

        summary_points.append(f"Retrieved {len(process_logs)} process event(s) around alert timestamp.")

        # 2. Analyze process telemetry for indicators of malicious activity
        for event in process_logs:
            # Check for encoded PowerShell commands
            if "powershell" in event.process_name.lower() and ("-enc" in event.command_line.lower() or "-encodedcommand" in event.command_line.lower()):
                is_suspicious = True
                suspicious_pids.add(event.process_id)
                evidence_list.append(
                    Evidence(
                        artifact_type="encoded_powershell_execution",
                        description=f"PowerShell executed with encoded payload (PID {event.process_id}, Parent PID {event.parent_process_id}).",
                        data={
                            "event_id": event.event_id,
                            "process_name": event.process_name,
                            "process_id": event.process_id,
                            "command_line": event.command_line,
                            "parent_process": event.parent_process_name,
                            "user": event.user,
                        },
                        confidence=0.95,
                    )
                )
                summary_points.append(f"Detected obfuscated PowerShell execution (PID {event.process_id}).")

            # Check for suspicious reconnaissance child processes
            elif event.parent_process_name and "powershell" in event.parent_process_name.lower() and event.process_name.lower() in ["cmd.exe", "whoami.exe", "net.exe"]:
                is_suspicious = True
                suspicious_pids.add(event.process_id)
                evidence_list.append(
                    Evidence(
                        artifact_type="post_exploitation_recon",
                        description=f"Suspicious child reconnaissance process {event.process_name} spawned by PowerShell.",
                        data={
                            "event_id": event.event_id,
                            "process_name": event.process_name,
                            "process_id": event.process_id,
                            "command_line": event.command_line,
                            "parent_process": event.parent_process_name,
                            "user": event.user,
                        },
                        confidence=0.90,
                    )
                )
                summary_points.append(f"Detected post-exploitation recon command ({event.command_line}).")

        # 3. Pivot to Network Telemetry for suspicious PIDs
        for pid in suspicious_pids:
            net_events: List[NetworkEvent] = get_network_logs(
                host=alert.host,
                timestamp=alert.timestamp,
                window_minutes=15,
                process_id=pid,
            )
            for net_evt in net_events:
                evidence_list.append(
                    Evidence(
                        artifact_type="network_c2_connection",
                        description=f"Outbound network socket initiated by suspicious PID {pid} to {net_evt.destination_ip}:{net_evt.destination_port} ({net_evt.domain or 'No Domain'}).",
                        data={
                            "event_id": net_evt.event_id,
                            "process_id": net_evt.process_id,
                            "process_name": net_evt.process_name,
                            "source_ip": net_evt.source_ip,
                            "destination_ip": net_evt.destination_ip,
                            "destination_port": net_evt.destination_port,
                            "protocol": net_evt.protocol,
                            "domain": net_evt.domain,
                        },
                        confidence=0.95,
                    )
                )
                summary_points.append(
                    f"Correlated outbound connection from PID {pid} to {net_evt.destination_ip}:{net_evt.destination_port} ({net_evt.domain})."
                )

        # 4. Formulate final verdict and synthesis
        if is_suspicious:
            verdict = "suspicious"
            summary = "Investigation confirmed malicious activity: " + " ".join(summary_points)
        else:
            verdict = "benign"
            summary = "Investigation completed. No malicious process or network behavior identified: " + " ".join(summary_points)

        result = InvestigationResult(
            alert_id=alert.alert_id,
            host=alert.host,
            verdict=verdict,
            summary=summary,
            evidence=evidence_list,
        )

        logger.info(f"[{self.agent_name}] Investigation completed for {alert.alert_id} with verdict: {verdict}")
        return result

    def investigate_sync(self, alert: Alert) -> InvestigationResult:
        """
        Synchronous helper for executing an investigation.
        """
        import asyncio
        return asyncio.run(self.investigate(alert))
