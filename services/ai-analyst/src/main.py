import os  # <--- Now being used for the existence check
import sys
from fastapi import FastAPI
from dotenv import load_dotenv
from agno.agent import Agent
from agno.models.groq import Groq

# 1. PATH FIX
sys.path.append('/app') 
from tools.intel_tools import check_ip_reputation, check_file_hash

load_dotenv()

# Load Corporate Policy Context (RAG)
KNOWLEDGE_FILE = "/app/shared/security_policy_maintenance.md"

def get_security_policy():
    """Reads corporate policy. Uses 'os' to verify path integrity inside Docker."""
    if not os.path.exists(KNOWLEDGE_FILE): # <--- This makes the 'os' import active
        print("[🚨] CONFIG ERROR: Policy file not found in /app/shared/")
        return "Internal Policy knowledge is currently unavailable."
    try:
        with open(KNOWLEDGE_FILE, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error loading policy: {str(e)}"

POLICY_TEXT = get_security_policy()
shared_model = Groq(id="llama-3.3-70b-versatile")

# --- 🚀 OCSF SPECIALIST ROLES ---

intel_expert = Agent(
    name="Intel_Expert",
    model=shared_model,
    tools=[check_ip_reputation, check_file_hash],
    instructions=["Audit OCSF Network Activity [4001]. Focus on dst_endpoint reputation. Skip if IP is private."]
)

detection_expert = Agent(
    name="Detection_Expert",
    model=shared_model,
    instructions=[
        "Audit OCSF Process Activity [1007]. Analyze cmd_line and integrity_level.",
        "Identify MITRE ATT&CK techniques using your internal knowledge. Provide technique IDs."
    ]
)

compliance_expert = Agent(
    name="Compliance_Expert",
    model=shared_model,
    instructions=[
        f"Audit OCSF Authentication [3002]. Match against Policy: {POLICY_TEXT}.",
        "Focus on identity legitimacy and maintenance window violations."
    ]
)

# --- 🧠 THE LEAD ORCHESTRATOR (TEAM BOSS) ---

lead_analyst = Agent(
    name="SOC_Lead_Orchestrator",
    role="Senior L3 Incident Response Director",
    model=shared_model,
    instructions=[
        "You are the L3 Director responsible for correlating specialized forensic folders into a unified verdict.",

        "🚨 TRIAGE ARCHITECTURE (Juan Model) 🚨",
        "1. CONTEXTUAL REASONING: You receive 'Specialist dossiers'. Analyze the mission metadata first.",
        "2. IP PRIORITY: Note if the Intel Specialist was bypassed. If the asset is internal, base the decision purely on Policy and Technical Behavior.",
        "3. RESOLUTION: If the COMPLIANCE DOSSIER identifies an approved Section 1 maintenance sync, the decision is AUTHORIZED. Policy matches override technical suspicions.",

        "🚨 VERDICT SELECTION (STRICT) 🚨",
        "Line 1 MUST be exactly: [DECISION] | [VERDICT]",
        "Verdicts MUST BE: MALICIOUS, AUTHORIZED, or SUSPICIOUS.",
        "DO NOT use the word 'UNAUTHORIZED' in Line 1. Use 'MALICIOUS' for policy violations.",
        "Do NOT include introductory chatter like 'Here is my report' or 'Steps taken...'.",

        "⚠️ JIRA REPORT FORMAT (Wiki Markup) ⚠️",
        "Use exactly these h2. headers for a professional visual report in Jira:",
        "h2. TECHNICAL ANALYSIS (Breakdown of indicators found in dossiers)",
        "h2. IDENTITY & CONTEXT AUDIT (Correlation of login types, mfa, and policy window)",
        "h2. MITRE ATT&CK (Identify specific T-Codes and goals)",
        "h2. RECOMMENDED REMEDIATION (Urgent action items)"
    ],
    markdown=False
)

# --- 🛠️ FASTAPI SERVICE ---
app = FastAPI(title="NeoGrid OCSF Swarm Swarm Swarm V3")

@app.post("/analyze")
async def analyze_incident(data: dict):
    ocsf = data.get("ocsf_data", {})
    hostname = data.get('hostname', 'unknown-host')
    ip = data.get('ip_address', '0.0.0.0')
    
    # Context-Sensitive Variable Mapping
    timing_str = "IN-WORK-HOURS" if data.get('is_business_hours') else "AFTER-HOURS"
    is_private_ip = any(ip.startswith(prefix) for prefix in ['10.', '192.168.', '172.16.'])

    print(f"[*] AGENT_MANAGER: Investigating triage mission for {hostname} ({ip})...")

    # --- THE JUAN MODEL: DELEGATE BASED ON CONTEXT ---

    # 1. Intel (Network Dossier [4001])
    intel_report = "Specialist Notice: Internal Private Target. Threat Intel Bypassed."
    if not is_private_ip:
        print("[*] DELEGATING: Running Reputation Specialists.")
        intel_report = intel_expert.run(f"Indicators: {ocsf.get('network')}").content

    # 2. Behavior (Detection Dossier [1007])
    print("[*] DELEGATING: Running TTP Mapping Specialist.")
    detection_report = detection_expert.run(f"Process Metrics: {ocsf.get('process')}").content

    # 3. Compliance (Identity Dossier [3002])
    print("[*] DELEGATING: Running Governance Auditor.")
    comp_report = compliance_expert.run(
        f"Compliance Mission: host={hostname}, schedule={timing_str}, AuthContext: {ocsf.get('auth')}"
    ).content

    # --- 🏗️ SYNTHESIS: THE MAIN AGENT DECISION ---

    mission_packet = f"""
    EXPERT ANALYSIS PACKETS FOR REVIEW:
    
    FOLDER A (Intel 4001): {intel_report}
    FOLDER B (Behavior 1007): {detection_report}
    FOLDER C (Governance 3002): {comp_report}
    
    META: asset={hostname} | IP={ip} | time_ctx={timing_str}

    GOAL: Final Forensic Verdict and Synthesis. Provide headers for TECHNICAL ANALYSIS and RECOMMENDED REMEDIATION.
    """

    print(f"[*] LEAD_ANALYST: Processing final incident correlation...")
    response = lead_analyst.run(mission_packet)
    
    return {"verdict_report": response.content}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)