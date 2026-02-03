import os
import sys
from fastapi import FastAPI
from dotenv import load_dotenv
from agno.agent import Agent
from agno.models.groq import Groq

# 1. PATH FIX
sys.path.append('/app') 
from tools.intel_tools import check_ip_reputation, check_file_hash

load_dotenv()

# Load Corporate Policy Context (The RAG knowledge)
KNOWLEDGE_FILE = "/app/shared/security_policy_maintenance.md"

def get_security_policy():
    """Reads corporate policy. Uses 'os' to verify path integrity inside Docker."""
    if not os.path.exists(KNOWLEDGE_FILE):
        print("[🚨] CONFIG ERROR: Policy file not found in /app/shared/")
        return "Internal Policy knowledge is currently unavailable."
    try:
        with open(KNOWLEDGE_FILE, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error loading policy: {str(e)}"

POLICY_TEXT = get_security_policy()
shared_model = Groq(id="llama-3.3-70b-versatile")

# --- 🚀 OCSF SPECIALIST ROLES (Back-End Experts) ---

intel_expert = Agent(
    name="Intel_Expert",
    model=shared_model,
    tools=[check_ip_reputation, check_file_hash],
    instructions=[
        "You are an Elite Threat Intel Specialist.",
        
        "🚨 DATA GOVERNANCE & PRIVACY PROTOCOL 🚨",
        "1. SCOPE VERIFICATION: Before calling external tools, check the 'Target IP' category.",
        "2. NON-ROUTABLE GATE: If the IP is a Loopback address (127.x.x.x) or falls within an RFC 1918 Private range (10.x.x.x, 172.16.x.x-172.31.x.x, 192.168.x.x), DO NOT call 'check_ip_reputation'.",
        "3. JUSTIFICATION: For Loopback or RFC 1918 IPs, return: 'Bypassed: Internal Private Asset Context. Public reputation lookup not applicable for internal network topology.'",
        "4. EXTERNAL TARGETS ONLY: Run tools only for valid, public-routable IP addresses and SHA-256/MD5 hashes."
    ]
)

detection_expert = Agent(
    name="Detection_Expert",
    model=shared_model,
    instructions=[
        "Identify MITRE ATT&CK techniques from process [1007] telemetry.",
        "Provide T-code mappings and specific goal descriptions."
    ]
)

compliance_expert = Agent(
    name="Compliance_Expert",
    model=shared_model,
    instructions=[
        f"Match signals against policy windows and whitelists in: {POLICY_TEXT}",
        "Focus on Auth [3002] risks (mfa, logon_type)."
    ]
)

# --- 🧠 THE LEAD ORCHESTRATOR (L3 DECISION BRAIN) ---

lead_analyst = Agent(
    name="SOC_Lead_Orchestrator",
    role="Senior L3 Director",
    model=shared_model,
    instructions=[
        "You are the L3 Director. Your report is a formal legal record of the investigation.",
        
        "🚨 RESPONSE PROTOCOL (MANDATORY) 🚨",
        "1. NO CONVERSATION: Do not explain your steps or mention folders. Output ONLY the forensic results.",
        "2. SINGLE WORD VERDICT: You MUST choose EXACTLY ONE verdict: AUTHORIZED, MALICIOUS, or SUSPICIOUS.",
        "3. FORMAT: Line 1 MUST be exactly: [DECISION] | VERDICT (Replace VERDICT with your single chosen word).",
        "4. NO SYMBOLS: Never use # or ##. Use the h2. prefix for headers as defined below.",
        
        "⚠️ OUTPUT FORMAT ⚠️",
        "Line 1: [DECISION] | (MALICIOUS/AUTHORIZED/SUSPICIOUS)",
        "h2. TECHNICAL ANALYSIS (Merge Technical and Intelligence findings.)",
        "h2. IDENTITY & CONTEXT AUDIT (Analyze MFA, logon type, and policy windows.)",
        "h2. MITRE ATT&CK (Select the final technique ID mapping.)",
        "h2. RECOMMENDED REMEDIATION (Mandatory action plan.)"
    ],
    markdown=False
)

# --- 🛠️ FASTAPI SERVICE ---
app = FastAPI(title="NeoGrid OCSF Autonomous Director Swarm")

@app.post("/analyze")
async def analyze_incident(data: dict):
    ocsf = data.get("ocsf_data", {})
    hostname = data.get('hostname', 'unknown')
    ip = data.get('ip_address', '0.0.0.0')
    
    # Context Processing
    timing_str = "DURING-WORK-HOURS" if data.get('is_business_hours') else "AFTER-HOURS"
    is_private_ip = any(ip.startswith(prefix) for prefix in ['10.', '192.168.', '172.16.'])

    print(f"[*] DIRECTOR: Delegating OCSF-Native triage for {hostname} ({ip})...")

    # --- THE JUAN MODEL: ORCHESTRATE DELEGATES SEQUENTIALLY ---

    # A. Reputation Intelligence
    intel_report = "Director Notice: Target is Private IP. Public Intelligence Bypassed."
    if not is_private_ip:
        intel_report = intel_expert.run(f"Gather context for: {ocsf.get('network')}").content

    # B. Detection & TTPs
    detection_report = detection_expert.run(f"Map TTPs for process log: {ocsf.get('process')}").content

    # C. Compliance & Identity
    compliance_report = compliance_expert.run(
        f"Audit compliance for {hostname}. Context: {timing_str}. AuthLog: {ocsf.get('auth')}"
    ).content

    # --- 🏗️ THE FINAL SYNTHESIS Turn ---

    mission_dossiers = f"""
    EXPERT EVIDENCE LOGS:
    
    INTEL EVIDENCE [4001]: {intel_report}
    DETECTION EVIDENCE [1007]: {detection_report}
    GOVERNANCE EVIDENCE [3002]: {compliance_report}
    
    MISSION TARGET: host={hostname} | target_ip={ip} | time_ctx={timing_str}

    TASK: Act as L3 Director. Review Evidence and produce ONE structured Forensic Verdict. No chatter.
    """

    response = lead_analyst.run(mission_dossiers)
    
    return {"verdict_report": response.content}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)