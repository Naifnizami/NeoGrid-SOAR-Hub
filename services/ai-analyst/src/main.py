import os
import sys
from fastapi import FastAPI
from dotenv import load_dotenv
from agno.agent import Agent
from agno.models.groq import Groq

# 1. PATH FIX FOR TOOLS
sys.path.append('/app') 
from tools.intel_tools import check_ip_reputation, check_file_hash, get_mitre_context

load_dotenv()

# Load Corporate Policy Context
KNOWLEDGE_FILE = "/app/shared/security_policy_maintenance.md"
def get_security_policy():
    try:
        with open(KNOWLEDGE_FILE, 'r') as f: return f.read()
    except: return "No maintenance policy found."

POLICY_TEXT = get_security_policy()
shared_model = Groq(id="llama-3.3-70b-versatile")

# --- 🚀 THE AGNO TEAM SPECIALISTS ---

intel_specialist = Agent(
    name="Threat_Intel_Specialist",
    model=shared_model,
    tools=[check_ip_reputation, check_file_hash],
    instructions=["Identify reputation only. Output ONLY raw facts. Do NOT use for private IPs."]
)

mitre_specialist = Agent(
    name="MITRE_Detection_Engineer",
    model=shared_model,
    tools=[get_mitre_context],
    instructions=["Break down behaviors and identify T-codes. Do NOT decriptify logs yourself; use tools."]
)

compliance_specialist = Agent(
    name="Corporate_Compliance_Auditor",
    model=shared_model,
    instructions=[f"Verify activity against NeoGrid internal governance rules: {POLICY_TEXT}"]
)

# --- 🧠 THE LEAD ORCHESTRATOR (FINAL REFINEMENT) ---

lead_analyst = Agent(
    name="SOC_Lead_Orchestrator",
    role="L3 Senior Incident Manager",
    model=shared_model,
    instructions=[
        "You are the Lead Analyst. You correlate Specialist reports into a final verdict.",
        "Your goal is zero-touch triage. Trust the Compliance expert's policy matches above all else.",
        "",
        "🚨 RESPONSE PROTOCOL (CRITICAL) 🚨",
        "Line 1 MUST be plain text with no symbols: [DECISION] | [VERDICT]",
        "Verdicts are: AUTHORIZED, MALICIOUS, or SUSPICIOUS.",
        "DO NOT use '##' or '#' for Line 1. No preamble.",
        "",
        "REPORT STRUCTURE (Wiki Markup):",
        "h2. TECHNICAL ANALYSIS (Consolidated facts)",
        "h2. CONTEXT AUDIT (Governance findings)",
        "h2. MITRE ATT&CK (Final technique ID)",
        "h2. RECOMMENDED REMEDIATION (Mandatory IR steps)"
    ],
    markdown=False
)

# --- 🛠️ FASTAPI SERVICE ---
app = FastAPI(title="NeoGrid Main-Agent Autonomous Swarm")

@app.post("/analyze")
async def analyze_incident(data: dict):
    host = data.get('hostname')
    ip = data.get('ip_address')
    cmd = data.get('command')
    is_private_ip = any(ip.startswith(prefix) for prefix in ['10.', '192.168.', '172.16.'])
    
    # 🩹 FIX 1: Pydantic Validation Safety (Bool to String)
    timing_str = "IN-WORK-HOURS" if data.get('is_business_hours') else "AFTER-HOURS"

    print(f"[*] MANAGER: Investigating triage task for {host}...")

    # --- THE JUAN MODEL: ORCHESTRATE EXPERTS DYNAMICALLY ---
    
    # Context-Aware Intel Choice
    if not is_private_ip:
        print("[*] DELEGATING: Fetching Global Threat Intel.")
        intel_report = intel_specialist.run(f"Lookup reputation for PUBLIC IP: {ip}").content
    else:
        intel_report = "Specialist Skip: Context is an Internal Private Asset."

    # Behavioral specialist
    print("[*] DELEGATING: Running TTP behavior analysis.")
    mitre_report = mitre_specialist.run(f"Identify T-Codes for this command log: `{cmd}`").content

    # Policy specialist
    print("[*] DELEGATING: Performing Policy & Business audit.")
    comp_report = compliance_specialist.run(f"Audit {host} during {timing_str} with cmd: `{cmd}`").content

    # Step 2: Feed expert results to the Team Manager for correlation
    orchestration_mission = f"""
    ### SPECIALIST DOSSIER FOR L3 REVIEW:
    1. THREAT INTEL: {intel_report}
    2. DETECTION ENGINEER: {mitre_report}
    3. COMPLIANCE AUDIT: {comp_report}
    
    META: host={host} | IP={ip} | time_ctx={timing_str}
    
    ACTION: Produce the single forensic investigation report based on these dossiers.
    """
    
    response = lead_analyst.run(orchestration_mission)
    return {"verdict_report": response.content}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)