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

# Load Corporate Policy
KNOWLEDGE_FILE = "/app/shared/security_policy_maintenance.md"
def get_security_policy():
    try:
        if not os.path.exists(KNOWLEDGE_FILE):
            return "No specific maintenance policy found."
        with open(KNOWLEDGE_FILE, 'r') as f:
            return f.read()
    except:
        return "Internal Policy knowledge is currently unavailable."

POLICY_TEXT = get_security_policy()

# --- 🚀 TEAM DEFINITION: SPECIALIZED AGENTS ---

shared_model = Groq(id="llama-3.3-70b-versatile")

# 🕵️ Specialist 1: Threat Intelligence Specialist
intel_specialist = Agent(
    name="Threat Intel Specialist",
    role="Reputation Analysis Auditor",
    model=shared_model,
    tools=[check_ip_reputation, check_file_hash],
    instructions=[
        "Identify reputation data only.",
        "IF THE IP IS PRIVATE, respond with: 'Internal Network Asset. Tool lookup bypassed.'",
        "Otherwise, summarize global reputation scores and engine hits."
    ]
)

# 🛠️ Specialist 2: Detection Engineer
detection_specialist = Agent(
    name="Detection Specialist",
    role="MITRE ATT&CK Mapping expert",
    model=shared_model,
    tools=[get_mitre_context],
    instructions=[
        "Focus strictly on the behavior of the 'Command'.",
        "Map it to a MITRE Technique using tools or your internal logic.",
        "Provide T-code evidence. Be concise."
    ]
)

# 🏢 Specialist 3: Compliance & Asset Specialist
compliance_specialist = Agent(
    name="Compliance Agent",
    role="Internal Corporate Governance expert",
    model=shared_model,
    instructions=[
        "Evaluate signals against Corporate Policy.",
        f"POLICY SOURCE: {POLICY_TEXT}",
        "CRITICAL: If the activity (like Scenario 2 Backup) matches SECTION 1 precisely, tag it as 'MATCHED EXCEPTION'.",
        "Check business hours logic and asset criticality."
    ]
)

# --- 🧠 LEAD ANALYST: THE "NO-FLUFF" ORCHESTRATOR ---

lead_analyst = Agent(
    name="Lead SOC Analyst",
    role="L3 Senior Decision Maker",
    model=shared_model,
    instructions=[
        "You provide the FINAL EXECUTIVE VERDICT. Your goal is SOC efficiency.",
        
        "🚨 TRIAGE POLICY 🚨",
        "If the Compliance Specialist reports a 'MATCHED EXCEPTION' or an approved activity, your decision is AUTHORIZED.",
        "If the Detection Engineer reports Malicious activity and no exception matches, your decision is MALICIOUS.",
        
        "⚠️ OUTPUT RULES (JIRA WIKI FORMAT) ⚠️",
        "LINE 1: You must output exactly: [DECISION] | AUTHORIZED or [DECISION] | MALICIOUS or [DECISION] | SUSPICIOUS",
        "DO NOT use # or ## or any markdown headers. DO NOT include introductory chatter.",
        
        "FORMATTING STRUCTURE:",
        "h2. TECHNICAL ANALYSIS",
        "Detailed synthesis of specialist findings. Use *bold* for emphasis.",
        "h2. CONTEXT AUDIT",
        "Audit of Policy windows and Asset role.",
        "h2. MITRE ATT&CK",
        "Technique ID and Tactic description.",
        "h2. RECOMMENDED REMEDIATION",
        "Required response actions."
    ],
    markdown=False
)

# --- 🛠️ FASTAPI SERVICE ---
app = FastAPI(title="NeoGrid AI Agent Swarm Swarm Swarm Swarm Swarm")

@app.post("/analyze")
async def analyze_incident(data: dict):
    host = data.get('hostname')
    ip = data.get('ip_address')
    cmd = data.get('command')
    is_biz = data.get('is_business_hours')
    crit = data.get('criticality')

    print(f"[*] AGENT SWARM: Investigating {host} with team...")

    # Step 1: Trigger Specialized Analysis
    intel_rep = intel_specialist.run(f"Signals: IP {ip}")
    detection_rep = detection_specialist.run(f"Signals: Command {cmd}")
    compliance_rep = compliance_specialist.run(f"Context: {host}, Criticality: {crit}, BizHours: {is_biz}, Command: {cmd}")

    # Step 2: Feed expert data to the Lead Orchestrator
    orchestration_payload = f"""
    AUDIT REPORTS:
    1. INTEL SPECIALIST: {intel_rep.content}
    2. DETECTION ENGINEER: {detection_rep.content}
    3. COMPLIANCE AGENT: {compliance_rep.content}
    
    METADATA:
    Host: {host} | CMD: {cmd} | Hours: {is_biz} | TargetIP: {ip}
    """
    
    final_response = lead_analyst.run(orchestration_payload)
    return {"verdict_report": final_response.content.strip()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)