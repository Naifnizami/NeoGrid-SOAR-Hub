import os
import sys
import json
from fastapi import FastAPI
from dotenv import load_dotenv
from agno.agent import Agent
from agno.models.groq import Groq

# Ensure local modules are discoverable
sys.path.append('/app') 
from tools.intel_tools import check_ip_reputation, check_file_hash

load_dotenv()

# Configuration & Policy Loader
KNOWLEDGE_FILE = "/app/shared/security_policy_maintenance.md"
shared_model = Groq(id="llama-3.3-70b-versatile")

def get_security_policy():
    """Load RAG context from the shared policy folder."""
    if not os.path.exists(KNOWLEDGE_FILE):
        return "Internal Policy unavailable."
    with open(KNOWLEDGE_FILE, 'r') as f:
        return f.read()

POLICY_TEXT = get_security_policy()

# --- 🚀 EXPERT SWARM AGENTS ---

intel_expert = Agent(
    name="Intel_Expert",
    model=shared_model,
    tools=[check_ip_reputation, check_file_hash],
    instructions=["Expert in public threat reputation. Bypass internal/private targets."]
)

detection_expert = Agent(
    name="Detection_Expert",
    model=shared_model,
    instructions=["Identify MITRE ATT&CK techniques. Focus on T-code accuracy and recon detection."]
)

compliance_expert = Agent(
    name="Compliance_Expert",
    model=shared_model,
    instructions=[
        f"Refer to Security Policy: {POLICY_TEXT}",
        "1. DEFINITION: Metadata separators (; or PWD=) are NORMAL in logs.",
        "2. CHAINING CHECK: A command chain is malicious only if NEW BINARIES follow a whitelist binary (e.g., curl ; whoami).",
        "3. LOGIC: A pure 'sudo curl' exactly matching Section 1.3 is AUTHORIZED, regardless of session-open logs."
    ]
)

# --- 🧠 THE LEAD ORCHESTRATOR (V8.0 Zero-Bias & Syntax Fixed) ---

lead_analyst = Agent(
    name="SOC_Lead_Orchestrator",
    model=shared_model,
    instructions=[  
        "You are an Elite SOC Forensic Director. You judge sessions based on provided telemetry.",
        
        "🚨 DECISION HIERARCHY (MANDATORY) 🚨",
        "1. FORCE MALICIOUS: If 'logic_gate_flag' contains 'CRITICAL ALERT', you MUST rule MALICIOUS.",
        "   - Reason: A logic gate detected suspicious syntax (; or &&) used to hide commands.",
        "2. CHAIN DETECTION: Examine the full command trace. If you see a whitelisted curl FOLLOWED by 'id', 'whoami', 'cat', or 'ls', flag as MALICIOUS.",
        "3. LOG_METADATA_BYPASS: Ignore semicolons (;) when they appear in log metadata like 'PWD=/... ; USER=root'. These are not attacks.",

        "🚨 AUTHORIZATION CRITERIA 🚨",
        "1. MATCH: Rule as AUTHORIZED only if the command is purely Section 1.3 curl with NO secondary actions in the session.",
        "2. SUDO: Do not flag 'sudo' usage as malicious for the Kali host; it is an expected part of the maintenance window.",

        "⚠️ REPORTING PROTOCOL (JIRA/ADF COMPATIBLE) ⚠️",
        "• START with exactly: [DECISION] | (WORD). No intro text.",
        "• Use 'h2.' for all headers (No spaces before h2).",
        "• Use simple bullets (*) only. Never use numbers (1.) or letters (a.).",
    ],
    markdown=False
)

app = FastAPI(title="NeoGrid SOAR V8.5")

@app.post("/analyze")
async def analyze_incident(data: dict):
    # Resilience Check: If Tines sends data as a string, try to load it as JSON
    ocsf = data.get("ocsf_data", {})
    if isinstance(ocsf, str):
        try: ocsf = json.loads(ocsf)
        except: ocsf = {"error": "Could not parse OCSF"}

    hostname = data.get('hostname', 'unknown')
    # Use fallback if flag is missing
    gate_flag = data.get("logic_gate_flag") or "NO_GATE_DATA_RECEIVED" 
    history = data.get("FULL_TERMINAL_HISTORY", "N/A")

    print(f"[*] AI-SWARM: Analyzing {hostname} | Flag: {gate_flag}")

    # Start Swarm Logic
    try:
        det_log = detection_expert.run(f"Command context: {ocsf}").content
        comp_log = compliance_expert.run(f"Audit trace check: {history}").content

        mission = f"""
        VERIFY: {hostname}
        GATE OPINION: {gate_flag}
        RAW LOGS: {history}
        EXPERT 1 (EDR): {det_log}
        EXPERT 2 (POLICY): {comp_log}
        """

        report = lead_analyst.run(mission)
        return {"verdict_report": report.content}
    except Exception as e:
        print(f"[!] ERROR IN AI EXECUTION: {e}")
        return {"verdict_report": f"[DECISION] | ERROR: System failed during analysis - {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)