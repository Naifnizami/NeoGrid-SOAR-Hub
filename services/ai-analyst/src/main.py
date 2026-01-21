import os
import sys
from fastapi import FastAPI
from dotenv import load_dotenv
from agno.agent import Agent
from agno.models.groq import Groq

# 1. PATH FIX FOR TOOLS
# Docker WORKDIR is /app. 'src' and 'tools' are siblings under /app.
sys.path.append('/app') 

from tools.intel_tools import check_ip_reputation, check_file_hash, get_mitre_context

# 2. LOAD SECRETS
# In Docker, we use 'env_file' so vars are usually already in the environment,
# but we'll call load_dotenv for local fallback.
load_dotenv()

# 🚨 DOCKER PATH: Corporate policy is mounted to /app/shared/
KNOWLEDGE_FILE = "/app/shared/security_policy_maintenance.md"

def get_security_policy():
    """Reads local SOC policies for RAG context inside the container."""
    try:
        with open(KNOWLEDGE_FILE, 'r') as f:
            return f.read()
    except Exception as e:
        # We print a brutal warning if the volume mount failed
        print(f"[🚨 DOCKER ERROR] Volume not found at {KNOWLEDGE_FILE}: {e}")
        return "No specific maintenance policy found."

POLICY_TEXT = get_security_policy()

app = FastAPI(title="NGF AI Analyst Service")

# 3. THE ANALYST AGENT
analyst_agent = Agent(
    model=Groq(id="llama-3.3-70b-versatile"),
    tools=[check_ip_reputation, check_file_hash, get_mitre_context],
    instructions=[
        "You are a Senior Tier-3 SOC Analyst at NeoGrid Financial.",
        "--- CORPORATE SECURITY POLICY ---",
        POLICY_TEXT,
        "--- END POLICY ---",
        "",
        "🚨 DECISION PROTOCOL (MANDATORY) 🚨:",
        "Every response MUST start with a machine-readable line. ",
        "FORMAT Line 1 exactly as follows:",
        "- If Case 2 (Authorized Gateway Backup) -> [DECISION] | AUTHORIZED",
        "- If violates Section 2 Prohibited List -> [DECISION] | MALICIOUS",
        "- For everything else (Default/Noise)   -> [DECISION] | SUSPICIOUS",
        "",
        "After Line 1, provide a flat technical report using ## Headers.",
        "Check IP reputation and map to MITRE ATT&CK codes."
    ]
)

@app.post("/analyze")
async def analyze_incident(data: dict):
    print(f"[*] DOCKER-LOG: Analyzing alert from {data['hostname']}...")
    
    prompt = f"""
    ANALYSIS REQUEST:
    Host: {data.get('hostname')} | IP: {data.get('ip_address')}
    Risk: {data.get('criticality')} | Command: `{data.get('command')}`

    Provide a forensic report. Start your response with Line 1: [DECISION] | verdict.
    """
    
    response = analyst_agent.run(prompt)
    return {"verdict_report": response.content}

if __name__ == "__main__":
    import uvicorn
    print(f"[*] ANALYST BRAIN READY ON PORT 8001")
    # 🚨 CRITICAL CHANGE FOR DOCKER: host MUST be 0.0.0.0
    uvicorn.run(app, host="0.0.0.0", port=8001)