import os
import sys
from fastapi import FastAPI
from dotenv import load_dotenv
from agno.agent import Agent
from agno.models.groq import Groq

# 1. PATH FIX FOR TOOLS
# Ensure tools/ folder is accessible regardless of how the container starts
sys.path.append('/app') 
from tools.intel_tools import check_ip_reputation, check_file_hash, get_mitre_context

load_dotenv()

KNOWLEDGE_FILE = "/app/shared/security_policy_maintenance.md"

def get_security_policy():
    """Reads the corporate RAG context to identify approved behaviors."""
    try:
        if not os.path.exists(KNOWLEDGE_FILE):
            return "Policy error: Maintenance guide not found."
        with open(KNOWLEDGE_FILE, 'r') as f:
            return f.read()
    except Exception as e:
        print(f"[🚨] Policy Load Error: {e}")
        return "No specific maintenance policy found."

POLICY_TEXT = get_security_policy()

app = FastAPI(title="NeoGrid AI Analyst Service")

# 2. THE UPGRADED AGENT: BEHAVIORAL ANALYST TUNING
# Focused on identifying account misuse and business-context anomalies
analyst_agent = Agent(
    model=Groq(id="llama-3.3-70b-versatile"),
    tools=[check_ip_reputation, check_file_hash, get_mitre_context],
    instructions=[
        "You are an Elite Level-3 SOC Incident Responder specializing in Behavioral Analysis.",
        "Your mission is to differentiate between approved IT admin work and advanced attacker movements.",
        
        "--- CORPORATE POLICY CONTEXT ---",
        POLICY_TEXT,
        "--- END POLICY ---",
        
        "🚨 ANALYSIS PROTOCOL 🚨",
        "1. BEHAVIORAL TRIAGE: Cross-reference 'Command' with 'is_business_hours'. Unauthorized commands executed outside hours are high-risk.",
        "2. ACCOUNT MISUSE: Look for misuse of valid accounts. Even if the account is an Admin, verify if the pattern matches a Policy Whitelist.",
        "3. INTEL GATHERING: Map the command behavior to a MITRE ATT&CK T-code using tools.",
        "4. **IP PRIORITY**: If the Target System/IP is PRIVATE (10.x, 192.168.x, 172.16.x), prioritize the CORPORATE POLICY above all else and DO NOT call external IP tools.",
        
        "⚠️ MANDATORY RESPONSE RULES ⚠️",
            "LINE 1 MUST be exactly one of these headers:",
            "[DECISION] | AUTHORIZED",
            "[DECISION] | MALICIOUS",
            "[DECISION] | SUSPICIOUS",
            "If a tool fails to provide a result, mention 'Threat Intelligence unavailable' and make your decision based on Behavioral Policy alone."
        
        # --- FINAL FIX: USE WIKI MARKUP (h2. and *bold*) AND ENFORCE NO PRE-TEXT ---
        "CRITICAL: The ONLY output required is the final REPORT STRUCTURE below. DO NOT generate any introductory text, steps, or redundant [DECISION] headers after Line 1.",
        
        "REPORT STRUCTURE (Jira Wiki Markup):",
        "h2. TECHNICAL ANALYSIS (What the command actually does and Tool findings)",
        "h2. CONTEXT AUDIT (Role vs Business Hours vs Policy)",
        "h2. MITRE ATT&CK (T-Code and description)",
        "h2. RECOMMENDED REMEDIATION (e.g. Host Isolation, Password Reset, etc.)"
    ],
    markdown=False # Set to False so it doesn't automatically escape our Wiki Markup
)

@app.post("/analyze")
async def analyze_incident(data: dict):
    # Log incoming telemetry for observability
    host = data.get('hostname')
    ip = data.get('ip_address')
    print(f"[*] AGENT LOG: Performing Behavioral Triage for {host} ({ip})")
    
    # Check for a private IP range to inform the AI
    is_private_ip = ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.16.')

    # 3. CONTEXT-RICH PROMPT
    # We remove the external tool instruction entirely, as the Agent's instructions now cover conditional tool use.
    prompt = f"""
    Investigate the following signal from the SOAR Bridge:
    - Hostname: {host}
    - Criticality Level: {data.get('criticality', 'Standard')}
    - Target System/IP: {ip}
    - Is During Business Hours: {data.get('is_business_hours', 'Unknown')}
    - Redacted Command: `{data.get('command')}`
    CRITICAL SUMMARY: The IP is {'PRIVATE' if is_private_ip else 'PUBLIC'}. Follow the IP PRIORITY rules in the analysis protocol.
    """
    
    response = analyst_agent.run(prompt)
    return {"verdict_report": response.content}

if __name__ == "__main__":
    import uvicorn
    # Listening on internal Docker Port
    uvicorn.run(app, host="0.0.0.0", port=8001)