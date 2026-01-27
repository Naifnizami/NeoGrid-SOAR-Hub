import sys, os
# 1. ENSURE PATHS ARE SET FIRST (Required for Shared Volume access)
sys.path.append('/app/src')
sys.path.append('/app/shared')

print("[*] SYSTEM: Bootstrapping SOAR Bridge Orchestrator...")

import requests, base64, datetime, pytz, yaml, re
from fastapi import FastAPI
from pydantic import BaseModel
from dotenv import load_dotenv

# 2. IMPORT ENTERPRISE SERVICES
from asset_service import AssetService
from state_manager import StateManager
from privacy_engine import PrivacyEngine

print("[*] SYSTEM: Asset, State, and Privacy modules loaded.")

# 3. SETUP & ENVIRONMENT
load_dotenv()
CONFIG_PATH = "/app/config/soar_config.yaml"
ASSET_DB_PATH = "/app/shared/asset_inventory.csv"
STATE_FILE_PATH = "/app/shared/incident_state.json"

def load_soar_config():
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)

cfg = load_soar_config()
app = FastAPI(title=f"{cfg['system']['org_name']} Orchestrator")

# Initialize Global Instances
asset_inventory = AssetService(ASSET_DB_PATH)
memory = StateManager(STATE_FILE_PATH)
scrubber = PrivacyEngine()

# API Configuration Constants
AI_ENDPOINT = cfg['network']['ai_analyst_endpoint']
AGENT_ENDPOINT = cfg['network']['agent_endpoint']
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")
ANALYST_ID = os.getenv("JIRA_ANALYST_ID")
JIRA_ARCHIVE_ID = cfg['jira_settings']['transitions']['archive_id']

class Incident(BaseModel):
    hostname: str
    ip_address: str
    command: str
    severity: str = "Low"

# --- [ ULTIMATE JIRA DOCUMENT FORMATTER (ADF) ] ---
def format_description_to_jira_doc(report_text):
    """
    Converts a Markdown-style string into Jira's structured JSON Document format (ADF).
    This uses a basic paragraph structure to maximize acceptance by the v3 API.
    """
    content_blocks = []
    # Split by newlines and create a paragraph block for each non-empty line
    for line in report_text.split('\n'):
        if line.strip():
            content_blocks.append({"type": "paragraph", "content": [{"type": "text", "text": line}]})

    return {
        "type": "doc",
        "version": 1,
        "content": content_blocks
    }

# --- [ ENTERPRISE ACTION HANDLERS ] ---

def create_jira_ticket(title, description, priority="Medium", assignee_id=None):
    """Creates a full investigative case in Jira (using v3 API with rich ADF description)."""
    url = f"{os.getenv('JIRA_URL')}/rest/api/3/issue" # <-- v3 Endpoint
    user = os.getenv("JIRA_USER_EMAIL")
    token = os.getenv("JIRA_API_TOKEN")
    auth = base64.b64encode(f"{user}:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
    
    # Use the Jira Document Format for the description
    description_doc = format_description_to_jira_doc(description)
    
    payload = {
        "fields": {
            "project": {"key": cfg['jira_settings']['project_key']},
            "summary": title, 
            "description": description_doc, 
            "issuetype": {"name": cfg['jira_settings']['defaults']['issue_type']},
            "priority": {"name": priority}
        }
    }
    if assignee_id: 
        payload["fields"]["assignee"] = {"accountId": assignee_id}
    
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        
        if r.status_code == 201:
            return r.json().get("key")
        else:
            print(f"[🚨] JIRA API FAILED: Status {r.status_code}")
            print(f"[🚨] JIRA REASON: {r.text}")
            return None
            
    except Exception as e: 
        print(f"[🚨] JIRA CONNECTION ERROR: {e}")
        return None

def add_jira_comment(issue_key, message):
    """Adds evidence/comments to an existing investigation for auditing."""
    url = f"{os.getenv('JIRA_URL')}/rest/api/2/issue/{issue_key}/comment"
    auth = base64.b64encode(f"{os.getenv('JIRA_USER_EMAIL')}:{os.getenv('JIRA_API_TOKEN')}".encode()).decode()
    try:
        requests.post(url, json={"body": message}, headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"}, timeout=5)
    except: 
        pass

def transition_to_archive(issue_key):
    """Moves False Positive tickets to the ARCHIVED column."""
    url = f"{os.getenv('JIRA_URL')}/rest/api/2/issue/{issue_key}/transitions"
    auth = base64.b64encode(f"{os.getenv('JIRA_USER_EMAIL')}:{os.getenv('JIRA_API_TOKEN')}".encode()).decode()
    try:
        requests.post(url, json={"transition": {"id": JIRA_ARCHIVE_ID}}, headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"}, timeout=5)
    except: 
        pass

def send_slack_alert(verdict, hostname, priority, ticket_key):
    """
    Triggers high-priority ChatOps alerts for real-time response.
    The preview is intelligently extracted from the TECHNICAL ANALYSIS section (500 char limit).
    """
    if not SLACK_WEBHOOK: return

    # --- INTELLIGENT PREVIEW EXTRACTION ---
    preview = "Full report available in Jira." # Default fallback
    try:
        # Find the start of the Technical Analysis section
        start_tag = '## TECHNICAL ANALYSIS'
        # Find the start of the next major section (or end of string)
        end_tag = '## CONTEXT AUDIT'
        
        start_index = verdict.index(start_tag) + len(start_tag)
        
        try:
            end_index = verdict.index(end_tag, start_index)
        except ValueError:
            # If CONTEXT AUDIT is not found, use the end of the string
            end_index = len(verdict)
            
        # Extract the relevant text, strip whitespace, and safely limit to 500 chars
        preview_text = verdict[start_index:end_index].strip()
        
        # Replace newlines with spaces for a cleaner Slack message
        preview = preview_text.replace('\n', ' ')[:500] 
        
    except ValueError:
        # Fallback if the expected headers are not found
        preview = verdict.replace('\n', ' ')[:500] 
    
    # --- SLACK API CALL ---
    try:
        requests.post(SLACK_WEBHOOK, json={
            "text": (
                f"🚨 *SOC ESCALATION*: {priority}\n"
                f"*Host:* {hostname} | *Ticket:* <{os.getenv('JIRA_URL')}/browse/{ticket_key}|{ticket_key}>\n"
                f"*Technical Summary:* {preview}"
            )
        }, timeout=2)
    except Exception as e: 
        print(f"[!] Slack Alert Failed: {e}")

# --- [ CORE SOAR LOGIC ] ---

@app.post("/alert")
async def process_pipeline(incident: Incident):
    print(f"\n[*] INGESTING ALERT: {incident.ip_address} | {incident.hostname}")

    # STEP 1: STATEFUL DEDUPLICATION (Memory check)
    existing_ticket, hit_count = memory.check_duplicate(incident.ip_address)
    if existing_ticket:
        print(f"[!] DEDUPLICATING: Repeat activity on ticket {existing_ticket}")
        memory.update_incident(incident.ip_address, existing_ticket)
        
        recurring_msg = (
            f"⚠️ **RECURRING ACTIVITY LOGGED**\n"
            f"Observed Host: `{incident.hostname}`\n"
            f"Observed Command: `{incident.command}`\n"
            f"Incident Hit Count: {hit_count + 1}"
        )
        add_jira_comment(existing_ticket, recurring_msg)
        return {"status": "Deduplicated", "ticket": existing_ticket}

    # STEP 2: CONTEXT ENRICHMENT (Business Policy & Hours)
    context = asset_inventory.get_context(incident.ip_address)
    
    # STEP 3: PRIVACY SHIELD (Data scrubbing)
    safe_command = scrubber.redact_log(incident.command)

    # STEP 4: COGNITIVE TRIAGE (Llama-3 analysis)
    try:
        ai_payload = {
            "hostname": incident.hostname,
            "ip_address": incident.ip_address,
            "command": safe_command,
            "criticality": context['criticality'],
            "is_business_hours": context['is_business_hours']
        }
        
        print("[*] AI ANALYST: Submitting behavioral report for reasoning...")
        ai_req = requests.post(AI_ENDPOINT, json=ai_payload, timeout=50)
        verdict_report = ai_req.json().get("verdict_report", "Forensic Investigation Error. Manual Review Required.")

        # Behavioral Classification
        is_malicious = "[DECISION] | MALICIOUS" in verdict_report.upper()
        is_fp = "[DECISION] | AUTHORIZED" in verdict_report.upper()

        # STEP 5: REMEDIATION & NOTIFICATION
        priority = "Highest" if (is_malicious and context['criticality'] == 'CRITICAL') else "Medium"
        if is_fp: priority = "Lowest"
        
        label = "TP ALERT" if is_malicious else ("AUTO-RESOLVED" if is_fp else "INVESTIGATE")
        assignee = ANALYST_ID if (is_malicious or not is_fp) else None

        # Autonomous Active Defense: Block host if malicious
        if is_malicious:
            print(f"[🛡️] ACTION: Malicious activity confirmed. Isolating {incident.ip_address}")
            requests.post(AGENT_ENDPOINT, json={"ip": incident.ip_address}, timeout=5)

        # Jira Creation - Final Description Construction
        description_final = (
            f"REPORT GENERATED: {datetime.datetime.now()}\n\n"
            f"{verdict_report}\n\n"
            f"--- Context ---\n"
            f"ASSET OWNER: {context['owner']}\n"
            f"BUSINESS HOURS: {context['is_business_hours']}"
        )

        jira_key = create_jira_ticket(
            title=f"[{label}] {incident.hostname}",
            description=description_final,
            priority=priority,
            assignee_id=assignee
        )

        if jira_key:
            memory.update_incident(incident.ip_address, jira_key)
            
            # --- FINAL LIFECYCLE MANAGEMENT ---
            if is_fp:
                transition_to_archive(jira_key)
            else:
                send_slack_alert(verdict_report, incident.hostname, priority, jira_key)
                
            print(f"[✅] FLOW COMPLETE: Ticket {jira_key} synchronized.")
            return {"status": "Complete", "ticket": jira_key}

    except Exception as e:
        print(f"[!] Pipeline Error: {e}")
        return {"status": "Error"}

if __name__ == "__main__":
    import uvicorn
    print("[*] SYSTEM: Starting FastAPI Orchestrator on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)