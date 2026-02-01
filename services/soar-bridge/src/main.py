import sys, os
# 1. ENSURE PATHS ARE SET FIRST
sys.path.append('/app/src')
sys.path.append('/app/shared')

print("[*] SYSTEM: Bootstrapping Enterprise SOAR Bridge...")

import requests, base64, datetime, pytz, yaml, re
from fastapi import FastAPI
from pydantic import BaseModel
from dotenv import load_dotenv

# 2. IMPORT ENTERPRISE SERVICES
from asset_service import AssetService
from state_manager import StateManager
from privacy_engine import PrivacyEngine

print("[*] SYSTEM: Internal Services Layer Online.")

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

# Initialize Service Logic
asset_inventory = AssetService(ASSET_DB_PATH)
memory = StateManager(STATE_FILE_PATH)
scrubber = PrivacyEngine()

# Configuration Constants
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

# --- [ 🛠️ ADF PARSER: WIKI MARKUP TO JIRA STRUCTURAL HEADERS ] ---
def format_description_to_jira_doc(report_text):
    """
    Converts AI Wiki Markup into Jira v3 Document Format.
    Corrects 'h2.' strings into blue Heading nodes in the Jira UI.
    """
    content_blocks = []
    for line in report_text.split('\n'):
        clean_line = line.strip()
        if not clean_line:
            continue

        if clean_line.startswith("h2. "):
            heading_text = clean_line.replace("h2. ", "")
            content_blocks.append({
                "type": "heading",
                "attrs": {"level": 2},
                "content": [{"type": "text", "text": heading_text}]
            })
        else:
            # Cleanup stray Markdown from AI and add as paragraph
            content_text = clean_line.replace("**", "").replace("#", "").replace("--", "").strip()
            content_blocks.append({
                "type": "paragraph",
                "content": [{"type": "text", "text": content_text}]
            })

    return {"type": "doc", "version": 1, "content": content_blocks}

# --- [ ENTERPRISE ACTION HANDLERS ] ---

def create_jira_ticket(title, description, priority="Medium", assignee_id=None):
    """Creates case in Jira using v3 REST API."""
    url = f"{os.getenv('JIRA_URL')}/rest/api/3/issue"
    user = os.getenv("JIRA_USER_EMAIL")
    token = os.getenv("JIRA_API_TOKEN")
    auth = base64.b64encode(f"{user}:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
    
    payload = {
        "fields": {
            "project": {"key": cfg['jira_settings']['project_key']},
            "summary": title, 
            "description": format_description_to_jira_doc(description), 
            "issuetype": {"name": cfg['jira_settings']['defaults']['issue_type']},
            "priority": {"name": priority}
        }
    }
    if assignee_id: 
        payload["fields"]["assignee"] = {"accountId": assignee_id}
    
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=15)
        return r.json().get("key") if r.status_code == 201 else None
    except: 
        return None

def add_jira_comment(issue_key, message):
    """Appends deduplicated alert history to an existing case."""
    url = f"{os.getenv('JIRA_URL')}/rest/api/2/issue/{issue_key}/comment"
    auth = base64.b64encode(f"{os.getenv('JIRA_USER_EMAIL')}:{os.getenv('JIRA_API_TOKEN')}".encode()).decode()
    try:
        requests.post(url, json={"body": message}, headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"}, timeout=5)
    except: pass

def transition_to_archive(issue_key):
    """Moves benign tickets to ARCHIVED column."""
    url = f"{os.getenv('JIRA_URL')}/rest/api/2/issue/{issue_key}/transitions"
    auth = base64.b64encode(f"{os.getenv('JIRA_USER_EMAIL')}:{os.getenv('JIRA_API_TOKEN')}".encode()).decode()
    try:
        requests.post(url, json={"transition": {"id": JIRA_ARCHIVE_ID}}, headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"}, timeout=5)
    except: pass

def send_slack_alert(verdict_report, hostname, priority, ticket_key):
    """
    OpSec-focused Minimalist Slack Notification.
    Ensures confidentiality on mobile by directing forensics to Jira.
    """
    if not SLACK_WEBHOOK: return

    # Extract raw decision for clear visibility
    decision = verdict_report.split('\n')[0].replace("[DECISION] | ", "").replace("#", "").strip()

    try:
        requests.post(SLACK_WEBHOOK, json={
            "text": (
                f"🚨 *SOC ESCALATION*: {priority}\n"
                f"*Host:* {hostname} | *Decision:* {decision}\n"
                f"*Ticket:* <{os.getenv('JIRA_URL')}/browse/{ticket_key}|{ticket_key}>\n"
                f"*OpSec Notice:* Detail secured in Jira. Click link for full AI analysis."
            )
        }, timeout=5)
    except: pass

# --- [ CORE SOAR PIPELINE ] ---

@app.post("/alert")
async def process_pipeline(incident: Incident):
    print(f"\n[*] INGESTING ALERT: {incident.ip_address} | {incident.hostname}")

    # 1. DEDUPLICATION (State)
    existing_ticket, hit_count = memory.check_duplicate(incident.ip_address)
    if existing_ticket:
        msg = f"⚠️ RECURRING ACTIVITY detected ({hit_count + 1} hits). Cmd: `{incident.command}`"
        add_jira_comment(existing_ticket, msg)
        memory.update_incident(incident.ip_address, existing_ticket)
        return {"status": "Deduplicated", "ticket": existing_ticket}

    # 2. ENRICHMENT & COMPLIANCE
    context = asset_inventory.get_context(incident.ip_address)
    safe_command = scrubber.redact_log(incident.command)

    # 3. TEAM SWARM REASONING
    try:
        ai_req = requests.post(AI_ENDPOINT, json={
            "hostname": incident.hostname, "ip_address": incident.ip_address,
            "command": safe_command, "criticality": context['criticality'],
            "is_business_hours": context['is_business_hours']
        }, timeout=60)
        
        verdict_report = ai_req.json().get("verdict_report", "Manual Review Required.")

        # --- ROBUST KEYWORD DETECTION ---
        # Search the top block of text to determine automation logic
        search_zone = verdict_report[:250].upper()
        is_malicious = "MALICIOUS" in search_zone
        is_fp = "AUTHORIZED" in search_zone

        # 4. ORCHESTRATED ACTIONS
        if is_malicious:
            priority = "Highest" if context['criticality'] == 'CRITICAL' else "High"
            label = "TP ALERT"
            assignee = ANALYST_ID
        elif is_fp:
            priority = "Lowest"
            label = "AUTO-RESOLVED" # Matches Jira Automation Rule
            assignee = None
        else:
            priority = "Medium"
            label = "INVESTIGATE"
            assignee = ANALYST_ID

        # Active Containment
        if is_malicious:
            print(f"[🛡️] ACTION: Containment triggered for {incident.ip_address}")
            requests.post(AGENT_ENDPOINT, json={"ip": incident.ip_address}, timeout=5)

        # Jira Synchronization
        jira_key = create_jira_ticket(
            title=f"[{label}] {incident.hostname}",
            description=f"AI ANALYSIS LOGGED AT {datetime.datetime.now()}\n\n{verdict_report}",
            priority=priority,
            assignee_id=assignee
        )

        if jira_key:
            memory.update_incident(incident.ip_address, jira_key)
            if is_fp:
                # Trigger primary API transition and Secondary Fail-safe label
                transition_to_archive(jira_key)
            else:
                # Mobile-safe ChatOps alert
                send_slack_alert(verdict_report, incident.hostname, priority, jira_key)
                
            print(f"[✅] FLOW COMPLETE: Ticket {jira_key} ({label})")
            return {"status": "Complete", "ticket": jira_key}

    except Exception as e:
        print(f"[!] Pipeline Error: {e}")
        return {"status": "Error"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)