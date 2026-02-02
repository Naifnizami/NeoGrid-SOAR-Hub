import sys, os
# 1. ENSURE PATHS ARE SET FIRST
sys.path.append('/app/src')
sys.path.append('/app/shared')

print("[*] SYSTEM: Bootstrapping OCSF-Native SOAR Bridge (Bug Fix Applied)...")

import requests, base64, datetime, pytz, yaml, re
from fastapi import FastAPI
from pydantic import BaseModel
from dotenv import load_dotenv

# 2. IMPORT ENTERPRISE SERVICES
from asset_service import AssetService
from state_manager import StateManager
from privacy_engine import PrivacyEngine
from normalizer import OCSFNormalizer

print("[*] SYSTEM: Internal Normalization Services Online.")

# 3. SETUP & ENVIRONMENT
load_dotenv()
CONFIG_PATH = "/app/config/soar_config.yaml"
ASSET_DB_PATH = "/app/shared/asset_inventory.csv"
STATE_FILE_PATH = "/app/shared/incident_state.json"

def load_soar_config():
    with open(CONFIG_PATH, 'r') as f: return yaml.safe_load(f)

cfg = load_soar_config()
app = FastAPI(title=f"{cfg['system']['org_name']} OCSF Orchestrator")

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
    username: str = "unknown"       
    parent_process: str = "unknown" 
    logon_type: str = "Unknown"     
    severity: str = "Low"

def format_description_to_jira_doc(report_text):
    content_blocks = []
    for line in report_text.split('\n'):
        clean_line = line.strip()
        if not clean_line: continue
        if clean_line.startswith("h2. "):
            heading_text = clean_line.replace("h2. ", "")
            content_blocks.append({"type": "heading","attrs": {"level": 2},"content": [{"type": "text", "text": heading_text}]})
        else:
            content_text = clean_line.replace("**", "").replace("#", "").replace("--", "").strip()
            content_blocks.append({"type": "paragraph","content": [{"type": "text", "text": content_text}]})
    return {"type": "doc", "version": 1, "content": content_blocks}

def create_jira_ticket(title, description, priority="Medium", assignee_id=None):
    url = f"{os.getenv('JIRA_URL')}/rest/api/3/issue"
    user = os.getenv("JIRA_USER_EMAIL")
    token = os.getenv("JIRA_API_TOKEN")
    auth = base64.b64encode(f"{user}:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
    payload = {"fields": {"project": {"key": cfg['jira_settings']['project_key']},"summary": title, "description": format_description_to_jira_doc(description), "issuetype": {"name": cfg['jira_settings']['defaults']['issue_type']},"priority": {"name": priority}}}
    if assignee_id: payload["fields"]["assignee"] = {"accountId": assignee_id}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=15)
        return r.json().get("key") if r.status_code == 201 else None
    except: return None

def add_jira_comment(issue_key, message):
    url = f"{os.getenv('JIRA_URL')}/rest/api/2/issue/{issue_key}/comment"
    auth = base64.b64encode(f"{os.getenv('JIRA_USER_EMAIL')}:{os.getenv('JIRA_API_TOKEN')}".encode()).decode()
    try: requests.post(url, json={"body": message}, headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"}, timeout=5)
    except: pass

def transition_to_archive(issue_key):
    url = f"{os.getenv('JIRA_URL')}/rest/api/2/issue/{issue_key}/transitions"
    auth = base64.b64encode(f"{os.getenv('JIRA_USER_EMAIL')}:{os.getenv('JIRA_API_TOKEN')}".encode()).decode()
    try: requests.post(url, json={"transition": {"id": JIRA_ARCHIVE_ID}}, headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"}, timeout=5)
    except: pass

def send_slack_alert(verdict_report, hostname, priority, ticket_key):
    if not SLACK_WEBHOOK: return
    # Extract Line 1 Decision securely
    decision_line = verdict_report.splitlines()[0].upper().replace("[DECISION] | ", "").strip()
    try:
        requests.post(SLACK_WEBHOOK, json={"text": (f"🚨 *SOC ESCALATION*: {priority}\n*Host:* {hostname} | *Decision:* {decision_line}\n*Ticket:* <{os.getenv('JIRA_URL')}/browse/{ticket_key}|{ticket_key}>\n*OpSec:* Forensic summary secured in Jira. Swarm analysis available.")}, timeout=5)
    except: pass

@app.post("/alert")
async def process_pipeline(incident: Incident):
    print(f"\n[*] INGESTING SIGNAL: {incident.ip_address} from {incident.hostname}")

    # 1. STATEFUL DEDUPLICATION
    existing_ticket, hit_count = memory.check_duplicate(incident.ip_address)
    if existing_ticket:
        msg = f"⚠️ RECURRING ACTIVITY detected ({hit_count + 1} hits). Cmd: `{incident.command}`"
        add_jira_comment(existing_ticket, msg)
        memory.update_incident(incident.ip_address, existing_ticket)
        return {"status": "Deduplicated", "ticket": existing_ticket}

    # 2. ENRICHMENT & PII SCRUBBING
    context = asset_inventory.get_context(incident.ip_address)
    safe_command = scrubber.redact_log(incident.command)
    normalized_ocsf = OCSFNormalizer.build_ocsf_signal({"hostname": incident.hostname,"command": safe_command,"ip_address": incident.ip_address,"username": incident.username, "parent_process": incident.parent_process, "logon_type": incident.logon_type})

    # 3. TEAM SWARM REASONING
    try:
        ai_req = requests.post(AI_ENDPOINT, json={"hostname": incident.hostname,"ip_address": incident.ip_address,"is_business_hours": context['is_business_hours'],"ocsf_data": normalized_ocsf}, timeout=60)
        verdict_report = ai_req.json().get("verdict_report", "Review Needed.")

        # --- BUG FIX: SECURE KEYWORD DETECTION ---
        # Isolate the first line to prevent misidentifying "UNAUTHORIZED" as "AUTHORIZED"
        first_line = verdict_report.splitlines()[0].upper()
        
        # We define Booleans strictly
        is_malicious = "MALICIOUS" in first_line
        # An event is an FP ONLY if AUTHORIZED is there and UNAUTHORIZED is NOT.
        is_fp = "AUTHORIZED" in first_line and "UNAUTHORIZED" not in first_line

        # 4. ORCHESTRATED ACTIONS
        if is_malicious:
            priority = "Highest" if context['criticality'] == 'CRITICAL' else "High"
            label = "TP ALERT"
            assignee = ANALYST_ID
            print(f"[🛡️] ACTION: Malicious activity confirmed. Isolating {incident.ip_address}")
            requests.post(AGENT_ENDPOINT, json={"ip": incident.ip_address}, timeout=5)
        elif is_fp:
            priority = "Lowest"
            label = "AUTO-RESOLVED"
            assignee = None # Archived cases are unassigned
        else:
            # Catch 'SUSPICIOUS', 'UNAUTHORIZED', or unknown states
            priority = "Medium"
            label = "INVESTIGATE"
            assignee = ANALYST_ID

        jira_key = create_jira_ticket(
            title=f"[{label}] {incident.hostname}",
            description=f"AI-SWARM OCSF INVESTIGATION LOGGED AT {datetime.datetime.now()}\n\n{verdict_report}",
            priority=priority,
            assignee_id=assignee
        )

        if jira_key:
            memory.update_incident(incident.ip_address, jira_key)
            if is_fp:
                transition_to_archive(jira_key)
                print(f"[✔] CLEANUP: Benchmarked benign hit archived: {jira_key}")
            else:
                send_slack_alert(verdict_report, incident.hostname, priority, jira_key)
                
            print(f"[✅] FLOW COMPLETE: Ticket {jira_key} finalized as {label}.")
            return {"status": "Complete", "ticket": jira_key}

    except Exception as e:
        print(f"[!] Pipeline Error: {e}")
        return {"status": "Error"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)