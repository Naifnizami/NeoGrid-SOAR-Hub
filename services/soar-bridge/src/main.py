import os
import requests
import base64
import datetime
import json
import pytz
import pandas as pd
import yaml
from fastapi import FastAPI
from pydantic import BaseModel
from dotenv import load_dotenv

# 1. SETUP
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(CURRENT_DIR)))
load_dotenv(dotenv_path=os.path.join(ROOT_DIR, ".env")) 

CONFIG_PATH = "/app/config/soar_config.yaml"
ASSET_DB_PATH = "/app/shared/asset_inventory.csv"
STATE_FILE_PATH = "/app/shared/incident_state.json"

def load_soar_config():
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)

cfg = load_soar_config()
app = FastAPI(title=f"{cfg['system']['org_name']} SOAR Bridge")

JIRA_ARCHIVE_ID = cfg['jira_settings']['transitions']['archive_id']
ANALYST_ACCOUNT_ID = os.getenv("JIRA_ANALYST_ID")
AI_ENDPOINT = cfg['network']['ai_analyst_endpoint']
AGENT_ENDPOINT = cfg['network']['agent_endpoint']
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")

class Incident(BaseModel):
    hostname: str
    ip_address: str
    command: str
    severity: str = "Low"

# --- STATE/MEMORY ---
def load_state():
    if os.path.exists(STATE_FILE_PATH):
        try:
            with open(STATE_FILE_PATH, 'r') as f:
                return json.load(f)
        except: return {}
    return {}

def save_state(state):
    with open(STATE_FILE_PATH, 'w') as f:
        json.dump(state, f)

def check_history(ip):
    """Returns: is_known (bool), hit_count (int), last_ticket (str)"""
    state = load_state()
    if ip in state:
        return True, state[ip]['count'], state[ip]['ticket']
    return False, 0, None

def update_history(ip, jira_key):
    state = load_state()
    count = state.get(ip, {}).get('count', 0)
    state[ip] = {'count': count + 1, 'ticket': jira_key, 'last_seen': str(datetime.datetime.now())}
    save_state(state)

# --- HELPERS ---
def enrich_incident_data(ip: str):
    try:
        df = pd.read_csv(ASSET_DB_PATH)
        asset = df[df['ip_address'] == ip]
        if not asset.empty:
            return {"criticality": asset.iloc[0]['criticality'], "department": asset.iloc[0]['department']}
        return {"criticality": "Standard", "department": "Unknown"}
    except: return {"criticality": "Standard", "department": "Unknown"}

def create_jira_ticket(title, description, priority="Medium", assignee_id=None):
    url = f"{os.getenv('JIRA_URL')}/rest/api/2/issue"
    user = os.getenv("JIRA_USER_EMAIL")
    token = os.getenv("JIRA_API_TOKEN")
    project = cfg['jira_settings']['project_key']
    
    auth = base64.b64encode(f"{user}:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
    
    payload = {
        "fields": {
            "project": {"key": project}, "summary": title, "description": description,
            "issuetype": {"name": cfg['jira_settings']['defaults']['issue_type']},
            "priority": {"name": priority}
        }
    }
    if assignee_id:
        payload["fields"]["assignee"] = {"accountId": assignee_id}
    
    try:
        r = requests.post(url, json=payload, headers=headers)
        return r.json().get("key") if r.status_code == 201 else None
    except: return None

def add_jira_comment(issue_key, message):
    url = f"{os.getenv('JIRA_URL')}/rest/api/2/issue/{issue_key}/comment"
    user = os.getenv("JIRA_USER_EMAIL")
    token = os.getenv("JIRA_API_TOKEN")
    auth = base64.b64encode(f"{user}:{token}".encode()).decode()
    requests.post(url, json={"body": message}, headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"})

def transition_to_archive(issue_key):
    url = f"{os.getenv('JIRA_URL')}/rest/api/2/issue/{issue_key}/transitions"
    user = os.getenv("JIRA_USER_EMAIL")
    token = os.getenv("JIRA_API_TOKEN")
    auth = base64.b64encode(f"{user}:{token}".encode()).decode()
    requests.post(url, json={"transition": {"id": JIRA_ARCHIVE_ID}}, headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"})

def send_slack_alert(verdict, hostname, priority, ticket_key):
    if not SLACK_WEBHOOK: return
    color = "#FF0000" if "High" in priority else "#FFCC00"
    emoji = "🚨" if "High" in priority else "⚠️"
    try:
        requests.post(SLACK_WEBHOOK, json={
            "text": f"{emoji} SOC ALERT: {priority} Priority\n*Asset:* {hostname}\n*Ticket:* {ticket_key}\n*Verdict:* {verdict.splitlines()[0]}"
        }, timeout=2)
    except: pass

def trigger_active_containment(target_ip):
    try:
        requests.post(AGENT_ENDPOINT, json={"ip": target_ip}, timeout=5)
        print(f"[⚔️] ACTIVE DEFENSE: Sent Block to {target_ip}")
    except: pass

# --- MAIN LOGIC ---
@app.post("/alert")
async def receive_alert(incident: Incident):
    uae_now = datetime.datetime.now(pytz.timezone(cfg['system']['operating_timezone'])).strftime('%Y-%m-%d %H:%M:%S GST')
    print(f"\n--- INGESTING FROM {incident.ip_address} ---")

    is_known, hit_count, existing_ticket = check_history(incident.ip_address)
    enrichment = enrich_incident_data(incident.ip_address)

    # Call AI
    try:
        print(f"[*] Consulting AI Analyst...")
        ai_req = requests.post(AI_ENDPOINT, json={
            "hostname": incident.hostname, "ip_address": incident.ip_address,
            "command": incident.command, "criticality": enrichment['criticality']
        }, timeout=45)
        
        verdict = ai_req.json().get("verdict_report", "Unknown")
        decision_header = "\n".join(verdict.splitlines()[:2]).upper()
        
        # Categorize
        is_malicious = "MALICIOUS" in decision_header
        is_suspicious = "SUSPICIOUS" in decision_header # <-- Added this Variable
        is_fp = "AUTHORIZED" in decision_header
        
        # --- FIXED DEDUPLICATION LOGIC ---
        # If Malicious OR Suspicious, AND we know them -> Update Comment
        if (is_malicious or is_suspicious) and is_known and existing_ticket:
            print(f"[!] REPEAT OFFENDER ({hit_count+1}). Updating {existing_ticket}...")
            msg = f"⚠️ **RECURRING EVENT**: {incident.hostname} targeted again at {uae_now}.\nCmd: `{incident.command}`"
            add_jira_comment(existing_ticket, msg)
            update_history(incident.ip_address, existing_ticket)
            
            if is_malicious and enrichment['criticality'] == 'CRITICAL':
                trigger_active_containment(incident.ip_address) # Block again if critical
            
            return {"status": "Deduplicated", "ticket": existing_ticket}
        # ---------------------------------

        # If New Ticket Logic:
        priority = "Medium"
        label = "SUSPICIOUS"
        assignee = None

        if is_malicious:
            priority = "Highest" if enrichment['criticality'] == "CRITICAL" else "High"
            label = "🚨 TP ALERT"
            assignee = ANALYST_ACCOUNT_ID
            trigger_active_containment(incident.ip_address)
        elif is_fp:
            priority = "Lowest"
            label = "✅ AUTO-RESOLVED"
        else: # Suspicious
            assignee = ANALYST_ACCOUNT_ID

        # Create Ticket
        jira_key = create_jira_ticket(
            title=f"[{label}] {incident.hostname}",
            description=f"AI REPORT:\n{verdict}\n\n**CTX:** {enrichment}",
            priority=priority,
            assignee_id=assignee
        )

        if is_fp and jira_key:
            print(f"[✔] ARCHIVING {jira_key}")
            transition_to_archive(jira_key)
        elif jira_key:
            print(f"[#] NEW INCIDENT {jira_key}")
            send_slack_alert(verdict, incident.hostname, priority, jira_key)
            # IMPORTANT: Save to memory now so next time it is 'Known'
            update_history(incident.ip_address, jira_key)

        return {"status": "Complete", "ticket": jira_key}

    except Exception as e:
        print(f"[!] Error: {e}")
        return {"status": "Error"}

if __name__ == "__main__":
    import uvicorn
    print("[*] SOAR ENGINE ONLINE")
    uvicorn.run(app, host="0.0.0.0", port=8000)