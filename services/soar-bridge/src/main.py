import sys, os
sys.path.append('/app/src')
sys.path.append('/app/shared')

import requests, base64, datetime, yaml
from fastapi import FastAPI
from pydantic import BaseModel
from dotenv import load_dotenv

from asset_service import AssetService
from state_manager import StateManager
from privacy_engine import PrivacyEngine
from normalizer import OCSFNormalizer

print("[*] SYSTEM: Enterprise SOAR Bridge Online. Ready for SIEM/Sim traffic.")

load_dotenv()
CONFIG_PATH = "/app/config/soar_config.yaml"
ASSET_DB_PATH = "/app/shared/asset_inventory.csv"
STATE_FILE_PATH = "/app/shared/incident_state.json"

def load_soar_config():
    with open(CONFIG_PATH, 'r') as f: return yaml.safe_load(f)

cfg = load_soar_config()
app = FastAPI(title="NeoGrid SOAR Hub")

asset_inventory = AssetService(ASSET_DB_PATH)
memory = StateManager(STATE_FILE_PATH)
scrubber = PrivacyEngine()

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
    url = f"{os.getenv('JIRA_URL').rstrip('/')}/rest/api/3/issue"
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
    decision_line = verdict_report.splitlines()[0].upper().replace("[DECISION] | ", "").strip()
    try:
        requests.post(SLACK_WEBHOOK, json={"text": (f"🚨 *SOC ESCALATION*: {priority}\n*Host:* {hostname} | *Decision:* {decision_line}\n*Ticket:* <{os.getenv('JIRA_URL')}/browse/{ticket_key}|{ticket_key}>\n*Notice:* OpSec forensic secured in Jira. Swarm analysis available.")}, timeout=5)
    except: pass

@app.post("/splunk-alert")
async def receive_splunk_event(payload: dict):
    """Entry point for real SIEM data."""
    res = payload.get("result", {})
    ocsf_dossier = OCSFNormalizer.from_splunk(res)
    splunk_incident = Incident(
        hostname=res.get("host", "kali-vm"), ip_address="127.0.0.1",
        command=res.get("_raw")[:350], username="Root" if "uid=0" in str(res.get("_raw")) else "User"
    )
    return await process_pipeline(splunk_incident, splunk_ocsf=ocsf_dossier)

@app.post("/alert")
async def receive_sim_alert(incident: Incident):
    return await process_pipeline(incident)

async def process_pipeline(incident: Incident, splunk_ocsf=None):
    print(f"[*] SIGNAL: {incident.hostname} ({incident.ip_address})")
    
    # Normalization (Priority to real OCSF)
    context = asset_inventory.get_context(incident.ip_address)
    safe_command = scrubber.redact_log(incident.command)
    normalized_ocsf = splunk_ocsf if splunk_ocsf else OCSFNormalizer.build_ocsf_signal({
        "hostname": incident.hostname, "command": safe_command, "ip_address": incident.ip_address,
        "username": incident.username, "parent_process": incident.parent_process, "logon_type": incident.logon_type
    })

    # Deduplication
    proc_name = normalized_ocsf['process']['name']
    existing_ticket, hit_count = memory.check_duplicate(incident.ip_address, proc_name)
    if existing_ticket:
        msg = f"⚠️ RECURRING ACTIVITY ({hit_count + 1} hits): `{proc_name}`."
        add_jira_comment(existing_ticket, msg)
        memory.update_incident(incident.ip_address, existing_ticket, proc_name)
        return {"status": "Deduplicated", "ticket": existing_ticket}

    # AI Reasoning
    try:
        ai_req = requests.post(AI_ENDPOINT, json={"hostname": incident.hostname,"is_business_hours": context['is_business_hours'],"ip_address": incident.ip_address,"ocsf_data": normalized_ocsf}, timeout=60)
        verdict_report = ai_req.json().get("verdict_report", "Forensic Data Incomplete.")
        decision_line = verdict_report.splitlines()[0].upper()
        
        is_malicious = "[DECISION] | MALICIOUS" in decision_line
        is_fp = "[DECISION] | AUTHORIZED" in decision_line

        priority = "Highest" if is_malicious and context['criticality'] == 'CRITICAL' else ("Lowest" if is_fp else "High")
        label = "TP ALERT" if is_malicious else ("AUTO-RESOLVED" if is_fp else "INVESTIGATE")
        assignee = ANALYST_ID if label != "AUTO-RESOLVED" else None

        if is_malicious: requests.post(AGENT_ENDPOINT, json={"ip": incident.ip_address}, timeout=5)

        jira_key = create_jira_ticket(title=f"[{label}] {incident.hostname}", description=f"AI ANALYSIS LOGGED AT {datetime.datetime.now()}\n\n{verdict_report}", priority=priority, assignee_id=assignee)

        if jira_key:
            memory.update_incident(incident.ip_address, jira_key, proc_name)
            if is_fp: transition_to_archive(jira_key)
            else: send_slack_alert(verdict_report, incident.hostname, priority, jira_key)
            return {"status": "Complete", "ticket": jira_key}
    except Exception as e: return {"status": "Error", "message": str(e)}

# --- 🔌 n8n UTILITY ROUTE ---
@app.post("/normalize")
async def normalize_event_for_n8n(incident: Incident):
    """
    Dedicated endpoint for n8n to request OCSF 1.7.0 normalization
    without triggering the full internal bridge orchestration.
    """
    print(f"[*] NORMALIZER: Serving OCSF translation for n8n flow ({incident.ip_address})")
    
    # 1. Enrichment
    context = asset_inventory.get_context(incident.ip_address)
    
    # 2. Privacy & Normalization
    safe_command = scrubber.redact_log(incident.command)
    
    normalized_ocsf = OCSFNormalizer.build_ocsf_signal({
        "hostname": incident.hostname,
        "command": safe_command,
        "ip_address": incident.ip_address,
        "username": incident.username,
        "parent_process": incident.parent_process,
        "logon_type": incident.logon_type
    })
    
    # Return the clean OCSF object + enriched context for n8n
    return {
        "ocsf_data": normalized_ocsf,
        "context": context
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)