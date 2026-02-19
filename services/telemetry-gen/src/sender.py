import os
import json
import requests
import uuid
import sys
from requests.exceptions import JSONDecodeError

# --- POINT TO N8N WEBHOOK ---
# Use the "Test URL" from your n8n Ingress node screenshot
N8N_URL = os.getenv("N8N_URL", "http://localhost:5678/webhook-test/splunk-alert")

# Relative path fixing for local Windows vs Docker container
DATA_FILE_PATHS = [
    "/app/data/attack_scenarios.json",                  # Docker path
    "../data/attack_scenarios.json",                   # Relative src path
    "./services/telemetry-gen/data/attack_scenarios.json" # Project root path
]

def fire_simulation(case_id):
    """
    Sends a specific Case ID from attack_scenarios.json into the n8n pipeline.
    """
    # 1. Locate the attack_scenarios.json file
    json_path = None
    for path in DATA_FILE_PATHS:
        if os.path.exists(path):
            json_path = path
            break

    if not json_path:
        print("[!] ERROR: attack_scenarios.json not found. Check file paths.")
        return

    try:
        with open(json_path, 'r') as f:
            scenarios = json.load(f)

        if case_id not in scenarios:
            print(f"[!] Case {case_id} not found in {json_path}. Try 1, 2, or 3.")
            return

        # 2. Prepare the payload (Keeping it OCSF-friendly)
        payload = scenarios[case_id]
        payload["event_id"] = str(uuid.uuid4())
        
        # We add 'result' wrapper so n8n "Clean Splunk" node finds the data easily
        # If your n8n workflow expects a simple body, keep it flat. 
        # Here we send it exactly as n8n usually receives Splunk logs.
        splunk_style_payload = {
            "result": payload,
            "hostname": payload.get("hostname"), # redundacy for easier mapping
            "command": payload.get("command")    # redundancy for easier mapping
        }

        print(f"\n[🔥] FIRING SIMULATION CASE {case_id}: {payload.get('description', 'Manual Attack')}")
        print(f"[>] Sending to n8n: {N8N_URL}")
        
        # 3. Fire request to n8n
        r = requests.post(N8N_URL, json=splunk_style_payload, timeout=60)
        
        if r.status_code == 200:
            print(f"[✅] n8n PIPELINE TRIGGERED SUCCESSFULLY")
            
            try:
                # n8n will return either the node data or {"status":"success"}
                result = r.json()
                print(f"[+] Server Response: {json.dumps(result, indent=2)}")
            except JSONDecodeError:
                print(f"[+] Pipeline started (no response body received).")
        else:
            print(f"[🚨] n8n REJECTED DATA: Status {r.status_code}")
            print(f"Message: {r.text}")

    except Exception as e:
        print(f"[!] Simulation Delivery Failure: {e}")

if __name__ == "__main__":
    # Usage: python sender.py 1
    # Cases typically: 1 (Attack), 2 (Maintenance/Safe), 3 (Data Theft)
    demo_case = sys.argv[1] if len(sys.argv) > 1 else "1"
    fire_simulation(demo_case)