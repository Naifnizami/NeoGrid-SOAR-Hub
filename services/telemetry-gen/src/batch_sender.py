import os
import requests
import time
import random
import sys

# --- CONFIGURATION ---
# Use the "Test URL" from your n8n Webhook node screenshot.
# Note: 'nif_n8n_soar' is the container name from your docker-compose.
# If running THIS script inside a container: use http://nif_n8n_soar:5678/...
# If running THIS script from your Windows terminal: use http://localhost:5678/...
N8N_URL = os.getenv("N8N_URL", "http://localhost:5678/webhook/splunk-alert")

# --- DATA POOLS ---
KNOWN_ASSETS = [
    {"host": "dxb-sql-prod", "ip": "10.0.5.5"},
    {"host": "uae-cloud-gateway", "ip": "10.0.80.50"},
    {"host": "hr-desktop-user", "ip": "192.168.1.102"},
]

RANDOM_ASSETS = [
    {"host": "mkt-laptop-01", "ip": "192.168.5.50"},
    {"host": "dev-server-09", "ip": "172.16.0.99"}
]

BAD_CMDS = ["mimikatz.exe", "powershell -enc JABzID...", "net user /add hacker"]
GOOD_CMDS = ["curl -X POST https://api.backup.uae", "ping google.com"]
SUS_CMDS = ["whoami /priv", "netstat -an"]

def generate_payload():
    scenario = random.choice(["SAFE", "BAD", "SUS"])
    asset = random.choice(KNOWN_ASSETS + RANDOM_ASSETS)
    
    if scenario == "SAFE":
        cmd, sev = random.choice(GOOD_CMDS), "Info"
    elif scenario == "BAD":
        cmd, sev = random.choice(BAD_CMDS), "High"
    else:
        cmd, sev = random.choice(SUS_CMDS), "Medium"

    return {
        "hostname": asset['host'],
        "ip_address": asset['ip'],
        "command": cmd,
        "severity": sev,
        "scenario_type": scenario # Extra metadata for n8n logging
    }

def run_test(count):
    # If count > 20, we enter "STORM TEST" (No sleep)
    is_storm = count > 20
    
    print(f"\n[🚀] STARTING {'STORM' if is_storm else 'NORMAL'} TEST: {count} INCIDENTS")
    print(f"Targeting n8n: {N8N_URL}")
    print("-" * 50)

    for i in range(1, count + 1):
        payload = generate_payload()
        print(f"[{i}/{count}] Sending {payload['scenario_type']} from {payload['hostname']}...", end=" ", flush=True)
        
        try:
            r = requests.post(N8N_URL, json=payload, timeout=5)
            if r.status_code == 200:
                print("✅ SENT")
            else:
                print(f"❌ FAILED ({r.status_code})")
        except Exception as e:
            print(f"⚠️ ERROR: {e}")

        # If it's NOT a storm, sleep to simulate normal traffic
        if not is_storm:
            time.sleep(random.randint(2, 5))
        # In a storm, we send as fast as possible!

if __name__ == "__main__":
    total = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    run_test(total)