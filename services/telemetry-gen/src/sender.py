import os
import json
import requests
import uuid
import sys

# Standard internal Docker networking
BRIDGE_URL = os.getenv("BRIDGE_URL", "http://soar-bridge:8000/alert")
# Path inside the Docker container where data is mounted
DATA_FILE = "/app/data/attack_scenarios.json"

def fire_simulation(case_id):
    """
    Orchestrates the breach simulation by reading logic from the JSON arsenal.
    """
    # Check if we are running in Docker or Local Windows for file path
    path = DATA_FILE if os.path.exists(DATA_FILE) else "../data/attack_scenarios.json"

    try:
        with open(path, 'r') as f:
            scenarios = json.load(f)

        if case_id not in scenarios:
            print(f"[!] Case {case_id} not found. Please choose 1, 2, or 3.")
            return

        # Prepare the payload
        payload = scenarios[case_id]
        payload["event_id"] = str(uuid.uuid4())

        print(f"\n[🔥] FIRING SIMULATION CASE {case_id}: {payload['description']}")
        
        # INCREASED TIMEOUT: 60 seconds allows AI to think and Jira to post
        r = requests.post(BRIDGE_URL, json=payload, timeout=60)
        
        if r.status_code == 200:
            result = r.json()
            print(f"[✅] SOC PIPELINE SUCCESS")
            print(f"[+] Final Jira Status: {result.get('status')}")
            print(f"[+] Incident Tracking ID: {result.get('ticket')}")
        else:
            print(f"[🚨] SOAR BRIDGE REJECTED LOG: Status {r.status_code}")

    except Exception as e:
        print(f"[!] Simulation Delivery Failure: {e}")

if __name__ == "__main__":
    # Check if user provided a number (python sender.py 1)
    # Default to '2' (The authorized case) if no number provided
    demo_case = sys.argv[1] if len(sys.argv) > 1 else "2"
    fire_simulation(demo_case)