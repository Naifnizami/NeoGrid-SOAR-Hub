from fastapi import FastAPI
import uvicorn
import datetime

app = FastAPI()

@app.post("/block")
async def block_host(data: dict):
    target_ip = data.get("ip")
    # This logs to the Telemetry Container, representing the Agent's action
    print(f"\n[!!!] AGENT COMMAND RECEIVED [!!!]")
    print(f"[🛡️] ACTIVE DEFENSE TRIGGERED: ISOLATING HOST {target_ip}")
    print(f"[✔] Firewall Rule Applied: DROP ALL TRAFFIC")
    print(f"[✔] User Session Terminated.")
    print(f"[time]: {datetime.datetime.now()}")
    
    return {"status": "SUCCESS", "action": "ISOLATION_APPLIED"}

if __name__ == "__main__":
    # We run on Port 5000 inside the Telemetry container
    print("[*] FALCON SIMULATION AGENT LISTENING ON PORT 5000...")
    uvicorn.run(app, host="0.0.0.0", port=5000)