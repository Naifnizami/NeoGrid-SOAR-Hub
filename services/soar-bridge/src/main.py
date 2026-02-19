import sys, yaml
import binascii
# Maintain paths for internal modules
sys.path.append('/app/src')
sys.path.append('/app/shared')

from fastapi import FastAPI
from pydantic import BaseModel
from dotenv import load_dotenv

from asset_service import AssetService
from privacy_engine import PrivacyEngine
from normalizer import OCSFNormalizer

print("[*] SYSTEM: NeoGrid SOAR Normalizer V4. Ready for n8n requests.")

# Load Environment and Configuration
load_dotenv()
CONFIG_PATH = "/app/config/soar_config.yaml"
ASSET_DB_PATH = "/app/shared/asset_inventory.csv"

def load_soar_config():
    with open(CONFIG_PATH, 'r') as f: 
        return yaml.safe_load(f)

app = FastAPI(title="NeoGrid SOAR Normalizer")

# Initialize shared engines
asset_inventory = AssetService(ASSET_DB_PATH)
scrubber = PrivacyEngine()

class Incident(BaseModel):
    hostname: str
    ip_address: str
    command: str
    username: str = "unknown"       
    parent_process: str = "unknown" 
    logon_type: str = "Unknown"     
    severity: str = "Low"

@app.post("/normalize")
async def normalize_event_v10(data: dict):
    # 1. Initialization (Support Flat Keys OR Nested Keys)
    # n8n sends "hostname", "command". Splunk Raw sends "result": {"host":...}
    
    # HOSTNAME STRATEGY
    hostname = data.get("hostname") # Check flat n8n key first
    if not hostname or hostname == "unknown":
        hostname = data.get("result", {}).get("host", "unknown")
    
    # IP STRATEGY
    ip_addr = data.get("ip_address")
    if not ip_addr:
         ip_addr = data.get("result", {}).get("src_ip", "127.0.0.1")

    # 2. COMMAND EXTRACTION STRATEGY
    # We want the text you see in n8n first.
    full_cmd = data.get("command") 

    # If n8n didn't send a clean command, check for the Splunk Hex/Result objects
    if not full_cmd:
        res = data.get("result", {})
        hex_cmd = res.get("cmd") # Linux Audit Hex
        
        if hex_cmd: 
            try:
                full_cmd = binascii.unhexlify(hex_cmd).decode('utf-8')
            except:
                full_cmd = res.get("COMMAND", "unknown")
        else:
            # Fallback to whatever 'raw' text exists
            full_cmd = res.get("COMMAND") or res.get("_raw", "unknown")

    print(f"[*] BRIDGE: Processing {hostname} | Command Length: {len(str(full_cmd))}")

    # 3. BUILD THE SIGNAL
    normalized_ocsf = OCSFNormalizer.build_ocsf_signal({
        "hostname": hostname,
        "command": full_cmd, 
        "ip_address": ip_addr
    })
    
    return {
        "ocsf_data": normalized_ocsf,
        "context": asset_inventory.get_context(ip_addr)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)