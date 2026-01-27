import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()
# Keep this one, as VirusTotal requires it.
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_ip_reputation(ip: str):
    """
    Checks IP Geolocation and basic risk context via IP-API (No API Key Required).
    """
    # NO KEY NEEDED - reliable free service for demo context
    url = f"http://ip-api.com/json/{ip}"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            
            if data.get('status') == 'success':
                report = (
                    f"External IP Context: **{ip}**\n"
                    f"- **Country:** {data.get('country')}\n"
                    f"- **City/Region:** {data.get('city')}, {data.get('regionName')}\n"
                    f"- **ISP/ORG:** {data.get('isp')}\n"
                )
                # The AI can use this context for behavioral analysis (e.g., login from a new country)
                return report
            
            return f"IP Context lookup failed: {data.get('message', 'Unknown Error')}"

        return "External Intelligence connection failed (Status: 500/400 from vendor)."
    except requests.exceptions.Timeout:
        return "External Intelligence connection timed out."
    except Exception:
        return "Intelligence connection error (Check DNS/Network)."

def check_file_hash(file_hash: str):
    """Checks VirusTotal for file risk analytics (API Key Required)."""
    if not VT_API_KEY: 
        return "VirusTotal API Key missing. Skipping hash check."
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return f"VirusTotal Scan: Found {stats['malicious']} engines flagging this as malicious."
        return "No VirusTotal data found for this hash."
    except Exception as e: 
        return f"VT API connection error: {str(e)}"

# Path points to the shared volume mount inside the Docker container
MITRE_DB_PATH = "/app/shared/mitre_db.json"

def get_mitre_context(t_code: str):
    """Maps T-Codes to the Enterprise MITRE DB JSON for investigation context."""
    try:
        with open(MITRE_DB_PATH, 'r') as f:
            mitre_data = json.load(f)
        
        code = t_code.strip().upper()
        
        if code in mitre_data:
            info = mitre_data[code]
            return (
                f"MITRE ATT&CK Info found: {info['technique']} | "
                f"Tactic: {info['tactic']} | "
                f"Description: {info['description']} | "
                f"Baseline Severity: {info['severity']}"
            )
        
        return f"MITRE context not found for code: {code}. Missing from local intelligence."
    
    except Exception:
        return "Internal Error retrieving MITRE context. Check mitre_db.json file integrity."