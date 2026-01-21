import os
import requests
from dotenv import load_dotenv

# 1. SECRET LOADING (DOCKER WAY)
# We still call load_dotenv() without a path as a fallback.
# In Docker, os.getenv() will fetch variables injected by docker-compose.
load_dotenv()

ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_ip_reputation(ip: str):
    """Checks the global reputation of an IP address via AbuseIPDB."""
    # Safety Check: If Key is missing inside Docker, alert the logs
    if not ABUSE_API_KEY:
        return "[!] Intel Error: ABUSEIPDB_API_KEY missing from Environment."

    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': ABUSE_API_KEY}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            score = data['data']['abuseConfidenceScore']
            return f"IP {ip} Reputation Check: {score}% abuse confidence (High is Malicious)."
        return f"AbuseIPDB Lookup Failed (HTTP {response.status_code})."
    except Exception as e:
        return f"Intel connection error: {e}"

def check_file_hash(file_hash: str):
    """Queries VirusTotal to see if a file hash is malicious."""
    if not VT_API_KEY:
        return "[!] Intel Error: VIRUSTOTAL_API_KEY missing from Environment."

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return (f"VT Scan Results: {file_hash} -> "
                    f"Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}")
        return f"VirusTotal data not found for this hash (Status: {response.status_code})."
    except Exception as e:
        return f"VT API Connection Error: {e}"

def get_mitre_context(t_code: str):
    """Maps activity to the MITRE ATT&CK Framework Context."""
    mapping = {
        "T1059.001": "PowerShell: Adversaries use PowerShell for discovery and command execution.",
        "T1562.001": "Disable Tools: Adversaries modify security software (like Defender) to avoid detection.",
        "T1078": "Valid Accounts: Adversaries may abuse existing legitimate credentials for access.",
        "T1567": "Exfiltration over Web: Adversaries use web services to steal company data."
    }
    desc = mapping.get(t_code, "Known adversarial behavior pattern detected.")
    return f"MITRE Context for {t_code}: {desc}"