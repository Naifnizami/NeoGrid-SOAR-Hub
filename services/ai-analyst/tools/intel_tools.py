import os
import requests
import ipaddress 
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_ip_reputation(ip: str):
    """
    Checks IP reputation context via IP-API. 
    Standardized to skip lookups for internal (RFC 1918) and loopback addresses.
    """
    # 1. Validation Safety: Handle Null or Empty Inputs
    if not ip or str(ip).lower() in ["none", "null", "", "undefined"]:
        return "Tool Notice: IP metadata unavailable for this signal."

    # 2. RFC 1918 and Loopback Compliance (Enterprise Standard)
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return f"Context Notice: IP {ip} is an internal/loopback asset. External lookup bypassed by security policy."
    except ValueError:
        return "Tool Notice: The provided indicator is not a valid IP address."
    
    # 3. Public API Call
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return (
                    f"External Intelligence for {ip}:\n"
                    f"- Geolocation: {data.get('country')}, {data.get('city')}\n"
                    f"- ISP/ORG: {data.get('isp')}"
                )
        return "Intelligence tool: Connection success, but no public record found."
    except:
        return "Intelligence tool: External connection timed out."

def check_file_hash(file_hash: str):
    """
    Checks VirusTotal for risk forensics. 
    Standardized with a length-check guard to prevent junk API calls.
    """
    # 1. Structural Validation (Prevents API credit waste)
    clean_hash = str(file_hash).strip()
    if not clean_hash or len(clean_hash) not in [32, 40, 64]:
        return "Notice: No valid hash (MD5/SHA) provided. Integrity lookup bypassed."

    if not VT_API_KEY: 
        return "Warning: VirusTotal API Key missing from SOAR Environment."
    
    # 2. VT v3 API Call
    url = f"https://www.virustotal.com/api/v3/files/{clean_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            total = stats['malicious'] + stats['harmless'] + stats['undetected']
            return (
                f"VirusTotal Scan for {clean_hash[:8]}... : "
                f"{stats['malicious']}/{total} engines flagged as MALICIOUS."
            )
        return f"Intel: Hash {clean_hash[:8]}... was checked; no known malware record found."
    except: 
        return "Intel: VirusTotal connection error (check system network)."