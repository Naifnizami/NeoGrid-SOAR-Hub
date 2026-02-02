from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class OCSFBase(BaseModel):
    version: str = "1.7.0"
    category_uid: int
    class_uid: int

# --- Class 1007: Process Activity ---
class ProcessBlock(BaseModel):
    name: str
    cmd_line: str
    integrity_level: str = "Medium"
    parent_process_name: str = "explorer.exe"

# --- Class 3002: Authentication ---
class AuthBlock(BaseModel):
    user_name: str
    logon_type: str = "Network" # e.g., Remote, Interactive, Network
    mfa: bool = False
    outcome: str = "Success"

# --- Class 4001: Network Activity ---
class NetworkBlock(BaseModel):
    src_ip: str
    dst_ip: str
    dst_port: int = 443
    direction: str = "Outbound"

class OCSFContainer(BaseModel):
    """The 'Dossier' we send to the AI Swarm."""
    metadata: OCSFBase
    process: Optional[ProcessBlock] = None
    auth: Optional[AuthBlock] = None
    network: Optional[NetworkBlock] = None