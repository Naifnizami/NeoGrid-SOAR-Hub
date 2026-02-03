from pydantic import BaseModel
from typing import Optional

class OCSFBase(BaseModel):
    version: str = "1.7.0"
    category_uid: int
    class_uid: int

class ProcessBlock(BaseModel):
    name: str
    cmd_line: str
    integrity_level: str = "Medium"
    parent_process_name: str = "explorer.exe"

class AuthBlock(BaseModel):
    user_name: str
    logon_type: str = "Network"
    mfa: bool = False
    outcome: str = "Success"

class NetworkBlock(BaseModel):
    src_ip: str
    dst_ip: str
    dst_port: int = 443
    direction: str = "Outbound"

class OCSFContainer(BaseModel):
    metadata: OCSFBase
    process: Optional[ProcessBlock] = None
    auth: Optional[AuthBlock] = None
    network: Optional[NetworkBlock] = None