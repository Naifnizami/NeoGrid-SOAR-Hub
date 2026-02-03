import re
from ocsf_schemas import OCSFContainer, ProcessBlock, AuthBlock, OCSFBase

class OCSFNormalizer:
    @staticmethod
    def parse_auditd_raw(raw_str: str) -> dict:
        """Parses Linux Auditd key=value pairs into a Python dict."""
        return dict(re.findall(r'(\w+)=["\']?([^"\']*)["\']?', raw_str))

    @staticmethod
    def from_splunk(splunk_result: dict) -> dict:
        """
        Translates Real SIEM telemetry into OCSF 1.7.0 structure.
        Maps raw Auditd strings to Class 1007 (Process Activity).
        """
        raw_msg = splunk_result.get("_raw", "")
        parsed = OCSFNormalizer.parse_auditd_raw(raw_msg)
        
        # OCSF 1007 (Process)
        process_data = ProcessBlock(
            name=parsed.get("exe", "unknown-process"),
            cmd_line=raw_msg,
            integrity_level="High" if parsed.get("uid") == "0" else "Medium",
            parent_process_name=parsed.get("ppid", "Unknown")
        )

        # OCSF 3002 (Authentication context found in shell logs)
        auth_data = AuthBlock(
            user_name=parsed.get("auid", "unknown_uid"),
            logon_type="Interactive" if "sudo" in raw_msg or "bash" in raw_msg else "Network",
            mfa=False
        )

        container = OCSFContainer(
            metadata=OCSFBase(category_uid=1, class_uid=1007),
            process=process_data,
            auth=auth_data
        )
        return container.model_dump()

    @staticmethod
    def build_ocsf_signal(raw_incident: dict) -> dict:
        """Original Mock/Batch data normalizer logic."""
        cmd = raw_incident.get("command", "")
        process_data = ProcessBlock(
            name=cmd.split(' ')[0] if cmd else "unknown",
            cmd_line=cmd,
            parent_process_name=raw_incident.get("parent_process", "Unknown"),
            integrity_level="High" if "powershell" in cmd else "Medium"
        )
        auth_data = AuthBlock(
            user_name=raw_incident.get("username", "system_internal"),
            logon_type=raw_incident.get("logon_type", "Internal_RPC"),
            mfa=raw_incident.get("mfa_used", False)
        )
        container = OCSFContainer(
            metadata=OCSFBase(category_uid=1, class_uid=1007),
            process=process_data,
            auth=auth_data
        )
        return container.model_dump()