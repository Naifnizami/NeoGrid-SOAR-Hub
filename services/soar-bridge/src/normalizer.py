from ocsf_schemas import OCSFContainer, ProcessBlock, AuthBlock, NetworkBlock, OCSFBase

class OCSFNormalizer:
    @staticmethod
    def build_ocsf_signal(raw_incident: dict) -> dict:
        """
        Standardizes raw signals. Handles missing fields ('None') 
        to ensure compatibility with production Splunk telemetry.
        """
        cmd = raw_incident.get("command", "")
        
        # OCSF 1007 (Process)
        process_data = ProcessBlock(
            name=cmd.split(' ')[0] if cmd else "unknown",
            cmd_line=cmd,
            parent_process_name=raw_incident.get("parent_process", "Unknown"),
            # We determine integrity level via keyword lookup
            integrity_level="System" if "service" in raw_incident.get("username", "") else "High"
        )

        # OCSF 3002 (Authentication) - Robustly handle unknown MFA
        auth_data = AuthBlock(
            user_name=raw_incident.get("username", "system_internal"),
            logon_type=raw_incident.get("logon_type", "Internal_RPC"),
            # Defaulting to None/False if missing ensures AI stays cautious
            mfa=raw_incident.get("mfa_used", False) 
        )

        container = OCSFContainer(
            metadata=OCSFBase(category_uid=1, class_uid=1007),
            process=process_data,
            auth=auth_data
        )

        return container.model_dump()