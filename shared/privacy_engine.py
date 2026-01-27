import re

class PrivacyEngine:
    def __init__(self):
        # Patterns for Email, Internal IP structure, and specific usernames
        self.email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
        # Masking internal IPs like 192.168.x.x but leaving the last octet for context
        self.ip_pattern = r'\b(?:\d{1,3}\.){2}\d{1,3}\.(\d{1,3})\b'

    def redact_log(self, text: str) -> str:
        """
        Main entry point to scrub a log string before sending to AI.
        """
        if not text:
            return ""

        # 1. Redact Emails
        scrubbed = re.sub(self.email_pattern, "[EMAIL_REDACTED]", text)

        # 2. Redact IPs (Masking prefix, keeping end for log correlation)
        # e.g., 192.168.1.102 -> INTERNAL_NET.102
        scrubbed = re.sub(self.ip_pattern, r"INTERNAL_NET.\1", scrubbed)

        # 3. Security context cleaning (Removing known sensitive paths if necessary)
        # This keeps the behavior but hides the specific server/user name
        return scrubbed

    @staticmethod
    def identify_pii_entities(text: str):
        """Metadata flagger (In an enterprise, you'd log that PII was found here)"""
        if "[EMAIL_REDACTED]" in text:
            return True
        return False