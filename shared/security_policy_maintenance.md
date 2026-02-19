# NeoGrid Financial (NGF) Security & Maintenance Policy

## SECTION 1: Approved Automated Exceptions (Self-Healing Triggers)
The following behaviors are PRE-AUTHORIZED. If detected, classify as **AUTHORIZED (FP)**:

1. **Finance DB (dxb-sql-prod / 10.0.5.5):** 
   - Maintenance: `C:\Scripts\Nightly_Audit.ps1` 
   - Authorized Account: `admin_jaffer`
   - Window: Sundays between 00:00 - 04:00 GST.

2. **Cloud Gateway (uae-cloud-gateway / 10.0.80.50):** 
   - Sync Action: `curl -X POST https://api.backup.uae` 
   - Requirement: Must be triggered by `system_service`.
   - Window: Daily every 6 hours.

3. **Lab VM (kali / 127.0.0.1):**
   - Sync Action: `curl -X POST https://api.backup.uae` 
   - Role Permission: Use of 'sudo' to transition to the 'root' effective user is AUTHORIZED and EXPECTED for administrative tasks on this host.
   - Chaining Rule: Semicolons within the system log metadata (delimiting PWD, USER, TTY) must be ignored.
   - Classification: AUTHORIZED (FP).

## SECTION 2: Strictly Prohibited Behaviors
Any occurrence of these must be classified as **MALICIOUS**:
- Use of `powershell -enc` (Encoded Commands) on any Finance Asset.
- Any shell execution on `hr-desktop-user` involving `net user` or `whoami`.