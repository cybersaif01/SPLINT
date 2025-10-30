# rules_windows.py
import re

# This is a set of detection rules for Windows Event Logs and common suspicious activity
# Mapped to MITRE ATT&CK framework IDs

rules_windows = [
    # =====================================================================
    # 1. AUTHENTICATION & ACCESS
    # =====================================================================
    {
        "name": "Windows - Successful Login",
        "severity": "low",
        "mitre_id": "T1078",
        "pattern": re.compile(r"An account was successfully logged on", re.IGNORECASE),
        "description": "A user successfully logged in to the system."
    },
    {
        "name": "Windows - Failed Login",
        "severity": "medium",
        "mitre_id": "T1110",
        "pattern": re.compile(r"An account failed to log on", re.IGNORECASE),
        "description": "A failed login attempt occurred on the system."
    },
    {
        "name": "Windows - Account Locked Out",
        "severity": "medium",
        "mitre_id": "T1078",
        "pattern": re.compile(r"Account Locked Out", re.IGNORECASE),
        "description": "A user account was locked out after multiple failed logins."
    },

    # =====================================================================
    # 2. PRIVILEGE ESCALATION
    # =====================================================================
    {
        "name": "User Added to Administrators Group",
        "severity": "high",
        "mitre_id": "T1098",
        "pattern": re.compile(r"Added member to group 'Administrators'", re.IGNORECASE),
        "description": "A user was added to a privileged group (Administrators)."
    },
    {
        "name": "New User Account Created",
        "severity": "medium",
        "mitre_id": "T1136.001",
        "pattern": re.compile(r"User Account Created", re.IGNORECASE),
        "description": "A new local user account was created."
    },

    # =====================================================================
    # 3. PROCESS & EXECUTION
    # =====================================================================
    {
        "name": "Suspicious PowerShell Execution",
        "severity": "high",
        "mitre_id": "T1059.001",
        "pattern": re.compile(r"powershell.*-enc", re.IGNORECASE),
        "description": "PowerShell executed with encoded commands, a common attack technique."
    },
    {
        "name": "Suspicious CMD Execution",
        "severity": "high",
        "mitre_id": "T1059.003",
        "pattern": re.compile(r"cmd\.exe /c", re.IGNORECASE),
        "description": "A potentially suspicious command prompt execution."
    },

    # =====================================================================
    # 4. DEFENSE EVASION
    # =====================================================================
    {
        "name": "Windows Firewall Disabled",
        "severity": "high",
        "mitre_id": "T1562.004",
        "pattern": re.compile(r"Windows Firewall Service stopped", re.IGNORECASE),
        "description": "The Windows Firewall service was disabled or stopped."
    },
    {
        "name": "Security Logging Disabled",
        "severity": "high",
        "mitre_id": "T1070.004",
        "pattern": re.compile(r"Audit Policy Change", re.IGNORECASE),
        "description": "Security auditing or logging has been changed, possibly to evade detection."
    },

    # =====================================================================
    # 5. FILE & SYSTEM MONITORING
    # =====================================================================
    {
        "name": "Suspicious File Deleted",
        "severity": "medium",
        "mitre_id": "T1070.004",
        "pattern": re.compile(r"File deletion detected", re.IGNORECASE),
        "description": "A critical or monitored file was deleted."
    },
    {
        "name": "Suspicious File Created",
        "severity": "high",
        "mitre_id": "T1036",
        "pattern": re.compile(r"Executable file created", re.IGNORECASE),
        "description": "A new executable file was created, possibly malware or a script dropper."
    },

    # =====================================================================
    # 6. NETWORK EVENTS
    # =====================================================================
    {
        "name": "Remote Desktop Login",
        "severity": "medium",
        "mitre_id": "T1076",
        "pattern": re.compile(r"Remote Desktop Services: User authentication succeeded", re.IGNORECASE),
        "description": "A user successfully logged in via RDP."
    },
    {
        "name": "Failed RDP Login Attempt",
        "severity": "medium",
        "mitre_id": "T1110",
        "pattern": re.compile(r"Remote Desktop Services: User authentication failed", re.IGNORECASE),
        "description": "A failed RDP login attempt occurred."
    }
]
