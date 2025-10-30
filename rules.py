import re

# This is a comprehensive set of rules for detecting suspicious activity.
# They are mapped to the MITRE ATT&CK framework for context.

rules = [
    # =====================================================================
    # 1. AUTHENTICATION & ACCESS
    # =====================================================================
    {
        "name": "SSH - Successful Login",
        "severity": "low",
        "mitre_id": "T1078",
        "pattern": re.compile(
            r"Accepted password for (?P<user>\S+) from (?P<ip>\S+) port"
        ),
        "description": "A user successfully logged in via SSH."
    },
    {
        "name": "SSH - Failed Login",
        "severity": "medium",
        "mitre_id": "T1110",
        "pattern": re.compile(
            r"Failed password for (?P<user>.*?) from (?P<ip>\S+) port"
        ),
        "description": "A failed SSH login attempt occurred."
    },
    {
        "name": "Sudo Command Execution",
        "severity": "low",
        "mitre_id": "T1078",
        "pattern": re.compile(
            r"sudo:.*COMMAND=(?P<cmd>.*)"
        ),
        "description": "A user executed a command with sudo privileges."
    },
    {
        "name": "User Session Opened (su)",
        "severity": "medium",
        "mitre_id": "T1548.001",
        "pattern": re.compile(
            r"session opened for user (?P<target_user>\S+) by (?P<source_user>\S+)\(uid=\d+\)"
        ),
        "description": "A user switched to another user account using 'su'."
    },

    # =====================================================================
    # 2. EXECUTION & COMMAND AND CONTROL (C2)
    # =====================================================================
    {
        "name": "Bash Reverse Shell",
        "severity": "critical",
        "mitre_id": "T1059.004",
        "pattern": re.compile(
            r"bash -i.*>/dev/tcp/(?P<ip>[\d.]+)/(?P<port>\d+)"
        ),
        "description": "A common bash reverse shell pattern was detected."
    },
    {
        "name": "Netcat Reverse Shell or Listener",
        "severity": "critical",
        "mitre_id": "T1059.004",
        "pattern": re.compile(
            r"nc\s+.*(-l|-p|-e|--listen|--exec)"
        ),
        "description": "Suspicious Netcat (nc) usage, potentially for a reverse shell or listener."
    },
    {
        "name": "Socat Reverse Shell",
        "severity": "critical",
        "mitre_id": "T1090",
        "pattern": re.compile(
            r"socat\s+(TCP|TCP4|TCP6)"
        ),
        "description": "Socat process started, often used for advanced reverse shells and C2."
    },
    {
        "name": "Download and Execute Script",
        "severity": "high",
        "mitre_id": "T1105",
        "pattern": re.compile(
            r"(curl|wget)\s+.*https?://.*\s*\|\s*(sh|bash|python)"
        ),
        "description": "A script was downloaded from the internet and piped directly into a shell for execution."
    },
    {
        "name": "Decoded Base64 Execution",
        "severity": "high",
        "mitre_id": "T1027",
        "pattern": re.compile(
            r"echo\s+['\"].*['\"]\s*\|\s*base64\s+(-d|--decode).*\s*\|\s*(sh|bash)"
        ),
        "description": "A base64-encoded string was decoded and piped into a shell, a common obfuscation technique."
    },

    # =====================================================================
    # 3. PRIVILEGE ESCALATION
    # =====================================================================
    {
        "name": "User Added to Privileged Group",
        "severity": "high",
        "mitre_id": "T1098",
        "pattern": re.compile(
            r"usermod -aG (sudo|docker|adm|root)\s+(?P<user>\S+)"
        ),
        "description": "A user was added to a highly privileged group (sudo, docker, etc.)."
    },
    {
        "name": "New User Account Created",
        "severity": "medium",
        "mitre_id": "T1136.001",
        "pattern": re.compile(
            r"new user\[\d+\]: name=(?P<user>\S+),"
        ),
        "description": "A new user account was created on the system."
    },

    # =====================================================================
    # 4. DEFENSE EVASION
    # =====================================================================
    {
        "name": "Firewall Disabled",
        "severity": "high",
        "mitre_id": "T1562.004",
        "pattern": re.compile(
            r"(ufw disable|iptables -F)"
        ),
        "description": "The system firewall (UFW or iptables) was disabled or flushed."
    },
    {
        "name": "History File Deletion or Clearing",
        "severity": "medium",
        "mitre_id": "T1070.003",
        "pattern": re.compile(
            r"(rm .bash_history|history -c)"
        ),
        "description": "An attempt to clear or delete the command-line history was detected."
    },

    # =====================================================================
    # 5. FIM (File Integrity Monitoring) RULES
    # =====================================================================
    {
        "name": "File Deleted",
        "type": "fim",
        "severity": "medium",
        "mitre_id": "T1070.004",
        "description": "A monitored file was deleted."
    },
    {
        "name": "File Modified",
        "type": "fim",
        "severity": "high",
        "mitre_id": "T1036",
        "description": "The content of a monitored file has changed."
    },
    {
        "name": "Permission Denied Reading File",
        "type": "fim",
        "severity": "low",
        "mitre_id": "T1222.002",
        "description": "FIM could not read a monitored file, possibly due to permission changes."
    },
    {
        "name": "Malicious String in File",
        "type": "fim-content",
        "severity": "high",
        "mitre_id": "T1027",
        "pattern": re.compile(
            r"(malicious|trojan|exploit|backdoor|pwned)",
            re.IGNORECASE
        ),
        "description": "A potentially malicious keyword was found inside a monitored file."
    },
    
    # =====================================================================
    # 6. HARDWARE & KERNEL EVENTS (from Log Files)
    # =====================================================================
    {
        "name": "USB Storage Device Attached (Kernel Log)",
        "pattern": re.compile(r"kernel:.*Attached SCSI removable disk"),
        "severity": "medium",
        "mitre_id": "T1200", # Hardware Additions
        "description": "A USB storage device was attached, detected via kernel logs."
    },
    {
        "name": "USB Device Detected (Kernel Log)",
        "pattern": re.compile(r"kernel:.*new high-speed USB device"),
        "severity": "low",
        "mitre_id": "T1200", # Hardware Additions
        "description": "Kernel detected a new high-speed USB device."
    },
    {
        "name": "USB Driver Loaded (Kernel Log)",
        "pattern": re.compile(r"kernel:.*usbcore: registered new interface driver"),
        "severity": "low",
        "mitre_id": "T1200", # Hardware Additions
        "description": "A new USB interface driver was registered by the kernel."
    }
]
