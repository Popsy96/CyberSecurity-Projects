"""
processing/response.py
=======================
Incident Response and Mitigation Plan data.

Provides structured IR playbooks and mitigation strategies
for each threat category detected by the CTI Dashboard.

Used by:
  - dashboard/js/charts.js (Tab 5 — IR & Mitigation)
  - main.py (exported to data.json)
"""

# ================================================================
# INCIDENT RESPONSE PLAYBOOKS
# Full lifecycle per threat category
# Based on: NIST SP 800-61r2, ASD Essential Eight, ACSC Guidelines
# ================================================================

IR_PLAYBOOKS = {
    "Phishing": {
        "severity":    "High",
        "mitre":       "T1566 — Phishing",
        "nist":        "Protect",
        "asd_e8":      "Restrict Office Macros · MFA",
        "response_time": "4 hours",
        "phases": {
            "Preparation": [
                "Deploy email filtering solution (e.g. Microsoft Defender, Proofpoint)",
                "Enable MFA on all email accounts",
                "Subscribe CTI Dashboard to OTX phishing pulses",
                "Train staff on phishing identification annually",
            ],
            "Detection": [
                "CTI Dashboard flags phishing URL or domain targeting AU brand",
                "User reports suspicious email to IT helpdesk",
                "Email gateway alerts on blocked phishing attempt",
                "Review CTI Dashboard for related IOCs (same domain family)",
            ],
            "Containment": [
                "Block phishing domain at DNS resolver immediately",
                "Block phishing URL at web proxy/firewall",
                "Remove phishing emails from all mailboxes via admin tools",
                "Disable any accounts that clicked and entered credentials",
            ],
            "Eradication": [
                "Reset credentials for all users who interacted with phishing page",
                "Scan endpoints of affected users for credential-stealing malware",
                "Review mail server logs to identify all recipients",
                "Remove any malicious email rules or forwarding set by attacker",
            ],
            "Recovery": [
                "Re-enable accounts after credential reset and MFA enrollment",
                "Monitor affected accounts for 30 days for suspicious activity",
                "Notify affected users of the incident and actions taken",
                "Verify no further phishing emails remain in mailboxes",
            ],
            "Lessons Learned": [
                "Document how the phishing email bypassed existing filters",
                "Update email filtering rules based on attack patterns",
                "Run phishing simulation to measure staff awareness improvement",
                "Add IOCs from this incident to CTI Dashboard watch list",
            ],
        },
        "mitigation": {
            "short_term": [
                "Block phishing domains from CTI Dashboard feed at DNS/firewall",
                "Enable MFA on all user accounts immediately",
                "Alert users about active phishing campaigns targeting AU brands",
                "Deploy email authentication: DMARC, SPF, DKIM",
            ],
            "long_term": [
                "Deploy advanced email filtering with AI-based phishing detection",
                "Conduct phishing simulation exercises quarterly",
                "Implement security awareness training program annually",
                "Subscribe to brand abuse monitoring for AU-targeted campaigns",
                "Enable conditional access policies based on login risk score",
            ],
        },
        "vulnerability_fixes": [
            "Enable email filtering (block known phishing domains)",
            "Implement MFA on all accounts",
            "Deploy DMARC / SPF / DKIM email authentication",
            "Conduct phishing awareness training",
            "Enable browser-based phishing protection",
        ],
        "au_contacts": [
            "Report phishing to ACSC: cyber.gov.au/report",
            "Report AU brand impersonation to ScamWatch: scamwatch.gov.au",
        ],
    },

    "C2 Server": {
        "severity":    "Critical",
        "mitre":       "T1071 — Application Layer Protocol",
        "nist":        "Detect",
        "asd_e8":      "Application Control · Patch Applications",
        "response_time": "1 hour",
        "phases": {
            "Preparation": [
                "Deploy EDR (Endpoint Detection and Response) on all endpoints",
                "Configure firewall to alert on outbound connections to known C2 IPs",
                "Integrate Feodo Tracker feed into CTI Dashboard for C2 detection",
                "Implement network segmentation to limit lateral movement",
            ],
            "Detection": [
                "CTI Dashboard flags active C2 IP from Feodo Tracker or OTX",
                "EDR detects malware beacon to known C2 infrastructure",
                "Firewall alerts on outbound connection to blocked IP range",
                "SIEM detects unusual outbound traffic patterns",
            ],
            "Containment": [
                "IMMEDIATELY block C2 IP address at perimeter firewall",
                "Isolate all hosts communicating with the C2 server",
                "Disable network access for affected hosts",
                "Preserve memory dumps and logs before remediation",
            ],
            "Eradication": [
                "Identify malware variant using CTI Dashboard malware family data",
                "Remove malware implants, persistence mechanisms, and scheduled tasks",
                "Scan all adjacent hosts for same malware indicators",
                "Rebuild hosts if compromise is deep or persistent",
            ],
            "Recovery": [
                "Restore clean system image from verified backup",
                "Reconnect systems to network only after verification",
                "Monitor restored systems for 30 days for reinfection",
                "Update EDR signatures with new malware indicators",
            ],
            "Lessons Learned": [
                "Identify how malware was initially delivered",
                "Review firewall rules to prevent similar C2 communications",
                "Update CTI Dashboard blocklist with new C2 infrastructure",
                "Improve network monitoring to detect C2 patterns earlier",
            ],
        },
        "mitigation": {
            "short_term": [
                "Block all C2 IPs from Feodo Tracker at perimeter firewall",
                "Search internal logs for connections to flagged C2 IPs",
                "Isolate any hosts found communicating with C2 infrastructure",
                "Deploy DNS filtering to block malicious domains",
            ],
            "long_term": [
                "Deploy EDR solution on all endpoints organisation-wide",
                "Implement Zero Trust Network Architecture",
                "Configure firewall to block outbound traffic on non-standard ports",
                "Implement network traffic analysis (NTA) for anomaly detection",
                "Deploy SIEM with C2 detection use cases",
            ],
        },
        "vulnerability_fixes": [
            "Deploy Endpoint Detection and Response (EDR)",
            "Block outbound traffic to known C2 IP ranges",
            "Implement network segmentation",
            "Enable DNS filtering (Cloudflare Gateway, Cisco Umbrella)",
            "Deploy SIEM for C2 communication pattern detection",
        ],
        "au_contacts": [
            "Report to ACSC: 1300 CYBER1 (1300 292 371)",
            "Report critical infrastructure incidents via ReportCyber: cyber.gov.au/report",
        ],
    },

    "Malware Distribution": {
        "severity":    "High",
        "mitre":       "T1204 — User Execution",
        "nist":        "Detect",
        "asd_e8":      "Application Control · Patch Applications",
        "response_time": "4 hours",
        "phases": {
            "Preparation": [
                "Deploy web content filtering to block malicious URLs",
                "Integrate URLhaus feed into CTI Dashboard for real-time URL blocking",
                "Configure antivirus with automatic signature updates",
                "Restrict ability for users to download executable files",
            ],
            "Detection": [
                "CTI Dashboard flags malicious URL from URLhaus feed",
                "Antivirus detects malware download attempt",
                "Web proxy blocks access to known malware distribution URL",
                "User reports unexpected file download or system behaviour",
            ],
            "Containment": [
                "Block malicious URLs at web proxy and DNS resolver",
                "Alert all users not to access flagged URLs",
                "Isolate any host that has downloaded malware",
                "Disable auto-run features on USB and removable media",
            ],
            "Eradication": [
                "Remove malware artifacts from affected systems",
                "Scan all endpoints for file hashes matching CTI Dashboard IOCs",
                "Restore affected files from clean backup",
                "Update antivirus signatures with new malware indicators",
            ],
            "Recovery": [
                "Restore clean system from verified backup",
                "Patch the vulnerability exploited by the malware",
                "Monitor restored systems for 30 days",
                "Verify antivirus is updated and running on all endpoints",
            ],
            "Lessons Learned": [
                "Identify how users accessed the malicious URL",
                "Update web filtering policies to prevent recurrence",
                "Review patch management process for exploited vulnerabilities",
                "Add new malware hashes to CTI Dashboard watchlist",
            ],
        },
        "mitigation": {
            "short_term": [
                "Block malicious URLs from URLhaus feed at web proxy",
                "Update antivirus signatures immediately",
                "Scan all endpoints for known malware indicators",
                "Restrict executable file downloads from internet",
            ],
            "long_term": [
                "Implement application whitelisting (only approved apps can run)",
                "Deploy sandboxing to analyse suspicious files before execution",
                "Establish patch management process with 30-day patch cycle",
                "Configure browsers to block known malicious sites",
                "Implement software restriction policies via Group Policy",
            ],
        },
        "vulnerability_fixes": [
            "Update antivirus signatures daily",
            "Patch all software within 30 days of release",
            "Restrict executable downloads from internet",
            "Deploy application whitelisting",
            "Enable browser safe browsing protection",
        ],
        "au_contacts": [
            "Report malware to ACSC: cyber.gov.au/report",
            "Submit malware samples to abuse.ch: urlhaus.abuse.ch/api",
        ],
    },

    "Brute Force": {
        "severity":    "High",
        "mitre":       "T1110 — Brute Force",
        "nist":        "Protect",
        "asd_e8":      "Multi-Factor Authentication · Restrict Admin Privileges",
        "response_time": "4 hours",
        "phases": {
            "Preparation": [
                "Enable MFA on all internet-facing accounts",
                "Configure account lockout after 5 failed login attempts",
                "Disable or restrict RDP and SSH access from public internet",
                "Integrate AbuseIPDB feed to detect brute force source IPs",
            ],
            "Detection": [
                "CTI Dashboard flags IP conducting brute force (AbuseIPDB confidence ≥ 70%)",
                "SIEM alerts on multiple failed login attempts from single IP",
                "Authentication logs show high volume of failed attempts",
                "Account lockout notifications triggered",
            ],
            "Containment": [
                "Block attacking IP address at firewall immediately",
                "Lock all accounts targeted in brute force attack",
                "Temporarily disable affected services if actively under attack",
                "Enable geo-blocking for countries not expected to access systems",
            ],
            "Eradication": [
                "Disable any accounts successfully compromised",
                "Force password reset for all targeted accounts",
                "Review authentication logs for successful logins from attacking IP",
                "Revoke any sessions established by attacker",
            ],
            "Recovery": [
                "Re-enable accounts after password reset and MFA enrollment",
                "Restore services with enhanced authentication controls",
                "Monitor accounts for 30 days for suspicious activity",
                "Verify account lockout policies are effective",
            ],
            "Lessons Learned": [
                "Review password policy strength requirements",
                "Assess MFA coverage across all accounts",
                "Update firewall rules to limit exposure of services",
                "Consider implementing Privileged Access Management (PAM)",
            ],
        },
        "mitigation": {
            "short_term": [
                "Block brute force source IPs from AbuseIPDB feed at firewall",
                "Enable account lockout after 5 failed attempts",
                "Force password reset on all targeted accounts",
                "Enable MFA immediately on all internet-facing accounts",
            ],
            "long_term": [
                "Implement Privileged Access Management (PAM) for admin accounts",
                "Enforce minimum 14-character passwords with complexity requirements",
                "Disable public access to RDP and SSH — require VPN",
                "Deploy SIEM with brute force detection use cases",
                "Implement risk-based authentication (flag unusual login patterns)",
            ],
        },
        "vulnerability_fixes": [
            "Enable MFA on all accounts",
            "Set account lockout after 5 failed attempts",
            "Enforce strong password policy (min 14 characters)",
            "Disable RDP/SSH from public internet (use VPN)",
            "Deploy SIEM with brute force alerting",
        ],
        "au_contacts": [
            "Report credential stuffing attacks to ACSC: cyber.gov.au/report",
        ],
    },

    "DDoS Attack": {
        "severity":    "High",
        "mitre":       "T1498 — Network Denial of Service",
        "nist":        "Respond",
        "asd_e8":      "Application Control",
        "response_time": "1 hour",
        "phases": {
            "Preparation": [
                "Subscribe to DDoS protection service (Cloudflare, AWS Shield)",
                "Establish ISP escalation contact for null-routing",
                "Configure CDN for all public-facing services",
                "Develop and test DDoS response runbook",
            ],
            "Detection": [
                "CTI Dashboard flags known DDoS botnet IP or campaign",
                "Network monitoring detects traffic spike exceeding baseline",
                "ISP alerts on volumetric attack targeting organisation",
                "Service availability monitoring triggers alerts",
            ],
            "Containment": [
                "Activate DDoS protection service immediately",
                "Rate-limit traffic from flagged IP ranges",
                "Contact ISP to null-route attack traffic upstream",
                "Implement traffic scrubbing to filter malicious traffic",
            ],
            "Eradication": [
                "Work with ISP and DDoS protection provider to block attack",
                "Identify and block attack source IP ranges",
                "Implement more aggressive rate limiting if attack persists",
            ],
            "Recovery": [
                "Restore service capacity after attack subsides",
                "Verify service availability for all users",
                "Review and tune DDoS protection thresholds",
                "Document attack characteristics for future detection",
            ],
            "Lessons Learned": [
                "Review DDoS protection capacity vs attack volume",
                "Improve ISP escalation procedures",
                "Update CTI Dashboard to monitor DDoS campaign IOCs",
                "Consider upgrading DDoS protection tier if attacks recur",
            ],
        },
        "mitigation": {
            "short_term": [
                "Activate DDoS protection service",
                "Rate-limit traffic from flagged IPs in CTI Dashboard",
                "Contact ISP for upstream traffic filtering",
                "Implement emergency access control lists",
            ],
            "long_term": [
                "Deploy CDN with built-in DDoS protection for all services",
                "Implement anycast network architecture for resilience",
                "Establish SLA with DDoS protection provider",
                "Conduct DDoS simulation exercise annually",
            ],
        },
        "vulnerability_fixes": [
            "Deploy CDN with DDoS protection (Cloudflare, AWS Shield)",
            "Configure rate limiting at perimeter",
            "Establish ISP escalation contacts in advance",
            "Implement anycast routing for resilience",
            "Test DDoS response runbook quarterly",
        ],
        "au_contacts": [
            "Report DDoS to ACSC: 1300 CYBER1",
            "Contact your ISP for upstream traffic filtering assistance",
        ],
    },

    "SQL Injection": {
        "severity":    "High",
        "mitre":       "T1190 — Exploit Public-Facing Application",
        "nist":        "Protect",
        "asd_e8":      "Patch Applications · Application Control",
        "response_time": "4 hours",
        "phases": {
            "Preparation": [
                "Deploy Web Application Firewall (WAF) on all web applications",
                "Conduct regular code reviews for SQL injection vulnerabilities",
                "Use parameterised queries in all database interactions",
                "Implement least-privilege database accounts",
            ],
            "Detection": [
                "CTI Dashboard flags IP conducting SQL injection (AbuseIPDB category 16)",
                "WAF blocks and alerts on SQL injection attempt patterns",
                "Application logs show malformed SQL queries in request parameters",
                "Database error messages appearing in application responses",
            ],
            "Containment": [
                "Block attacking IP at WAF and firewall",
                "Temporarily restrict access to affected web endpoints",
                "Review database logs for successful injection queries",
                "Preserve web server and database logs for forensic analysis",
            ],
            "Eradication": [
                "Patch the vulnerable code with parameterised queries",
                "Remove any malicious content injected into database",
                "Review and harden WAF rules",
                "Conduct full penetration test of affected application",
            ],
            "Recovery": [
                "Restore database from clean backup if data was manipulated",
                "Re-deploy patched application code",
                "Verify WAF is correctly blocking injection attempts",
                "Notify affected users if personal data was exposed (Privacy Act)",
            ],
            "Lessons Learned": [
                "Review secure coding practices across all applications",
                "Implement mandatory code review process for database queries",
                "Schedule regular penetration testing",
                "Update WAF rules with patterns from this attack",
            ],
        },
        "mitigation": {
            "short_term": [
                "Block SQL injection source IPs from CTI Dashboard at WAF",
                "Enable WAF in blocking mode for all web applications",
                "Review application logs for evidence of successful injection",
                "Apply emergency patches to vulnerable endpoints",
            ],
            "long_term": [
                "Refactor all database queries to use parameterised statements",
                "Implement mandatory secure code review process",
                "Conduct penetration testing annually",
                "Deploy runtime application self-protection (RASP)",
                "Implement database activity monitoring",
            ],
        },
        "vulnerability_fixes": [
            "Use parameterised queries / prepared statements",
            "Deploy Web Application Firewall (WAF)",
            "Patch vulnerable web applications",
            "Apply least-privilege to database accounts",
            "Conduct penetration testing annually",
        ],
        "au_contacts": [
            "Report web application attacks to ACSC: cyber.gov.au/report",
            "Notify OAIC if personal data was exposed: oaic.gov.au",
        ],
    },

    "Port Scan": {
        "severity":    "Medium",
        "mitre":       "T1046 — Network Service Discovery",
        "nist":        "Detect",
        "asd_e8":      "Application Control",
        "response_time": "24 hours",
        "phases": {
            "Preparation": [
                "Deploy network intrusion detection system (IDS)",
                "Configure firewall to log and alert on scanning activity",
                "Minimise attack surface by closing unused ports and services",
                "Integrate AbuseIPDB feed for known scanner IP detection",
            ],
            "Detection": [
                "CTI Dashboard flags IP conducting port scanning (AbuseIPDB category 14)",
                "IDS/IPS alerts on systematic port scanning pattern",
                "Firewall logs show sequential connection attempts across ports",
            ],
            "Containment": [
                "Block scanning IP at firewall",
                "Review what services were exposed during the scan",
                "Close any unnecessary open ports discovered during review",
            ],
            "Eradication": [
                "No malware removal required (scanning is reconnaissance only)",
                "Harden firewall rules to reduce exposed attack surface",
                "Disable any services not required for business operations",
            ],
            "Recovery": [
                "Normal operations can continue — scanning alone causes no damage",
                "Document exposed services for remediation planning",
                "Schedule vulnerability scan to verify hardening effectiveness",
            ],
            "Lessons Learned": [
                "Review firewall rules and close unnecessary ports",
                "Assess whether exposed services require additional protection",
                "Update CTI Dashboard filters to track scanning campaign patterns",
            ],
        },
        "mitigation": {
            "short_term": [
                "Block scanner IPs from CTI Dashboard at perimeter firewall",
                "Review and close unnecessary open ports",
                "Enable firewall logging for all connection attempts",
            ],
            "long_term": [
                "Implement network segmentation to reduce scan visibility",
                "Deploy honeypots to detect and study scanning activity",
                "Conduct regular port scanning self-assessment",
                "Implement geo-blocking for countries with no business need",
            ],
        },
        "vulnerability_fixes": [
            "Close all unnecessary open ports at firewall",
            "Deploy network intrusion detection (IDS)",
            "Implement network segmentation",
            "Enable firewall logging and alerting",
            "Deploy honeypots to detect reconnaissance",
        ],
        "au_contacts": [
            "Report persistent scanning to ACSC: cyber.gov.au/report",
        ],
    },

    "Ransomware": {
        "severity":    "Critical",
        "mitre":       "T1486 — Data Encrypted for Impact",
        "nist":        "Respond",
        "asd_e8":      "Regular Backups · Application Control · Patch OS",
        "response_time": "1 hour",
        "phases": {
            "Preparation": [
                "Implement 3-2-1 backup strategy with offline/immutable backups",
                "Test backup restoration monthly",
                "Deploy EDR with ransomware detection and rollback capability",
                "Implement least-privilege access controls",
            ],
            "Detection": [
                "CTI Dashboard detects ransomware-related IOC (C2, dropper, hash)",
                "EDR alerts on ransomware-like file encryption behaviour",
                "Users report files are encrypted or inaccessible",
                "Ransom note discovered on affected systems",
            ],
            "Containment": [
                "IMMEDIATELY disconnect affected systems from network",
                "Disable network shares and mapped drives",
                "Isolate backup systems to protect from encryption",
                "Shut down affected systems if encryption is still in progress",
            ],
            "Eradication": [
                "DO NOT pay the ransom — no guarantee of decryption",
                "Identify ransomware variant using CTI Dashboard malware classification",
                "Remove ransomware executable and persistence mechanisms",
                "Verify all traces removed before restoration",
            ],
            "Recovery": [
                "Restore from OFFLINE backups ONLY — verify integrity first",
                "Do NOT connect backup drives to infected network",
                "Restore systems in priority order (critical systems first)",
                "Patch the vulnerability used for initial access before reconnecting",
            ],
            "Lessons Learned": [
                "Identify initial infection vector (phishing, RDP, vulnerability)",
                "Review backup strategy and test restoration frequency",
                "Assess whether offline backups were truly isolated",
                "Report to ACSC — ransomware reporting now mandatory in Australia",
            ],
        },
        "mitigation": {
            "short_term": [
                "Verify offline backup integrity IMMEDIATELY",
                "Ensure at least one backup is completely disconnected from network",
                "Review and restrict administrative privileges",
                "Deploy EDR with ransomware-specific detection rules",
            ],
            "long_term": [
                "Implement immutable/air-gapped backup solution",
                "Deploy EDR on all endpoints with ransomware rollback",
                "Implement network segmentation to limit lateral spread",
                "Disable unnecessary services (RDP, SMBv1, macros)",
                "Conduct ransomware tabletop exercise annually",
            ],
        },
        "vulnerability_fixes": [
            "Maintain offline backups tested weekly",
            "Deploy EDR with ransomware detection and rollback",
            "Restrict administrative privileges (least privilege)",
            "Disable RDP from public internet",
            "Patch operating systems within 14 days of critical patches",
        ],
        "au_contacts": [
            "Report ransomware to ACSC: 1300 CYBER1 (mandatory reporting)",
            "Do NOT pay ransom — contact ACSC first",
            "Notify OAIC if personal data encrypted: oaic.gov.au",
            "Contact AFP Cybercrime: 1300 300 AFP",
        ],
    },
}

# Default playbook for unrecognised categories
DEFAULT_PLAYBOOK = {
    "severity":    "Medium",
    "mitre":       "T1071 — Application Layer Protocol",
    "nist":        "Detect",
    "asd_e8":      "Application Control",
    "response_time": "24 hours",
    "phases": {
        "Preparation":    ["Monitor via CTI Dashboard", "Ensure logging is enabled"],
        "Detection":      ["Review CTI Dashboard for related IOCs", "Check internal logs"],
        "Containment":    ["Block suspicious IPs at firewall", "Isolate affected systems"],
        "Eradication":    ["Remove threat artifacts", "Patch exploited vulnerabilities"],
        "Recovery":       ["Restore services from backup", "Monitor for recurrence"],
        "Lessons Learned":["Update detection rules", "Review this IRP"],
    },
    "mitigation": {
        "short_term": ["Block IOCs from CTI Dashboard", "Enable enhanced monitoring"],
        "long_term":  ["Apply security patches", "Implement SIEM monitoring"],
    },
    "vulnerability_fixes": [
        "Apply security updates",
        "Monitor logs regularly",
        "Implement SIEM monitoring",
    ],
    "au_contacts": ["Report to ACSC: cyber.gov.au/report"],
}


def get_incident_response(category: str) -> dict:
    """
    Get full incident response playbook for a threat category.
    Returns the playbook dict with all lifecycle phases.
    """
    return IR_PLAYBOOKS.get(category, DEFAULT_PLAYBOOK)


def get_mitigation_plan(category: str) -> dict:
    """
    Get short-term and long-term mitigation plan for a threat category.
    """
    playbook = IR_PLAYBOOKS.get(category, DEFAULT_PLAYBOOK)
    return playbook.get("mitigation", DEFAULT_PLAYBOOK["mitigation"])


def get_vulnerability_fix(category: str) -> list:
    """
    Get quick vulnerability fix list for a threat category.
    """
    playbook = IR_PLAYBOOKS.get(category, DEFAULT_PLAYBOOK)
    return playbook.get("vulnerability_fixes", DEFAULT_PLAYBOOK["vulnerability_fixes"])


def get_all_playbooks_summary() -> list:
    """
    Get a summary list of all playbooks for the dashboard overview table.
    Returns list of dicts with key fields only.
    """
    summary = []
    for category, data in IR_PLAYBOOKS.items():
        summary.append({
            "category":      category,
            "severity":      data["severity"],
            "mitre":         data["mitre"],
            "nist":          data["nist"],
            "asd_e8":        data["asd_e8"],
            "response_time": data["response_time"],
            "short_term_count": len(data["mitigation"]["short_term"]),
            "long_term_count":  len(data["mitigation"]["long_term"]),
        })
    return summary


def export_for_dashboard() -> dict:
    """
    Export all IR and mitigation data structured for the dashboard JS.
    Called by main.py and written into data.json.
    """
    return {
        "playbooks":  IR_PLAYBOOKS,
        "summary":    get_all_playbooks_summary(),
        "categories": list(IR_PLAYBOOKS.keys()),
    }