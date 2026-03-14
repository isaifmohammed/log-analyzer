import re
from datetime import datetime

def parse_log_line(line):
    result = {
        "raw": line.strip(),
        "timestamp": str(datetime.now()),
        "type": "unknown",
        "ip": None,
        "event": None,
        "severity": "INFO",
        "suspicious": False
    }
    
    ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
    if ip_match:
        result["ip"] = ip_match.group()
    
    if re.search(r'sshd|ssh', line, re.IGNORECASE):
        result["type"] = "SSH"
        if re.search(r'Failed|Invalid|error', line, re.IGNORECASE):
            result["severity"] = "WARNING"
            result["suspicious"] = True
            result["event"] = "Failed SSH Login Attempt"
        elif re.search(r'Accepted', line, re.IGNORECASE):
            result["event"] = "Successful SSH Login"

    elif re.search(r'apache|nginx|GET|POST', line, re.IGNORECASE):
        result["type"] = "WEB"
        status_match = re.search(r'\s([45]\d{2})\s', line)
        if status_match:
            result["severity"] = "WARNING"
            result["suspicious"] = True
            result["event"] = f"HTTP Error {status_match.group(1)}"
        else:
            result["event"] = "Web Request"

    elif re.search(r'firewall|iptables|blocked|denied', line, re.IGNORECASE):
        result["type"] = "FIREWALL"
        result["severity"] = "WARNING"
        result["suspicious"] = True
        result["event"] = "Firewall Block"

    elif re.search(r'login|logon|authentication', line, re.IGNORECASE):
        result["type"] = "AUTH"
        if re.search(r'fail|invalid|error|wrong', line, re.IGNORECASE):
            result["severity"] = "WARNING"
            result["suspicious"] = True
            result["event"] = "Failed Authentication"
        else:
            result["event"] = "Authentication Event"

    elif re.search(r'error|critical|alert|emergency', line, re.IGNORECASE):
        result["type"] = "SYSTEM"
        result["severity"] = "ERROR"
        result["event"] = "System Error"

    else:
        result["event"] = "General Log Entry"

    return result


def parse_log_file(content):
    lines = content.strip().split('\n')
    parsed_logs = []
    for line in lines:
        if line.strip():
            parsed_logs.append(parse_log_line(line))
    return parsed_logs