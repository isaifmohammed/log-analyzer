from datetime import datetime

# Store alerts in memory
alerts = []

def create_alert(log, analysis=None):
    """Create a new alert from a suspicious log"""
    
    alert = {
        "id": len(alerts) + 1,
        "timestamp": str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "type": log.get("type", "UNKNOWN"),
        "event": log.get("event", "Unknown Event"),
        "ip": log.get("ip", "N/A"),
        "severity": log.get("severity", "INFO"),
        "raw": log.get("raw", ""),
        "status": "OPEN"
    }
    
    alerts.append(alert)
    return alert


def get_all_alerts():
    """Get all alerts"""
    return alerts


def get_alerts_by_severity(severity):
    """Filter alerts by severity"""
    return [a for a in alerts if a["severity"] == severity]


def close_alert(alert_id):
    """Mark alert as closed"""
    for alert in alerts:
        if alert["id"] == alert_id:
            alert["status"] = "CLOSED"
            return True
    return False


def get_alert_stats():
    """Get alert statistics"""
    total = len(alerts)
    open_alerts = len([a for a in alerts if a["status"] == "OPEN"])
    closed_alerts = len([a for a in alerts if a["status"] == "CLOSED"])
    warnings = len([a for a in alerts if a["severity"] == "WARNING"])
    errors = len([a for a in alerts if a["severity"] == "ERROR"])
    
    return {
        "total": total,
        "open": open_alerts,
        "closed": closed_alerts,
        "warnings": warnings,
        "errors": errors
    }


def clear_all_alerts():
    """Clear all alerts"""
    global alerts
    alerts = []