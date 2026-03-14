from groq import Groq
import os
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def analyze_logs(parsed_logs):
    """Send parsed logs to Groq AI for threat analysis"""
    
    # Prepare summary for AI
    suspicious_logs = [log for log in parsed_logs if log["suspicious"]]
    total = len(parsed_logs)
    suspicious_count = len(suspicious_logs)
    
    log_summary = "\n".join([
        f"- [{log['type']}] {log['event']} | IP: {log['ip']} | Severity: {log['severity']}"
        for log in parsed_logs[:50]  # limit to 50 logs
    ])
    
    prompt = f"""You are a SOC analyst. Analyze these system logs and provide a threat assessment.

Total logs: {total}
Suspicious events: {suspicious_count}

Log Summary:
{log_summary}

Provide your analysis in this EXACT format:
THREAT_LEVEL: LOW or MEDIUM or HIGH or CRITICAL
SUMMARY: 2-3 sentences describing what you found
THREATS:
- threat 1
- threat 2
- threat 3
RECOMMENDATIONS:
- recommendation 1
- recommendation 2
- recommendation 3"""

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=500
    )
    
    response_text = response.choices[0].message.content.strip()
    
    # Parse the response
    lines = response_text.split('\n')
    
    threat_level = "LOW"
    summary = ""
    threats = []
    recommendations = []
    current_section = None
    
    for line in lines:
        line = line.strip()
        if line.startswith("THREAT_LEVEL:"):
            threat_level = line.replace("THREAT_LEVEL:", "").strip()
        elif line.startswith("SUMMARY:"):
            summary = line.replace("SUMMARY:", "").strip()
        elif line.startswith("THREATS:"):
            current_section = "threats"
        elif line.startswith("RECOMMENDATIONS:"):
            current_section = "recommendations"
        elif line.startswith("-") and current_section == "threats":
            threats.append(line[1:].strip())
        elif line.startswith("-") and current_section == "recommendations":
            recommendations.append(line[1:].strip())
    
    return {
        "threat_level": threat_level,
        "summary": summary,
        "threats": threats,
        "recommendations": recommendations,
        "total_logs": total,
        "suspicious_count": suspicious_count,
        "suspicious_logs": suspicious_logs[:10]
    }