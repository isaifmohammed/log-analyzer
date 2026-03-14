from flask import Flask, render_template, request, jsonify
from src.parser import parse_log_file
from src.analyzer import analyze_logs
from src.alerts import create_alert, get_all_alerts, close_alert, get_alert_stats, clear_all_alerts
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        # Get log content from request
        if "file" in request.files:
            file = request.files["file"]
            content = file.read().decode("utf-8")
        else:
            data = request.get_json()
            content = data.get("logs", "")

        if not content:
            return jsonify({"error": "No log content provided"}), 400

        # Step 1: Parse logs
        parsed_logs = parse_log_file(content)

        # Step 2: Create alerts for suspicious logs
        for log in parsed_logs:
            if log["suspicious"]:
                create_alert(log)

        # Step 3: AI Analysis
        analysis = analyze_logs(parsed_logs)

        return jsonify({
            "success": True,
            "analysis": analysis,
            "parsed_logs": parsed_logs[:20]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/alerts", methods=["GET"])
def get_alerts():
    return jsonify(get_all_alerts())


@app.route("/alerts/stats", methods=["GET"])
def alert_stats():
    return jsonify(get_alert_stats())


@app.route("/alerts/close/<int:alert_id>", methods=["POST"])
def close(alert_id):
    success = close_alert(alert_id)
    return jsonify({"success": success})


@app.route("/alerts/clear", methods=["POST"])
def clear():
    clear_all_alerts()
    return jsonify({"success": True})

if __name__ == "__main__":
    app.run(debug=True)