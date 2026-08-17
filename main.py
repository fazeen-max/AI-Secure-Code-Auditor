from flask import Flask, render_template, request
from analyzer.scanner import scan_code
import json
import os
from datetime import datetime

app = Flask(__name__)
HISTORY_FILE = "scan_history.json"


def calculate_risk(findings):
    high = sum(1 for finding in findings if finding["severity"] == "HIGH")
    medium = sum(1 for finding in findings if finding["severity"] == "MEDIUM")
    low = sum(1 for finding in findings if finding["severity"] == "LOW")

    # Start with a perfect score
    score = 100

    # Deduct points based on severity
    score -= high * 25
    score -= medium * 15
    score -= low * 5

    # Keep score between 0 and 100
    score = max(0, min(100, score))

    if score >= 80:
        risk = "LOW"
    elif score >= 50:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    return score, risk, high, medium, low
def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return []


def save_scan_history(score, risk, high, medium, low):
    history = load_history()

    history.append({
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "score": score,
        "risk": risk,
        "high": high,
        "medium": medium,
        "low": low
    })

    # Keep the most recent 20 scans
    history = history[-20:]

    with open(HISTORY_FILE, "w", encoding="utf-8") as file:
        json.dump(history, file, indent=4)


@app.route("/", methods=["GET", "POST"])
def dashboard():

    findings = []
    submitted_code = ""

    score = None
    risk = None
    high = 0
    medium = 0
    low = 0

    if request.method == "POST":

        submitted_code = request.form.get("code", "")

        if submitted_code.strip():

            findings = scan_code(submitted_code)

            score, risk, high, medium, low = calculate_risk(findings)
            save_scan_history(score, risk, high, medium, low)

    return render_template(
        "dashboard.html",
        findings=findings,
        submitted_code=submitted_code,
        score=score,
        risk=risk,
        high=high,
        medium=medium,
        low=low
    )
@app.route("/history")
def history():
    scan_history = load_history()

    # Show newest scans first
    scan_history.reverse()

    return render_template(
        "history.html",
        history=scan_history
    )


if __name__ == "__main__":
    app.run(debug=True)