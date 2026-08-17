from fileinput import filename

from flask import Flask, render_template, request, send_file
from analyzer.scanner import scan_code
import json
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

app = Flask(__name__)
ALLOWED_EXTENSIONS = {".py", ".js", ".java", ".php"}
MAX_FILE_SIZE = 500_000  # 500 KB
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

    history = history[-20:]

    with open(HISTORY_FILE, "w", encoding="utf-8") as file:
        json.dump(history, file, indent=4)
        ALLOWED_EXTENSIONS = {".py", ".js", ".java", ".php"}
MAX_FILE_SIZE = 500_000


def allowed_file(filename):
    if "." not in filename:
        return False

    extension = os.path.splitext(filename)[1].lower()
    return extension in ALLOWED_EXTENSIONS
    


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

        # Get pasted code
        submitted_code = request.form.get("code", "")

        # Get uploaded file
        uploaded_file = request.files.get("code_file")

        # If a file was uploaded, use the file instead
        if uploaded_file and uploaded_file.filename:

            if not allowed_file(uploaded_file.filename):
                return "Invalid file type. Please upload a .py, .js, .java, or .php file.", 400

            file_data = uploaded_file.read()

            if len(file_data) > MAX_FILE_SIZE:
                return "File is too large. Maximum allowed size is 500 KB.", 400

            try:
                submitted_code = file_data.decode("utf-8")
            except UnicodeDecodeError:
                return "The uploaded file could not be read as UTF-8 text.", 400

        # Scan the code
        if submitted_code.strip():

            findings = scan_code(submitted_code)

            score, risk, high, medium, low = calculate_risk(findings)

            save_scan_history(
                score,
                risk,
                high,
                medium,
                low
            )

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
@app.route("/download-report")
def download_report():

    history = load_history()

    if not history:
        return "No scan history available. Run a scan first.", 400

    latest = history[-1]

    filename = "security_report.pdf"

    c = canvas.Canvas(filename, pagesize=A4)

    width, height = A4
    y = height - 50

    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, y, "AI Secure Code Auditor")

    y -= 30

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Security Audit Report")

    y -= 35

    c.setFont("Helvetica", 11)

    c.drawString(50, y, f"Scan Date: {latest['date']}")
    y -= 20

    c.drawString(50, y, f"Security Score: {latest['score']}/100")
    y -= 20

    c.drawString(50, y, f"Overall Risk: {latest['risk']}")
    y -= 30

    c.drawString(50, y, f"HIGH Findings: {latest['high']}")
    y -= 20

    c.drawString(50, y, f"MEDIUM Findings: {latest['medium']}")
    y -= 20

    c.drawString(50, y, f"LOW Findings: {latest['low']}")

    c.save()

    return send_file(
        filename,
        as_attachment=True,
        download_name="security_report.pdf"
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