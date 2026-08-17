
AI Secure Code Auditor

A lightweight web-based security auditing tool that analyzes source code for common security vulnerabilities and presents the findings through a professional Flask dashboard.

Features

- 🔍 Source-code security scanning
- 🚨 Vulnerability detection with severity levels
- 🔴 HIGH, 🟠 MEDIUM, and 🟢 LOW risk classification
- 📊 Security score out of 100
- 📈 Scan History Analytics
- 📜 Persistent scan history using "history.json"
- 📄 Downloadable security audit report in PDF format
- 🖥️ Professional dark-themed Flask dashboard
- 💡 Security recommendations for detected vulnerabilities

Security Checks

The scanner currently detects:

Vulnerability| Severity
Hardcoded Secrets| HIGH
SQL Injection| HIGH
Command Execution| HIGH
Dynamic Code Execution ("eval" / "exec")| HIGH
Insecure Deserialization| HIGH
Path Traversal| HIGH
Weak Cryptography — MD5| MEDIUM
Weak Cryptography — SHA-1| MEDIUM
Weak Randomness| MEDIUM
Insecure HTTP| LOW

Dashboard

The web dashboard provides:

- Source-code input
- Security findings
- Finding counts
- Severity statistics
- Security score
- Overall risk level
- Recommended remediation
- Scan history analytics
- Security report download

Project Structure

AI-Secure-Code-Auditor/
│
├── analyzer/
│   └── scanner.py
│
├── templates/
│   └── dashboard.html
│
├── history.json
├── main.py
├── requirements.txt
├── README.md
└── .gitignore

Technologies Used

- Python 3
- Flask
- Jinja2
- Regular Expressions
- ReportLab
- HTML
- CSS
- JSON
- Git & GitHub

How It Works

1. The user submits source code through the Flask dashboard.
2. The scanner analyzes the code line by line.
3. Regular-expression based security rules identify suspicious patterns.
4. Each finding is assigned a vulnerability type and severity.
5. The application calculates an overall security score and risk level.
6. Scan results are stored in "history.json".
7. Historical scan data is used to generate dashboard analytics.
8. The latest scan can be exported as a PDF security report.

Installation

Clone the repository:

git clone https://github.com/fazeen-max/AI-Secure-Code-Auditor.git
cd AI-Secure-Code-Auditor

Create a virtual environment:

python -m venv .venv

Activate it on Windows:

.venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

Run the Application

Start the Flask application:

python main.py

Then open:

http://127.0.0.1:5000

Example

The scanner can detect insecure code such as:

password = "admin123"

and report it as:

Type: Hardcoded Secret
Severity: HIGH

along with a recommendation to store secrets securely.

Security Score

The application evaluates detected findings and calculates a security score from 0 to 100.

A higher score indicates fewer detected security issues, while a lower score indicates greater security risk.

Scan History

Each scan can be recorded in:

history.json

The dashboard uses this information to display:

- Total scans
- High-risk scans
- Medium-risk scans
- Low-risk scans
- Average security score

PDF Security Report

The application provides a Download Security Report option that generates a PDF containing information such as:

- Scan date
- Security score
- Overall risk
- High-severity findings
- Medium-severity findings
- Low-severity findings

Limitations

This project is a lightweight pattern-based security auditor. It is intended for educational and demonstration purposes and should not be considered a replacement for professional static application security testing tools.

Because the scanner relies on predefined patterns, it may produce false positives or miss vulnerabilities that require deeper code analysis.

Future Improvements

Possible future improvements include:

- AST-based Python analysis
- Support for additional programming languages
- More advanced vulnerability rules
- Improved false-positive handling
- User authentication
- More detailed historical charts
- Integration with professional SAST tools

Author

Fazeen Nadeem

Computer Science Student

License

This project is available for educational and personal use.