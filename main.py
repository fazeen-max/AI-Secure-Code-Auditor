from flask import Flask, render_template, request
from analyzer.scanner import scan_code

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def dashboard():

    findings = []
    submitted_code = ""

    if request.method == "POST":

        submitted_code = request.form.get("code", "")

        if submitted_code.strip():
            findings = scan_code(submitted_code)

    return render_template(
        "dashboard.html",
        findings=findings,
        submitted_code=submitted_code
    )


if __name__ == "__main__":
    app.run(debug=True)