import json
from pathlib import Path
from flask import Flask, render_template

app = Flask(__name__)

REPORT_PATH = Path("outputs/security_report.json")


def load_report():
    if not REPORT_PATH.exists():
        return {
            "metadata": {},
            "summary": {},
            "correlated_risks": [],
            "findings": []
        }

    with open(REPORT_PATH, "r") as file:
        return json.load(file)


@app.route("/")
def dashboard():
    report = load_report()

    return render_template(
        "index.html",
        metadata=report.get("metadata", {}),
        summary=report.get("summary", {}),
        correlated_risks=report.get("correlated_risks", []),
        findings=report.get("findings", [])
    )


if __name__ == "__main__":
    app.run(debug=True)
