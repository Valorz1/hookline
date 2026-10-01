from flask import Flask, render_template, request

from analyser.parser import parse_email_bytes
from analyser.observables import extract_observables
from analyser.checks import run_checks
from analyser.virustotal import choose_targets, lookup
from analyser.verdict import decide, vt_findings

app = Flask(__name__)

# Refuse uploads over 10 MB so nobody can crash the app with a giant file
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/analyse")
def analyse():
    upload = request.files.get("email")
    if not upload or not upload.filename:
        return render_template("index.html", error="Choose an .eml file first."), 400
    if not upload.filename.lower().endswith(".eml"):
        return render_template("index.html", error="That isn't an .eml file. Choose a file ending in .eml."), 400

    # The file is read in memory and never saved to disk
    parsed = parse_email_bytes(upload.read())
    found = extract_observables(parsed)
    findings = run_checks(parsed, found)

    vt_results = []
    if request.form.get("virustotal"):
        for kind, value in choose_targets(found, parsed["attachments"]):
            vt_results.append(lookup(kind, value))

    outcome = decide(findings + vt_findings(vt_results))
    return render_template(
        "result.html",
        filename=upload.filename,
        parsed=parsed,
        found=found,
        outcome=outcome,
        vt_results=vt_results,
    )


if __name__ == "__main__":
    # debug=True is for your own computer only: never on a public server
    app.run(debug=True)
