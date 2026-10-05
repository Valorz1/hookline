from flask import Flask, render_template, request

from analyser.parser import parse_email_bytes
from analyser import pipeline

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
    # pipeline.analyse, not analyse: this route function is ALSO called
    # analyse, and a plain analyse() here would call the route itself
    result = pipeline.analyse(parsed, use_virustotal=bool(request.form.get("virustotal")))
    return render_template(
        "result.html",
        filename=upload.filename,
        parsed=parsed,
        found=result["found"],
        outcome=result["outcome"],
        vt_results=result["vt_results"],
    )


if __name__ == "__main__":
    # debug=True is for your own computer only: never on a public server
    app.run(debug=True)
