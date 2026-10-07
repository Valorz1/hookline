import json
import queue
import threading
import uuid

from flask import Flask, Response, render_template, request, stream_with_context, url_for

from analyser.parser import parse_email_bytes
from analyser import pipeline
from analyser.virustotal import choose_targets

app = Flask(__name__)

# Refuse uploads over 10 MB so nobody can crash the app with a giant file
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# VirusTotal jobs still running, by id. Each has a queue: the background thread
# puts results in one end, /progress takes them out the other and sends them on.
# A job is removed when its page starts listening.
jobs = {}


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
    # analyse, and a plain analyse() here would call the route itself.
    # This is the quick part (under a second), so the page can appear at once.
    result = pipeline.analyse(parsed)
    vt_results = []
    stream_url = None

    targets = choose_targets(result["found"], parsed["attachments"]) if request.form.get("virustotal") else []
    if targets:
        # Placeholders, in the same order the lookups will happen
        vt_results = [{"kind": kind, "value": value, "status": "pending"} for kind, value in targets]
        job_id = uuid.uuid4().hex
        updates = queue.Queue()
        jobs[job_id] = {"updates": updates, "filename": upload.filename, "subject": parsed["subject"]}
        # daemon=True: don't keep the app running after Ctrl+C just for this thread
        threading.Thread(target=run_virustotal, args=(parsed, updates), daemon=True).start()
        stream_url = url_for("progress", job_id=job_id)

    return render_template(
        "result.html",
        filename=upload.filename,
        subject=parsed["subject"],
        parsed=parsed,
        found=result["found"],
        outcome=result["outcome"],
        vt_results=vt_results,
        stream_url=stream_url,
        live=bool(stream_url),
    )


def run_virustotal(parsed, updates):
    """Runs in a background thread: the full analysis, reporting each lookup as it lands."""
    try:
        result = pipeline.analyse(parsed, use_virustotal=True,
                                  on_lookup=lambda r: updates.put(("lookup", r)))
        updates.put(("done", result["outcome"]))
    except Exception as error:
        # Without this the page would wait forever for a "done" that never comes
        updates.put(("failed", str(error)))


def sse(event, data):
    """One Server-Sent Event: a name, then the data as JSON, then a blank line."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@app.get("/progress/<job_id>")
def progress(job_id):
    job = jobs.pop(job_id, None)
    if job is None:
        return "No such job, or it's already being watched.", 404

    def stream():
        while True:
            # Waits here until the thread puts something in the queue
            event, data = job["updates"].get()
            if event == "lookup":
                yield sse("lookup", render_template("_vt_row.html", r=data))
            elif event == "done":
                yield sse("done", {
                    "verdict": render_template("_verdict.html", outcome=data,
                                               filename=job["filename"], subject=job["subject"]),
                    "why": render_template("_why.html", outcome=data),
                    "title": f"{data['verdict']} · HookLine",
                })
                return
            else:
                yield sse("failed", data)
                return

    # stream_with_context keeps render_template working while the response streams
    return Response(stream_with_context(stream()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache"})


if __name__ == "__main__":
    # debug=True is for your own computer only: never on a public server
    app.run(debug=True)
