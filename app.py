import json

from flask import Flask, Response, render_template, request, stream_with_context, url_for

from analyser import jobs, pipeline
from analyser.checks import CHECKS
from analyser.parser import parse_email_bytes
from analyser.verdict import vt_level
from analyser.virustotal import choose_targets, report_link

app = Flask(__name__)

# Refuse uploads over 10 MB so nobody can crash the app with a giant file
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# Helpers the templates can call, so the rules live in Python, not in HTML
app.jinja_env.globals.update(vt_level=vt_level, report_link=report_link)

# While waiting for the next VirusTotal result, send a "still here" this often.
# Without it the connection sits silent for minutes, and browsers, proxies and
# antivirus web shields may decide it's dead and cut it.
HEARTBEAT_SECONDS = 15


@app.context_processor
def check_count():
    # So the pages never say "13 checks" after a 14th is added
    return {"check_count": len(CHECKS)}


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
    try:
        parsed = parse_email_bytes(upload.read())
    except Exception:
        # Phishing emails are sometimes broken on purpose. Say so, don't crash.
        return render_template("index.html", error="HookLine couldn't read that file as an email."), 400

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
        job = jobs.start(parsed, upload.filename, parsed["subject"])
        stream_url = url_for("progress", job_id=job.id)

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


def sse(event, data, event_id):
    """One Server-Sent Event: its number, a name, then the data as JSON, then a blank line."""
    return f"id: {event_id}\nevent: {event}\ndata: {json.dumps(data)}\n\n"


def render_event(job, name, data, number):
    """Turn one of a job's events into a Server-Sent Event for the page."""
    if name == "lookup":
        # Lookups come first, in order, so lookup number 1 fills row 0
        index = number - 1
        return sse("lookup", {"index": index,
                              "row": render_template("partials/vt_row.html", r=data, index=index)}, number)
    if name == "done":
        return sse("done", {
            "verdict": render_template("partials/verdict.html", outcome=data,
                                       filename=job.filename, subject=job.subject),
            "why": render_template("partials/why.html", outcome=data),
            "title": f"{data['verdict']} · HookLine",
        }, number)
    return sse("failed", data, number)


@app.get("/progress/<job_id>")
def progress(job_id):
    job = jobs.get(job_id)
    if job is None:
        return "No such job. It may have expired: analyse the email again.", 404

    # When the browser reconnects, it says the number of the last event it
    # received, so it's only sent the ones it missed
    last_seen = request.headers.get("Last-Event-ID", "")
    count = min(int(last_seen), len(job.events)) if last_seen.isdigit() else 0

    def stream():
        nonlocal count
        # Answer at once, even if the first lookup is minutes away, so the
        # browser knows it's connected. "retry" asks it to reconnect after
        # 3 seconds (3000 ms) if the connection ever drops.
        yield "retry: 3000\n\n"
        while True:
            # Waits here until the job has something new, or the heartbeat is due
            new = job.events_after(count, timeout=HEARTBEAT_SECONDS)
            if not new:
                # A line starting with ":" is a comment: the page ignores it,
                # but it shows the connection is alive
                yield ": still checking\n\n"
                continue
            for name, data in new:
                count += 1
                yield render_event(job, name, data, count)
                if name in ("done", "failed"):
                    return

    # stream_with_context keeps render_template working while the response streams
    return Response(stream_with_context(stream()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


if __name__ == "__main__":
    # debug=True is for your own computer only: never on a public server
    app.run(debug=True)
