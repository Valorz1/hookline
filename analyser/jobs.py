"""Background VirusTotal jobs for the web page.

The quick checks take under a second, but each VirusTotal lookup takes about
15 seconds, so app.py shows the page straight away and runs the lookups here,
in a background thread. The page listens for the results as they arrive.

A job keeps EVERY event it has produced, not just the newest. So when a page's
connection drops and the browser reconnects, or someone comes back with the
Back button, it's sent everything again instead of "no such job".
"""

import threading
import time
import uuid

from analyser import pipeline

# How long a job is remembered after it starts, so a page can reconnect to it
KEEP_FOR = 15 * 60

# Stop looking things up when no page has listened for this long. The person
# has moved on, and the lookups would only hold up the next email's: every
# job shares the same 4-a-minute VirusTotal allowance.
ABANDON_AFTER = 60


class Job:
    """One email's VirusTotal lookups, and everything they've produced so far."""

    def __init__(self, filename, subject):
        self.id = uuid.uuid4().hex
        self.filename = filename
        self.subject = subject
        self.started = time.monotonic()
        self.last_watched = self.started
        # ("lookup", result) for each lookup, then ("done", outcome) or ("failed", message)
        self.events = []
        self._changed = threading.Condition()

    def add(self, name, data):
        with self._changed:
            self.events.append((name, data))
            self._changed.notify_all()  # wake every page waiting in events_after()

    def events_after(self, count, timeout):
        """The events after the first `count`, waiting up to `timeout` seconds for one."""
        self.last_watched = time.monotonic()
        with self._changed:
            self._changed.wait_for(lambda: len(self.events) > count, timeout)
            return self.events[count:]

    def abandoned(self):
        return time.monotonic() - self.last_watched > ABANDON_AFTER


_jobs = {}
_jobs_lock = threading.Lock()


def start(parsed, filename, subject):
    """Start one email's VirusTotal lookups in the background and return its Job."""
    job = Job(filename, subject)
    with _jobs_lock:
        _forget_old()
        _jobs[job.id] = job
    # daemon=True: don't keep the app running after Ctrl+C just for this thread
    threading.Thread(target=_run, args=(job, parsed), daemon=True).start()
    return job


def get(job_id):
    """The job with this id, or None if there isn't one (or it's been forgotten)."""
    with _jobs_lock:
        return _jobs.get(job_id)


def _forget_old():
    now = time.monotonic()
    for job_id in [job_id for job_id, job in _jobs.items() if now - job.started > KEEP_FOR]:
        del _jobs[job_id]


def _run(job, parsed):
    """Runs in the background thread: the full analysis, reporting each lookup as it lands."""
    try:
        result = pipeline.analyse(parsed, use_virustotal=True,
                                  on_lookup=lambda r: job.add("lookup", r),
                                  should_stop=job.abandoned)
    except Exception as error:
        # Without this the page would wait forever for a "done" that never comes
        job.add("failed", str(error))
        return
    if result["vt_stopped"]:
        job.add("failed", "Stopped early because nobody was watching any more.")
    else:
        job.add("done", result["outcome"])
