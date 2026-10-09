"""The web page and its live VirusTotal stream, with VirusTotal replaced by a fake."""

import io
import re
import time
from pathlib import Path

import pytest

import app as hookline
from analyser import jobs, pipeline

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "fake" / "phish_03_password_expiry.eml"


@pytest.fixture
def client():
    hookline.app.config["TESTING"] = True
    return hookline.app.test_client()


@pytest.fixture
def fake_virustotal(monkeypatch):
    """Answer every lookup at once with "nothing found", without touching the network."""
    def fake_lookup(kind, value):
        return {"kind": kind, "value": value, "status": "found",
                "malicious": 0, "suspicious": 0, "engines": 90}
    monkeypatch.setattr(pipeline, "lookup", fake_lookup)


def upload(client, data, filename="test.eml", virustotal=False):
    form = {"email": (io.BytesIO(data), filename)}
    if virustotal:
        form["virustotal"] = "1"
    return client.post("/analyse", data=form, content_type="multipart/form-data")


def stream_url(page):
    return re.search(r'data-stream="([^"]+)"', page).group(1)


def test_home_page(client):
    page = client.get("/").get_data(as_text=True)
    assert f"{len(hookline.CHECKS)} red-flag checks" in page


def test_upload_needs_an_eml_file(client):
    assert client.post("/analyse", data={}).status_code == 400
    assert upload(client, b"hello", filename="notes.txt").status_code == 400


def test_result_page(client):
    response = upload(client, SAMPLE.read_bytes())
    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Malicious" in page
    assert "Sender and authentication" in page
    assert "data-stream" not in page    # VirusTotal wasn't switched on


def test_live_virustotal_stream(client, fake_virustotal):
    page = upload(client, SAMPLE.read_bytes(), virustotal=True).get_data(as_text=True)
    body = client.get(stream_url(page)).get_data(as_text=True)

    assert body.startswith("retry: 3000")     # sent at once, before any lookup
    assert "event: lookup" in body and "event: done" in body
    assert "id: 1\n" in body


def test_reconnecting_gets_what_was_missed(client, fake_virustotal):
    # The old version deleted the job when the page first connected, so a
    # browser reconnecting after a dropped connection got "No such job"
    page = upload(client, SAMPLE.read_bytes(), virustotal=True).get_data(as_text=True)
    url = stream_url(page)
    first = client.get(url).get_data(as_text=True)
    lookups = first.count("event: lookup")
    assert lookups >= 2

    again = client.get(url, headers={"Last-Event-ID": "1"})
    assert again.status_code == 200
    replay = again.get_data(as_text=True)
    assert "id: 1\n" not in replay                        # already seen
    assert replay.count("event: lookup") == lookups - 1   # the rest are resent
    assert "event: done" in replay


def test_heartbeat_while_waiting(client, monkeypatch):
    def slow_lookup(kind, value):
        time.sleep(0.3)
        return {"kind": kind, "value": value, "status": "not_found"}
    monkeypatch.setattr(pipeline, "lookup", slow_lookup)
    monkeypatch.setattr(hookline, "HEARTBEAT_SECONDS", 0.05)

    page = upload(client, SAMPLE.read_bytes(), virustotal=True).get_data(as_text=True)
    body = client.get(stream_url(page)).get_data(as_text=True)
    assert ": still checking" in body and "event: done" in body


def test_unknown_job(client):
    assert client.get("/progress/does-not-exist").status_code == 404


def test_abandoned_job_stops_looking_things_up(monkeypatch):
    looked_up = []

    def counting_lookup(kind, value):
        looked_up.append(value)
        return {"kind": kind, "value": value, "status": "not_found"}
    monkeypatch.setattr(pipeline, "lookup", counting_lookup)
    monkeypatch.setattr(jobs, "ABANDON_AFTER", -1)   # nobody has watched for "too long" already

    from analyser.parser import parse_email_bytes
    job = jobs.start(parse_email_bytes(SAMPLE.read_bytes()), "x.eml", "x")
    events = job.events_after(0, timeout=5)
    assert events[-1][0] == "failed"
    assert looked_up == []
