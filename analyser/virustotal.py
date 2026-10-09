import base64
import hashlib
import ipaddress
import json
import os
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

from analyser.domains import FREEMAIL
from analyser.observables import host_of

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"
REPORT_URL = "https://www.virustotal.com/gui"

# The free API key allows 4 requests per minute, so we need to wait 15 seconds between requests
SECONDS_BETWEEN_REQUESTS = 15

# When VirusTotal still says "too many requests" after a minute's rest, the
# daily allowance (500) is used up. Stop asking for this long instead of
# making every remaining lookup wait and fail one by one.
LIMIT_COOLDOWN = 15 * 60

# Well-known infrastructure and social sites that appear in normal emails.
# Looking these up would waste our 500-a-day limit, so we skip them.
ALLOWLIST = {"w3.org", "googleapis.com", "gstatic.com", "googleusercontent.com",
             "google.com", "youtube.com", "microsoft.com", "office.com", "apple.com",
             "amazon.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
             "linkedin.com", "tiktok.com", "pinterest.com", "whatsapp.com"}

# Images shown inside the email, not links anyone clicks
IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp", ".ico")

# Answers are saved here so we never look up the same thing twice,
# even between runs. It lives in the data/ folder, which is in .gitignore,
# whichever folder HookLine is started from.
CACHE_FILE = Path(__file__).resolve().parent.parent / "data" / "vt_cache.json"


_last_request = 0.0
_paused_until = 0.0         # after a "too many requests", nobody asks again before this
_limit_reached_until = 0.0  # the daily allowance is used up: don't ask at all before this

# The web app can run lookups in several threads at once. This lock makes them
# take turns, so together they still stay under 4 requests a minute.
_rate_lock = threading.Lock()
_cache_lock = threading.Lock()


def _load_cache():
    try:
        return json.loads(CACHE_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


_cache = _load_cache()


def _remember(key, result):
    """Add an answer to the cache and save it."""
    with _cache_lock:
        _cache[key] = result
        # Write a new file, then swap it in, so a crash mid-write can't
        # leave a half-written cache behind
        temporary = CACHE_FILE.with_suffix(".tmp")
        try:
            CACHE_FILE.parent.mkdir(exist_ok=True)
            temporary.write_text(json.dumps(_cache, indent=2))
            temporary.replace(CACHE_FILE)
        except OSError:
            pass  # e.g. antivirus has the file open: the answer is still remembered until restart


def is_allowlisted(domain):
    """True for allowlisted domains and their subdomains (fonts.googleapis.com)."""
    domain = (domain or "").lower()
    if domain in FREEMAIL:
        return True  # gmail.com etc are never malicious as a whole domain.
    return any(domain == safe or domain.endswith("." + safe) for safe in ALLOWLIST)


def _wait_for_rate_limit():
    """Sleep just long enough to stay under 4 requests a minute."""
    global _last_request
    with _rate_lock:
        now = time.monotonic()
        wait = max(SECONDS_BETWEEN_REQUESTS - (now - _last_request), _paused_until - now)
        if wait > 0:
            time.sleep(wait)
        _last_request = time.monotonic()


def _pause_everyone(seconds):
    """After a "too many requests", make every thread wait, not just this one."""
    global _paused_until
    _paused_until = max(_paused_until, time.monotonic() + seconds)


def _url_id(url):
    # VirusTotal identifies a URL by its base64 encoding, without the = padding
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _failed(kind, value, reason, detail):
    """A lookup that didn't get an answer. Never cached, so it's tried again next time."""
    return {"kind": kind, "value": value, "status": "error", "reason": reason, "detail": detail}


def lookup(kind, value):
    """Ask VirusTotal about one thing.

    Args:
        kind: "file", "domain", "ip" or "url"
        value: the SHA-256 hash, domain, IP address or URL

    Returns:
        dict with "status" ("found", "not_found" or "error") and, if found,
        how many engines called it malicious or suspicious. Errors have a short
        "reason" and a longer "detail" saying what to do about it.
    """
    global _limit_reached_until
    cache_key = f"{kind}:{value}"
    if cache_key in _cache:
        return _cache[cache_key]

    if not API_KEY:
        return _failed(kind, value, "No API key", "Add VT_API_KEY to the .env file (see .env.example).")
    if time.monotonic() < _limit_reached_until:
        return _failed(kind, value, "Daily limit reached",
                       "The VirusTotal key has used today's free lookups. Try again later.")

    paths = {"file": "files", "domain": "domains", "ip": "ip_addresses", "url": "urls"}
    item_id = _url_id(value) if kind == "url" else value
    address = f"{BASE_URL}/{paths[kind]}/{item_id}"

    try:
        _wait_for_rate_limit()
        # Another analysis may have looked this up while we waited our turn
        if cache_key in _cache:
            return _cache[cache_key]
        response = requests.get(address, headers={"x-apikey": API_KEY}, timeout=15)
        if response.status_code == 429:
            # Over the per-minute limit (maybe another program used the key):
            # everyone rests for a minute, then this lookup tries once more
            _pause_everyone(60)
            _wait_for_rate_limit()
            response = requests.get(address, headers={"x-apikey": API_KEY}, timeout=15)
    except requests.Timeout:
        return _failed(kind, value, "Timed out", "VirusTotal took too long to answer. Try again later.")
    except requests.ConnectionError:
        return _failed(kind, value, "No connection",
                       "Couldn't reach VirusTotal. Check the internet connection.")
    except requests.RequestException as error:
        return _failed(kind, value, "Lookup failed", str(error))

    if response.status_code == 200:
        try:
            data = response.json()["data"]
            stats = data["attributes"].get("last_analysis_stats", {})
        except (ValueError, KeyError, TypeError):
            return _failed(kind, value, "Odd answer", "VirusTotal's answer wasn't in the expected format.")
        result = {"kind": kind, "value": value, "status": "found", "id": data.get("id"),
                  "malicious": stats.get("malicious", 0),
                  "suspicious": stats.get("suspicious", 0),
                  # Only count engines that actually gave an opinion
                  "engines": sum(stats.get(k, 0) for k in
                                 ("malicious", "suspicious", "undetected", "harmless"))}
    elif response.status_code == 404:
        result = {"kind": kind, "value": value, "status": "not_found"}
    elif response.status_code == 429:
        _limit_reached_until = time.monotonic() + LIMIT_COOLDOWN
        return _failed(kind, value, "Daily limit reached",
                       "The VirusTotal key has used today's free lookups (500 a day). Try again later.")
    elif response.status_code in (401, 403):
        return _failed(kind, value, "Key rejected",
                       f"VirusTotal rejected the API key (HTTP {response.status_code}). "
                       f"Check VT_API_KEY in .env.")
    else:
        return _failed(kind, value, "VirusTotal error",
                       f"VirusTotal answered HTTP {response.status_code}. Try again later.")

    _remember(cache_key, result)
    return result


def _worth_checking_ip(ip):
    # Private addresses like 192.168.1.1 are inside someone's own network:
    # VirusTotal can't know anything about them
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def choose_targets(found, attachments, max_lookups=8):
    """Pick what to look up, most useful first, skipping allowlisted domains and images."""
    targets = [("file", a["sha256"]) for a in attachments]
    targets += [("ip", ip) for ip in found["ips"] if _worth_checking_ip(ip)]
    targets += [("domain", d) for d in found["domains"] if not is_allowlisted(d)]

    # One link per website is enough: tracking links to the same site are
    # all different, and VirusTotal has usually never seen any of them
    hosts = set()
    for url in found["urls"]:
        host = host_of(url)
        if (not host or host in hosts or is_allowlisted(host)
                or urlparse(url).path.lower().endswith(IMAGE_EXTENSIONS)):
            continue
        hosts.add(host)
        targets.append(("url", url))
    return targets[:max_lookups]


def report_link(result):
    """The page on virustotal.com with the full report, or None if there isn't one."""
    if result.get("status") != "found":
        return None
    kind, value = result["kind"], result["value"]
    if kind == "url":
        # VirusTotal's pages name a URL by its SHA-256. Older cache entries
        # don't have the id VirusTotal sent, so work it out from the URL.
        return f"{REPORT_URL}/url/{result.get('id') or hashlib.sha256(value.encode()).hexdigest()}"
    pages = {"file": "file", "domain": "domain", "ip": "ip-address"}
    return f"{REPORT_URL}/{pages[kind]}/{value}"


def describe(result):
    """One readable line about a lookup result."""
    label = f"{result['kind']:<7}{result['value'][:70]}"
    if result["status"] == "found":
        return f"{label}  ->  {result['malicious']} malicious, {result['suspicious']} suspicious (of {result['engines']})"
    if result["status"] == "not_found":
        return f"{label}  ->  never seen by VirusTotal"
    return f"{label}  ->  {result.get('reason', 'error')}: {result['detail']}"
