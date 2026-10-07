import base64
import json
import os
import threading
import time
from pathlib import Path
from urllib.parse import urlparse
from analyser.checks import FREEMAIL

import requests
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

#the free API key allows 4 requests per minute, so we need to wait 15 seconds between requests
SECONDS_BETWEEN_REQUESTS = 15

# Well-known infrastructure that appears in normal emails. Looking these up
# would waste our 500-a-day limit, so we skip them.
ALLOWLIST = {"w3.org", "googleapis.com", "gstatic.com", "googleusercontent.com",
             "google.com", "microsoft.com", "apple.com", "amazon.com"}


# Answers are saved here so we never look up the same thing twice,
# even between runs. This file is in .gitignore.

CACHE_FILE = Path("vt_cache.json")


_last_request = 0.0
# The web app can run lookups in several threads at once. This lock makes them
# take turns, so together they still stay under 4 requests a minute.
_rate_lock = threading.Lock()

def _load_cache():
    try:  
        return json.loads(CACHE_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}



_cache =_load_cache()

def _save_cache():
    CACHE_FILE.write_text(json.dumps(_cache, indent=2))


def is_allowlisted(domain):
    """True for allowlisted domains and their subdomains (fonts.googleapis.com)."""
    domain = (domain or "").lower()
    if domain in FREEMAIL:
        return True # gmail.com etc are nerver malicious as a whole domain.
    return any(domain == safe or domain.endswith("." + safe) for safe in ALLOWLIST)


def _wait_for_rate_limit():
    """Sleep just long enough to stay under 4 requests a minute."""
    global _last_request
    with _rate_lock:
        wait = SECONDS_BETWEEN_REQUESTS - (time.monotonic() - _last_request)
        if wait > 0:
            time.sleep(wait)
        _last_request = time.monotonic()


def _url_id(url):
    # VirusTotal identifies a URL by its base64 encoding, without the = padding
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def lookup(kind, value):
    """Ask VirusTotal about one thing.

    Args:
        kind: "file", "domain", "ip" or "url"
        value: the SHA-256 hash, domain, IP address or URL

    Returns:
        dict with "status" ("found", "not_found" or "error") and, if found,
        how many engines called it malicious or suspicious.
    """
    cache_key = f"{kind}:{value}"
    if cache_key in _cache:
        return _cache[cache_key]

    if not API_KEY:
        return {"kind": kind, "value": value, "status": "error",
                "detail": "No VT_API_KEY in .env"}

    paths = {"file": "files", "domain": "domains", "ip": "ip_addresses", "url": "urls"}
    item_id = _url_id(value) if kind == "url" else value
    address = f"{BASE_URL}/{paths[kind]}/{item_id}"

    try:
        _wait_for_rate_limit()
        response = requests.get(address, headers={"x-apikey": API_KEY}, timeout=15)
        if response.status_code == 429:
            # Over the limit anyway (maybe another program used the key): wait and retry once
            time.sleep(60)
            response = requests.get(address, headers={"x-apikey": API_KEY}, timeout=15)
    except requests.RequestException as error:
        # No internet, timeout, etc. Don't crash HookLine, and don't cache it
        return {"kind": kind, "value": value, "status": "error", "detail": str(error)}

    if response.status_code == 200:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        result = {"kind": kind, "value": value, "status": "found",
                  "malicious": stats.get("malicious", 0),
                  "suspicious": stats.get("suspicious", 0),
                  # Only count engines that actually gave an opinion
                  "engines": sum(stats.get(k, 0) for k in
                                 ("malicious", "suspicious", "undetected", "harmless"))}
    elif response.status_code == 404:
        result = {"kind": kind, "value": value, "status": "not_found"}
    else:
        # 401 = bad key, 429 = still over the limit. Not cached, so it's retried next time
        return {"kind": kind, "value": value, "status": "error",
                "detail": f"HTTP {response.status_code}"}

    _cache[cache_key] = result
    _save_cache()
    return result


def choose_targets(found, attachments, max_lookups=8):
    """Pick what to look up, most useful first, skipping allowlisted domains."""
    targets = [("file", a["sha256"]) for a in attachments]
    targets += [("ip", ip) for ip in found["ips"]]
    targets += [("domain", d) for d in found["domains"] if not is_allowlisted(d)]
    targets += [("url", u) for u in found["urls"]
                if not is_allowlisted(urlparse(u).hostname)]
    return targets[:max_lookups]


def describe(result):
    """One readable line about a lookup result."""
    label = f"{result['kind']:<7}{result['value'][:70]}"
    if result["status"] == "found":
        return f"{label}  ->  {result['malicious']} malicious, {result['suspicious']} suspicious (of {result['engines']})"
    if result["status"] == "not_found":
        return f"{label}  ->  never seen by VirusTotal"
    return f"{label}  ->  error: {result['detail']}"