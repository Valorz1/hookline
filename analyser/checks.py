import re 
from email.utils import parseaddr
from urllib.parse import urlparse

from analyser.observables import find_urls, is_ip
# THIS FILE TYPE THAT RUN IN THE CODE WHEN OPENDED
RISKY_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".vbs", ".wsf"}

#Phrase phising uses to rush peopel.
RISKY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bwithin \d+ hours\b", r"\b\d+ hours\b",
    r"\baction required\b", r"\bverify your\b", r"\bsuspended\b", r"\blimited\b",
    r"\blocked\b", r"\bunusual (sign-?in )?activity\b", r"\bexpires? today\b",
    r"\bwill be closed\b", r"\bunpaid\b", r"\byou have won\b", r"\bgift cards?\b",
    r"\bkeep this between us\b", r"\bdate of birth\b",
]

# Invisible characters used in phishing attempts
#char you dont see the attack and the attack use them tpo break up word like.
INVISIBLE_CHARS = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060", "\u2061", "\u2062", "\u2063", "\u2064", "\u2065", "\u2066", "\u2067", "\u2068", "\u2069"}


#Find links in the HTMl version.
LINK_PATTERN = re.compile(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.DOTALL)


TAG_PATTERN = re.compile(r"<[^>]+>")


def domain_of(header):
    """Name of the domain that sent an email, or None if it can't be determined."""
    address = parseaddr(str(header or ""))[1]
    return address.split("@", 1)[-1].lower() if "@" in address else None

def finding (name, point, detail):
    """Return a dictionary describing a finding."""
    return {
        "check": name,
        "points": point,
        "detail": detail,
    }



# ---------- the checks ----------
# Each check looks for ONE red flag. It returns a finding if it spots
# the flag, or None if the email looks fine on that point.

def check_authentication(parsed, found):
    results = str(parsed["auth_results"] or "").lower()
    if "spf=fail" in results:
        return finding("spf_fail", 3, "SPF failed: the sending server isn't allowed to send for this domain")
    if "spf=softfail" in results or "spf=none" in results:
        return finding("spf_weak", 1, "SPF is missing or only a soft fail")
    return None

def check_reply_to(parsed, found):
    sender = domain_of(parsed["from"])
    reply = domain_of(parsed["reply_to"])
    if reply and reply != sender:
        return finding("reply_to_mismatch", 3, f"Reply-To domain {reply} doesn't match sender {sender}")

    return None

def check_ip_links(parsed, found):
    ip_links = [url for url in found["urls"] if is_ip(urlparse(url).hostname or "")]
    if ip_links:
        return finding("ip_links", 3, f"Email contains links to IP addresses: {', '.join(ip_links)}")

    return None

def check_link_text(parsed, found):
    # The classic trick: the text SHOWS one address, the link GOES to another
    for href, shown in LINK_PATTERN.findall(parsed["html"]):
        shown = TAG_PATTERN.sub("", shown).strip()
        shown_urls = find_urls(shown)
        if not shown_urls:
            continue  # the text isn't an address ("Click here"), nothing to compare
        shown_host = urlparse(shown_urls[0]).hostname
        real_host = urlparse(href).hostname
        if shown_host and real_host and shown_host != real_host:
            return finding("link_text_mismatch", 4,
                           f"Link shows {shown_host} but goes to {real_host}")
    return None


def check_attachments(parsed, found):
    for attachment in parsed["attachments"]:
        name = attachment["filename"].lower()
        parts = name.split(".")
        extension = "." + parts[-1] if len(parts) > 1 else ""
        if extension in RISKY_EXTENSIONS and len(parts) > 2:
            return finding("double_extension", 5,
                           f"{attachment['filename']} pretends to be a document but is a program")
        if extension in RISKY_EXTENSIONS:
            return finding("risky_attachment", 4,
                           f"{attachment['filename']} is a file type that runs code")
    return None


def check_empty_body(parsed, found):
    # Remove invisible characters and tags, then see what's actually left
    text = parsed["body"] + TAG_PATTERN.sub("", parsed["html"])
    visible = "".join(ch for ch in text if ch not in INVISIBLE_CHARS).strip()
    if len(visible) < 20 and parsed["attachments"]:
        return finding("empty_body_attachment", 3,
                       "The body is (almost) empty: the real message is in the attachment")
    return None


def check_invisible_chars(parsed, found):
    text = str(parsed["subject"] or "") + parsed["body"] + parsed["html"]
    hidden = sum(1 for ch in text if ch in INVISIBLE_CHARS)
    # A combining mark straight after a plain English letter, like A + ܿ,
    # is the trick used to write "Aܿmܿaܿzܿon"
    disguised = re.findall(r"[A-Za-z][\u0300-\u036f\u0730-\u074a]", text)
    if hidden or disguised:
        return finding("invisible_chars", 3,
                       f"Hidden or disguising characters found ({hidden + len(disguised)})")
    return None


def check_urgency(parsed, found):
    text = (str(parsed["subject"] or "") + " " + parsed["body"]).lower()
    hits = [p for p in RISKY_PATTERNS if re.search(p, text)]
    # One urgent word happens in normal email; several together is pressure
    if len(hits) >= 2:
        return finding("urgent_language", 2, f"Pressure language ({len(hits)} phrases)")
    return None


# Every check in one list, so run_checks() can loop through them
CHECKS = [check_authentication, check_reply_to, check_ip_links, check_link_text,
          check_attachments, check_empty_body, check_invisible_chars, check_urgency]


def run_checks(parsed, found):
    """Run every check and return the list of red flags found."""
    findings = []
    for check in CHECKS:
        result = check(parsed, found)
        if result:
            findings.append(result)
    return findings