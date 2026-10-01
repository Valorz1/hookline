import re 
import unicodedata
from email.utils import getaddresses
from urllib.parse import urlparse

from analyser.observables import find_urls, is_ip

# Free personal email services. Real organisations don't send from these.
FREEMAIL = {"gmail.com", "googlemail.com", "hotmail.com", "outlook.com", "live.com",
            "yahoo.com", "icloud.com", "aol.com", "gmx.com", "proton.me", "protonmail.com"}

# Words that make a sender name sound like an organisation rather than a person
ORG_WORDS = re.compile(r"\b(bank|banco|support|security|service|team|account|billing|"
                       r"helpdesk|admin|customer|cliente|notification|department)\b",
                       re.IGNORECASE)

# File types that run code when opened. Real documents are never these.
RISKY_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".vbs", ".wsf",
                    ".ps1", ".jar", ".msi", ".iso", ".img", ".hta", ".lnk"}


# Services that hide a link's real destination until you click it
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "ow.ly",
              "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id"}

# Four or more single letters separated by spaces, like "C o i n b a s e"
SPACED_LETTERS = re.compile(r"\b(?:\w ){3,}\w\b")

# Famous brands and their real domains.
BRANDS = {
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "metamask": "metamask.io",
    "coindesk": "coindesk.com",
    "binance": "binance.com",
}

# Phrases phishing uses to rush people.
RISKY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bwithin \d+ hours\b", r"\b\d+ hours\b",
    r"\baction required\b", r"\bverify your\b", r"\bsuspended\b", r"\blimited\b",
    r"\blocked\b", r"\bunusual (sign-?in )?activity\b", r"\bexpires? today\b",
    r"\bwill be closed\b", r"\bunpaid\b", r"\byou have won\b", r"\bgift cards?\b",
    r"\bkeep this between us\b", r"\bdate of birth\b",
]

# Characters you can't see. Attackers use them to break up words like
# "PayPal" so filters don't match, or to pad out an empty-looking body.
INVISIBLE_CHARS = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060", "\u00ad", "\u2800",
                   "\u2061", "\u2062", "\u2063", "\u2064", "\u2066", "\u2067", "\u2068", "\u2069"}


# Find links in the HTML version. HTML ignores case, so <A HREF> counts too.
LINK_PATTERN = re.compile(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
                          re.IGNORECASE | re.DOTALL)


TAG_PATTERN = re.compile(r"<[^>]+>")


def domain_of(header):
    """Name of the domain that sent an email, or None if it can't be determined."""
    # getaddresses copes with messy headers that list several addresses,
    # like '"Microsoft account team", _ <x@evil.com>'. The real address is
    # usually last, so take the last one that has an @.
    for _, address in reversed(getaddresses([str(header or "")])):
        if "@" in address:
            return address.split("@")[-1].lower()
    return None

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
        return finding("reply_to_mismatch", 3,
                       f"Reply-To domain {reply} doesn't match sender {sender or '(no valid address)'}")

    return None

def check_freemail_org(parsed, found):
    # An organisation's name on a personal webmail account, like a "bank" on Gmail
    sender = domain_of(parsed["from"]) or ""
    if sender not in FREEMAIL:
        return None

    # The display name is everything before the < of the address
    name = str(parsed["from"] or "").split("<")[0]

    # Real people's names rarely have long numbers, [brackets] or words like "Bank"
    looks_official = (re.search(r"\d{6,}", name)
                      or "[" in name
                      or ORG_WORDS.search(name))
    if looks_official:
        return finding("freemail_org", 3,
                       f"Official-looking sender name, but sent from a personal {sender} account")
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


def check_brand_mismatch(parsed, found):
    # A famous brand in the From header, but sent from a domain the brand doesn't own.
    # Search the whole header, not just the parsed display name, because
    # attackers deliberately format it to confuse parsers.
    name = plain_text(str(parsed["from"] or "")).lower()
    sender = domain_of(parsed["from"]) or ""
    for brand, real_domain in BRANDS.items():
        # Real brands often send from a subdomain, like email.amazon.com
        is_real = sender == real_domain or sender.endswith("." + real_domain)
        if brand in name and not is_real:
            return finding("brand_mismatch", 4,
                           f"From header mentions {brand} but the email came from {sender}")
    return None


def plain_text(text):
    """Strip disguises: 'Aܿmܿaܿzܿon' -> 'Amazon', '𝕚ℂ𝕝𝕠𝕦𝕕' -> 'iCloud'."""
    # NFKD turns fancy letters into plain ones and splits off accents/marks
    text = unicodedata.normalize("NFKD", text)
    # Drop the combining marks and invisible characters, keep everything else
    return "".join(ch for ch in text
                   if not unicodedata.combining(ch) and ch not in INVISIBLE_CHARS)

def check_dkim_dmarc(parsed, found):
    results = str(parsed["auth_results"] or "").lower()
    if "dmarc=fail" in results:
        return finding("dmarc_fail", 3,
                       "DMARC failed: the From domain didn't authorise this email (likely spoofed)")
    if "dkim=fail" in results:
        return finding("dkim_fail", 2,
                       "DKIM failed: the email's digital signature doesn't check out")
    return None


def check_shortened_links(parsed, found):
    short = [domain for domain in found["domains"] if domain in SHORTENERS]
    if short:
        return finding("link_shortener", 2,
                       f"Links hidden behind a URL shortener ({short[0]})")
    return None


def check_spaced_name(parsed, found):
    if SPACED_LETTERS.search(str(parsed["from"] or "")):
        return finding("spaced_name", 3,
                       "Sender name is spaced out letter by letter to dodge filters")
    return None

# Every check in one list, so run_checks() can loop through them
CHECKS = [check_authentication, check_reply_to, check_ip_links, check_link_text,
          check_attachments, check_empty_body, check_invisible_chars, check_urgency,
          check_brand_mismatch, check_dkim_dmarc, check_shortened_links, check_spaced_name,
          check_freemail_org]


def run_checks(parsed, found):
    """Run every check and return the list of red flags found."""
    findings = []
    for check in CHECKS:
        result = check(parsed, found)
        if result:
            findings.append(result)
    return findings