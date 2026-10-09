import html
import re

from analyser.domains import (BRANDS, CLICK_TRACKERS, FREEMAIL, INVISIBLE_CHARS, SENDS_FOR_USERS,
                              SHORTENERS, SPACED_LETTERS, address_of, brand_in_domain,
                              brands_named_in, display_name_of, domain_of, imitated_brand, is_ip,
                              is_official, org_domain)
from analyser.observables import EMAIL_PATTERN, find_urls, host_of, unwrap_link

# Words that make a sender name sound like an organisation rather than a person
ORG_WORDS = re.compile(r"\b(bank|banco|support|security|service|team|account|billing|"
                       r"helpdesk|admin|customer|cliente|notification|department)\b",
                       re.IGNORECASE)

# File types that run code when opened. Real documents are never these.
RISKY_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs",
                    ".vbe", ".wsf", ".wsh", ".ps1", ".jar", ".msi", ".iso", ".img", ".vhd",
                    ".vhdx", ".hta", ".lnk", ".one", ".xll", ".cpl", ".scf", ".reg", ".msc",
                    ".appx", ".msix", ".chm"}

# Web pages sent as attachments open in the browser, ready to show a fake sign-in page
WEB_PAGE_EXTENSIONS = {".htm", ".html", ".shtml", ".xhtml", ".mht", ".mhtml", ".svg"}

# Office files that can carry macros: little programs that run inside Word or Excel
MACRO_EXTENSIONS = {".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".xlsb", ".pptm", ".ppam"}

# Phrases phishing uses to rush or scare people. Each is specific enough that
# ordinary emails rarely say it: "account suspended", not just "suspended",
# because "limited time offer" and "open 24 hours" are everyday marketing.
RISKY_PATTERNS = [re.compile(p) for p in [
    r"\burgent(ly)?\b", r"\bimmediately\b", r"\bimmediate action\b", r"\bwithin \d+ (hours|hrs|days)\b",
    r"\baction required\b", r"\bfinal (notice|warning|reminder)\b", r"\bfailure to\b",
    r"\b(verify|confirm|validate) your (account|identity|information|details|email|payment|password)\b",
    r"\b(account|card|wallet|mailbox|password|profile)( has been| have been| is| was| will be| are)?"
    r"( temporarily| now| currently)? (suspended|limited|locked|blocked|restricted|disabled|deactivated|"
    r"terminated|on hold)\b",
    r"\bunusual (sign-?in |login )?activity\b", r"\bsuspicious (sign-?in |login )?activity\b",
    r"\bunauthori[sz]ed (access|activity|transaction|login|sign-?in|payment)\b",
    r"\bexpires? today\b", r"\b(password|mailbox|account) (has )?expire[sd]?\b",
    r"\bwill be (closed|deleted|terminated|suspended)\b", r"\bunpaid\b",
    r"\b(update|confirm) (your )?(billing|payment) (details|information|method)\b",
    r"\bclick (here|below|the link|the button) to (verify|confirm|unlock|restore|reactivate|claim)\b",
    r"\byou('ve| have) (won|been (selected|chosen))\b", r"\bwinner\b",
    r"\bclaim (your )?(prize|reward|refund|gift|tokens?|airdrop)\b",
    r"\bgift ?cards?\b", r"\bkeep this between us\b", r"\bdate of birth\b",
    r"\b(seed|recovery|secret) phrase\b", r"\bconnect (your )?wallet\b",
    r"\bcancel (this|the) transaction\b", r"\b(parcel|package|shipment)\b.{0,15}\bon hold\b",
    r"\b(customs|redelivery|delivery) fee\b",
    # The same pressure in Portuguese and Spanish, common in the real samples
    r"\burgente\b", r"\b(imediatamente|inmediatamente)\b", r"\b(bloquead|suspens|suspendid)[oa]s?\b",
    r"\b(expira|expiram|expirando|vence) hoje\b", r"\b(saldo|cr[eé]dito|resgate|pontos)\b.{0,30}\b(liberad|expir)",
    r"\b(atualize|confirme|verifique) (seus|sua|seu)\b", r"\bverifique su\b",
]]

# Find links in the HTML version. HTML ignores case, so <A HREF> counts too.
LINK_PATTERN = re.compile(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
                          re.IGNORECASE | re.DOTALL)
TAG_PATTERN = re.compile(r"<[^>]+>")

# A box to type a password into, or any form that sends what you type to a website
PASSWORD_BOX = re.compile(r"<input\b[^>]*type\s*=\s*[\"']?password", re.IGNORECASE)
FORM = re.compile(r"<form\b", re.IGNORECASE)

# An invisible character INSIDE a word, like "Pay​Pal". Invisible characters
# between words are normal: marketing emails pad their preview text with them.
HIDDEN_IN_WORD = re.compile("[A-Za-z][" + "".join(map(re.escape, INVISIBLE_CHARS)) + "]+[A-Za-z]")
# A plain letter wearing an unusual mark, the trick behind "Aܿmܿaܿzܿon"
DISGUISE_MARK = re.compile(r"[A-Za-z][҃-҉ܰ-݊⃐-⃿]")
# Turns text the right way round from that point on, so "fdp.exe" displays as "exe.pdf"
RIGHT_TO_LEFT = "‮"


def finding(name, points, detail):
    """Return a dictionary describing a finding."""
    return {"check": name, "points": points, "detail": detail}


def brand_label(brand):
    """'paypal' -> 'Paypal', 'dhl' -> 'DHL'."""
    return brand.upper() if len(brand) <= 4 else brand.title()


def claimed_brands(from_header):
    """Brands the sender claims to be, in its name or the first half of its address."""
    header = str(from_header or "")
    address = address_of(header) or ""
    # Everything except the address itself, however oddly the header is written
    name = re.sub(re.escape(address), " ", header, flags=re.IGNORECASE) if address else header
    local = address.split("@")[0]
    in_address = [brand for brand in BRANDS
                  if " " not in brand and len(brand) >= 5 and brand in local]
    return list(dict.fromkeys(brands_named_in(name) + in_address))


def is_tracker(host):
    """True for an email service's click counter, like sendgrid.net."""
    return any(host == t or host.endswith("." + t) for t in CLICK_TRACKERS)


# ---------- the checks ----------
# Each check looks for ONE red flag. It returns a finding if it spots
# the flag, or None if the email looks fine on that point.

# Sender authentication. Your mail server records whether three checks passed:
#   SPF:   was the sending server allowed to send for that domain?
#   DKIM:  does the email's digital signature check out?
#   DMARC: does the From address the reader sees match what SPF/DKIM proved?
# DMARC passing settles who sent it, so SPF or DKIM hiccups on their own
# (common with forwarding and mailing lists) aren't counted then.

def check_spf(parsed, found):
    auth = parsed["auth"]
    if auth["dmarc"] == "pass":
        return None
    if auth["spf"] == "fail":
        return finding("spf_fail", 3, "SPF failed: the sending server isn't allowed to send for this domain")
    if auth["spf"] in ("softfail", "none", "neutral", "temperror", "permerror"):
        return finding("spf_weak", 1, f"SPF is missing or inconclusive (spf={auth['spf']})")
    return None


def check_dkim_dmarc(parsed, found):
    auth = parsed["auth"]
    if auth["dmarc"] == "fail":
        sender = domain_of(parsed["from"]) or "the sender's domain"
        return finding("dmarc_fail", 4,
                       f"DMARC failed: the email claims to be from {sender}, "
                       f"but {sender} didn't send it (spoofed)")
    if "fail" in auth["dkim"] and "pass" not in auth["dkim"] and auth["dmarc"] != "pass":
        return finding("dkim_fail", 2, "DKIM failed: the email's digital signature doesn't check out")
    return None


def check_compauth(parsed, found):
    # Microsoft's overall verdict, from SPF, DKIM, DMARC and the sender's history.
    # A DMARC failure already counts above, so it isn't counted twice.
    auth = parsed["auth"]
    if auth["compauth"] == "fail" and auth["dmarc"] != "fail":
        return finding("compauth_fail", 2,
                       "Microsoft couldn't confirm who really sent this (compauth=fail)")
    return None


def check_reply_to(parsed, found):
    sender_address = address_of(parsed["from"]) or ""
    reply_address = address_of(parsed["reply_to"])
    if not reply_address or reply_address == sender_address:
        return None
    sender = sender_address.split("@")[-1]
    reply = reply_address.split("@")[-1]
    personal = reply in FREEMAIL
    if not personal and org_domain(reply) == org_domain(sender):
        return None  # news.example.com and example.com are the same organisation

    verified = parsed["auth"]["dmarc"] == "pass"
    if verified and org_domain(sender) in SENDS_FOR_USERS:
        return None  # a Google Calendar invite replies to whoever sent it

    # With DMARC passing, the sender's domain chose where replies go: worth
    # noting, but the classic trick is a forged sender with a reply address
    # the scammer actually reads
    points = 1 if verified else 3
    if personal:
        return finding("reply_to_mismatch", points,
                       f"Replies go to a personal {reply} address, not to {sender or 'the sender'}")
    return finding("reply_to_mismatch", points,
                   f"Reply-To domain {reply} doesn't match sender {sender or '(no valid address)'}")


def check_freemail_org(parsed, found):
    # An organisation's name on a personal webmail account, like a "bank" on Gmail
    sender = domain_of(parsed["from"]) or ""
    if sender not in FREEMAIL:
        return None

    # The display name, or the address itself when there's no name
    name = display_name_of(parsed["from"]) or address_of(parsed["from"]) or ""

    # Real people's names rarely have long numbers, [brackets] or words like "Bank"
    looks_official = (re.search(r"\d{6,}", name)
                      or "[" in name
                      or ORG_WORDS.search(name))
    if looks_official:
        return finding("freemail_org", 3,
                       f"Official-looking sender name, but sent from a personal {sender} account")
    return None


def check_brand_mismatch(parsed, found):
    # A famous brand in the sender's name, but sent from a domain the brand doesn't own.
    # Real brands often send from a subdomain or a country domain (email.amazon.co.uk).
    sender = domain_of(parsed["from"]) or ""
    for brand in claimed_brands(parsed["from"]):
        if not is_official(brand, sender):
            return finding("brand_mismatch", 4,
                           f"The sender calls itself {brand_label(brand)}, "
                           f"but the email came from {sender or 'an unknown domain'}")
    return None


def check_display_name_address(parsed, found):
    # The sender's NAME is an email address, but not the real one:
    # "service@paypal.com" <x@evil.example>. Most apps only show the name.
    name = display_name_of(parsed["from"])
    if " via " in name.lower():
        return None  # "'jane@gmail.com' via Book Club" is how Google Groups names senders
    sender = domain_of(parsed["from"]) or ""
    for shown in EMAIL_PATTERN.findall(name):
        if org_domain(shown.split("@")[-1]) != org_domain(sender):
            return finding("display_name_spoof", 4,
                           f"The sender's name shows {shown}, but the email really came from {sender}")
    return None


def check_spaced_name(parsed, found):
    if SPACED_LETTERS.search(str(parsed["from"] or "")):
        return finding("spaced_name", 3,
                       "Sender name is spaced out letter by letter to dodge filters")
    return None


def check_lookalike_domains(parsed, found):
    # Domains dressed up as a brand's: typos (paypa1.com), or the brand as one
    # word of someone else's domain (paypal-secure-login.com) for the sender
    for host in filter(None, [domain_of(parsed["from"]), domain_of(parsed["reply_to"])]):
        brand = imitated_brand(host) or brand_in_domain(host)
        if brand:
            return finding("lookalike_domain", 4,
                           f"The sender's domain {host} imitates {brand_label(brand)}, but isn't theirs")
    for host in found["domains"]:
        brand = imitated_brand(host)
        if brand:
            return finding("lookalike_domain", 4,
                           f"Link to {host}, a look-alike of {brand_label(brand)}'s domain")
    return None


def check_punycode(parsed, found):
    # International domains are stored as "xn--...". Attackers use them to
    # swap in letters from other alphabets that look identical: аpple.com
    hosts = [domain_of(parsed["from"]), domain_of(parsed["reply_to"])] + found["domains"]
    for host in filter(None, hosts):
        if any(label.startswith("xn--") for label in host.split(".")):
            return finding("punycode_domain", 3,
                           f"{host} uses letters from another alphabet that can look like ordinary ones")
    return None


def check_ip_links(parsed, found):
    ip_links = [url for url in found["urls"] if is_ip(host_of(url) or "")]
    if ip_links:
        return finding("ip_links", 3, f"Email contains links to IP addresses: {', '.join(ip_links)}")
    return None


def check_link_text(parsed, found):
    # The classic trick: the text SHOWS one address, the link GOES to another
    sender_org = org_domain(domain_of(parsed["from"]))
    for href, shown in LINK_PATTERN.findall(parsed["html"]):
        shown = html.unescape(TAG_PATTERN.sub("", shown)).strip()
        if shown.lower().startswith("www."):
            shown = "http://" + shown
        shown_urls = find_urls(shown)
        if not shown_urls:
            continue  # the text isn't an address ("Click here"), nothing to compare
        shown_host = host_of(shown_urls[0])
        real_host = host_of(unwrap_link(html.unescape(href)))
        if not shown_host or not real_host:
            continue
        if org_domain(shown_host) == org_domain(real_host):
            continue  # www.example.com shown, example.com linked: same place
        if org_domain(shown_host) == sender_org and is_tracker(real_host):
            continue  # a company counting clicks on links to its own website
        return finding("link_text_mismatch", 4, f"Link shows {shown_host} but goes to {real_host}")
    return None


def check_shortened_links(parsed, found):
    sender_org = org_domain(domain_of(parsed["from"]))
    for domain in found["domains"]:
        if domain not in SHORTENERS:
            continue
        owners = SHORTENERS[domain]
        if owners and sender_org in owners:
            continue  # t.co in an email from X is X's own shortener
        return finding("link_shortener", 2, f"Links hidden behind a URL shortener ({domain})")
    return None


def check_html_form(parsed, found):
    # Real companies send you to their website to sign in; they don't put
    # a sign-in box inside the email itself
    if PASSWORD_BOX.search(parsed["html"]):
        return finding("html_form", 5, "The email itself has a box for typing a password")
    if FORM.search(parsed["html"]):
        return finding("html_form", 3, "The email contains a form that sends what you type to a website")
    return None


def check_attachments(parsed, found):
    worst = None
    for attachment in parsed["attachments"]:
        original = attachment["filename"]
        name = original.lower().strip()
        parts = name.split(".")
        extension = "." + parts[-1].strip() if len(parts) > 1 else ""

        if RIGHT_TO_LEFT in name:
            result = finding("double_extension", 5,
                             f"{original} uses a hidden character to disguise its real file type")
        elif extension in RISKY_EXTENSIONS and len(parts) > 2:
            result = finding("double_extension", 5,
                             f"{original} pretends to be a document but is a program")
        elif extension in RISKY_EXTENSIONS:
            result = finding("risky_attachment", 4, f"{original} is a file type that runs code")
        elif extension in WEB_PAGE_EXTENSIONS:
            result = finding("web_page_attachment", 3,
                             f"{original} is a web page: it opens in your browser, "
                             f"a favourite way to show a fake sign-in page")
        elif extension in MACRO_EXTENSIONS:
            result = finding("macro_attachment", 3,
                             f"{original} is an Office file that can contain macros (hidden programs)")
        else:
            continue
        if worst is None or result["points"] > worst["points"]:
            worst = result
    return worst


def check_empty_body(parsed, found):
    # Remove invisible characters, then see what a reader would actually see
    text = parsed["body"] + parsed["html_text"]
    visible = "".join(ch for ch in text if ch not in INVISIBLE_CHARS).strip()
    if len(visible) < 20 and parsed["attachments"]:
        return finding("empty_body_attachment", 3,
                       "The body is (almost) empty: the real message is in the attachment")
    return None


def check_invisible_chars(parsed, found):
    text = " ".join([str(parsed["subject"] or ""), str(parsed["from"] or ""),
                     parsed["body"], parsed["html_text"]])
    count = len(HIDDEN_IN_WORD.findall(text)) + len(DISGUISE_MARK.findall(text))
    if count:
        return finding("invisible_chars", 3,
                       f"Hidden or disguising characters inside words ({count})")
    return None


def check_urgency(parsed, found):
    # Subject, plain text AND the words of the HTML: most phishing is HTML only
    text = " ".join([str(parsed["subject"] or ""), parsed["body"], parsed["html_text"]]).lower()
    hits = [pattern for pattern in RISKY_PATTERNS if pattern.search(text)]
    # One urgent phrase happens in normal email; several together is pressure
    if len(hits) >= 4:
        return finding("urgent_language", 3, f"Heavy pressure language ({len(hits)} phrases)")
    if len(hits) >= 2:
        return finding("urgent_language", 2, f"Pressure language ({len(hits)} phrases)")
    return None


# Every check in one list, so run_checks() can loop through them
CHECKS = [check_spf, check_dkim_dmarc, check_compauth, check_reply_to, check_freemail_org,
          check_brand_mismatch, check_display_name_address, check_spaced_name,
          check_lookalike_domains, check_punycode, check_ip_links, check_link_text,
          check_shortened_links, check_html_form, check_attachments, check_empty_body,
          check_invisible_chars, check_urgency]


def run_checks(parsed, found):
    """Run every check and return the list of red flags found."""
    findings = []
    for check in CHECKS:
        result = check(parsed, found)
        if result:
            findings.append(result)
    return findings


def good_signs(parsed, found):
    """Things that check out, to show alongside the red flags.

    They never take points away: a scammer who registers their own domain
    can pass every one of these. They prove WHO sent an email, not that
    the sender is honest.
    """
    signs = []
    auth = parsed["auth"]
    sender = domain_of(parsed["from"])
    if auth["dmarc"] == "pass" and sender:
        signs.append(f"DMARC passed: this email really came from {sender}")
        for brand in claimed_brands(parsed["from"]):
            if is_official(brand, sender):
                signs.append(f"{sender} really belongs to {brand_label(brand)}")
    elif auth["spf"] == "pass" and "pass" in auth["dkim"]:
        signs.append("SPF and DKIM passed")
    if parsed["auth_results"] is None:
        signs.append("No authentication results in this email, so the sender couldn't be checked. "
                     "Was it forwarded or exported without its headers?")
    return signs
