import html
import re
from urllib.parse import parse_qs, urlparse

from analyser.domains import is_ip

# http:// or https:// followed by anything that isn't a space, quote or angle bracket
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")

# Four groups of 1-3 digits separated by dots, e.g. 192.168.1.10
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Something like name@domain.com
EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def find_urls(text):
    """Find every link in a piece of text."""
    urls = URL_PATTERN.findall(text)
    # Phishing emails often have punctuation after the URL, e.g. "Click here: https://example.com."
    # The ) matters too: in HTML, links often sit inside CSS like url(https://...)
    return [unwrap_link(html.unescape(url).rstrip(".,;:!?)")) for url in urls]


def host_of(url):
    """The host name in a link, lowercased, or None for a broken link like http://[oops."""
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def unwrap_link(url):
    """The real destination of a link that's been wrapped by a mail provider.

    Outlook (Safe Links) and Google rewrite links so a click goes through
    their checker first. The real address is kept inside the link, so take it
    back out: otherwise every link would look like it goes to outlook.com.
    """
    host = host_of(url) or ""
    parts = urlparse(url)
    wrapped = (host.endswith("safelinks.protection.outlook.com")
               or (host in {"www.google.com", "google.com"} and parts.path == "/url"))
    if wrapped:
        query = parse_qs(parts.query)
        for key in ("url", "q"):
            if query.get(key, [""])[0].startswith(("http://", "https://")):
                return query[key][0]
    return url


def extract_observables(parsed):
    """Pull links, IPs, domains and email addresses out of a parsed email."""
    text = parsed["body"] + "\n" + parsed["html"]
    headers = " ".join(str(parsed[key])
                       for key in ("subject", "from", "reply_to", "auth_results")
                       if parsed[key])

    # Sets ignore duplicates - the same link usually appears in both
    # the plain text and the HTML version of an email
    urls = set(find_urls(text) + find_urls(headers))
    domains = set()
    ips = set()

    # Split each link into its host: either a domain or a raw IP address
    for url in urls:
        host = host_of(url)
        if not host:
            continue
        if is_ip(host):
            ips.add(host)
        else:
            domains.add(host)

    # Also catch IP addresses written in the text without a link
    for match in IP_PATTERN.findall(text):
        if is_ip(match):
            ips.add(match)

    # Email addresses from the body and the sender-side headers.
    # Remove links first: things like facebook@2x.png inside image URLs
    # look like email addresses but are really filenames
    text_without_urls = URL_PATTERN.sub(" ", text + " " + headers)
    emails = set(EMAIL_PATTERN.findall(text_without_urls))
    for address in emails:
        domains.add(address.split("@")[1].lower())

    return {
        "urls": sorted(urls),
        "domains": sorted(domains),
        "ips": sorted(ips),
        "emails": sorted(emails),
    }
