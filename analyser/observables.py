import ipaddress # 
import re 
from urllib.parse import urlparse 

# http:// or https:// followed by anything that isn't a space, quote or angle bracket
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")

# Four groups of 1-3 digits separated by dots, e.g. 192.168.1.10
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Something like name@domain.com
EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

def is_ip(value):
    """Return True if value is a real IP address (each part 0-255)."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def find_urls(text):
    """Find every link in a piece of text."""
    urls = URL_PATTERN.findall(text)
# This part is important because phishing emails often have punctuation after the URL, e.g. "Click here: https://example.com."
# The ) matters too: in HTML, links often sit inside CSS like url(https://...)
    return [url.rstrip(".,;:!?)") for url in urls]



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
        host = urlparse(url).hostname
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