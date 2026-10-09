import hashlib
import html
import re
from email import policy
from email.parser import BytesParser

# Whole blocks whose contents a reader never sees. Not <head>: phishing HTML
# is often broken on purpose, with the whole body inside the head, and
# browsers show it anyway.
HIDDEN_BLOCKS = re.compile(r"<(style|script|title)\b.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
COMMENTS = re.compile(r"<!--.*?-->", re.DOTALL)
TAGS = re.compile(r"<[^>]+>")

# One result in an Authentication-Results header, like "dkim=pass"
AUTH_RESULT = re.compile(r"\b(spf|dkim|dmarc|compauth)\s*=\s*([a-z]+)", re.IGNORECASE)
# The comments in brackets, like "(google.com: domain of x designates y)"
AUTH_COMMENT = re.compile(r"\([^()]*\)")


def read_email(path):
    """Read a .eml file from disk and return its key parts as a dictionary.

    Args:
        path (str or Path): The path to the .eml file.

    Returns:
        dict: The email's headers, plain text body, HTML body and attachments.
    """
    with open(path, "rb") as file:
        return parse_email_bytes(file.read())


def parse_email_bytes(data):
    """Parse an email that's already in memory, like a file uploaded to the web page.

    Args:
        data (bytes): The raw contents of a .eml file.

    Returns:
        dict: The email's headers, plain text body, HTML body and attachments.
    """
    # Raw bytes, so the parser can work out the encoding itself
    msg = BytesParser(policy=policy.default).parsebytes(data)

    # Keep both body versions: phishing links often hide in the HTML.
    # get_body() returns None if that version doesn't exist.
    plain_part = msg.get_body(preferencelist=("plain",))
    html_part = msg.get_body(preferencelist=("html",))
    body = text_of(plain_part)
    html_body = text_of(html_part)

    # List attachments without opening or saving them. The SHA-256 hash
    # lets us look a file up on VirusTotal without uploading it.
    attachments = []
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        attachments.append({
            "filename": part.get_filename() or "(no name)",
            "content_type": part.get_content_type(),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })

    # The top Authentication-Results header is the one added by YOUR mail
    # server. Lower ones were added on the way, or faked by the sender.
    auth_header = msg["authentication-results"]

    return {
        "subject": msg["subject"],
        "from": msg["from"],
        "reply_to": msg["reply-to"],
        "return_path": msg["return-path"],
        "to": msg["to"],
        "date": msg["date"],
        "auth_results": auth_header,
        "auth": parse_auth_results(auth_header),
        "body": body,
        "html": html_body,
        "html_text": html_to_text(html_body),
        "attachments": attachments,
    }


def text_of(part):
    """The text of one body part, even when its declared encoding is wrong."""
    if part is None:
        return ""
    try:
        return part.get_content()
    except (LookupError, UnicodeError, ValueError, AssertionError):
        # An unknown charset like "x-unknown" or broken bytes: phishing emails
        # are often malformed on purpose. Decode what we can, mark the rest.
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def html_to_text(html_body):
    """The words a reader would actually see in an HTML email."""
    text = HIDDEN_BLOCKS.sub(" ", html_body)
    text = COMMENTS.sub(" ", text)
    text = TAGS.sub(" ", text)
    # &amp; -> &, &nbsp; -> a space, &#8203; -> the character itself
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def parse_auth_results(header):
    """Turn an Authentication-Results header into a dictionary.

    'mx.google.com; dkim=pass header.i=@x.com; spf=pass (...) smtp.mailfrom=x.com;
    dmarc=pass (p=REJECT) header.from=x.com'
    -> {"spf": "pass", "dkim": ["pass"], "dmarc": "pass", "compauth": None}

    DKIM is a list because an email can carry several signatures. compauth is
    Microsoft's own overall verdict, only present in Outlook and Hotmail emails.
    A value is None when the header doesn't mention that check at all.
    """
    results = {"spf": None, "dkim": [], "dmarc": None, "compauth": None}
    text = AUTH_COMMENT.sub(" ", str(header or ""))
    for name, value in AUTH_RESULT.findall(text):
        name, value = name.lower(), value.lower()
        if name == "dkim":
            results["dkim"].append(value)
        elif results[name] is None:
            results[name] = value
    return results
