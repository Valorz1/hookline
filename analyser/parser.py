import hashlib
from email import policy
from email.parser import BytesParser


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

    return {
        "subject": msg["subject"],
        "from": msg["from"],
        "reply_to": msg["reply-to"],
        "to": msg["to"],
        "date": msg["date"],
        "auth_results": msg["authentication-results"],
        "body": plain_part.get_content() if plain_part else "",
        "html": html_part.get_content() if html_part else "",
        "attachments": attachments,
    }