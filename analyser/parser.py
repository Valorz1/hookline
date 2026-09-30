from email import policy
from email.parser import BytesParser


def read_email(path):
    """Read and parse an email file.

    Args:
        path (str or Path): The path to the .eml file.

    Returns:
        dict: The email's headers, plain text body and HTML body.
    """
    # Read as raw bytes and let the parser work out the encoding,
    # because emails can be written in any language or character set.
    with open(path, "rb") as file:
        msg = BytesParser(policy=policy.default).parse(file)

    # Keep both body versions: phishing links often hide in the HTML.
    # get_body() returns None if that version doesn't exist.
    plain_part = msg.get_body(preferencelist=("plain",))
    html_part = msg.get_body(preferencelist=("html",))

    return {
        "subject": msg["subject"],
        "from": msg["from"],
        "reply_to": msg["reply-to"],
        "to": msg["to"],
        "date": msg["date"],
        "auth_results": msg["authentication-results"],
        "body": plain_part.get_content() if plain_part else "",
        "html": html_part.get_content() if html_part else "",
    }