"""
inbox.py - check a reporting inbox for forwarded suspicious emails.

People forward a suspicious email AS AN ATTACHMENT to a dedicated inbox.
This script reads the unread reports, pulls out the attached email,
and runs it through the same analysis as main.py and the web page.

Usage:
    python inbox.py            look at unread reports, leave them unread
    python inbox.py --mark     also mark them as read once analysed
"""

import imaplib
import os
import sys
from email import policy
from email.parser import BytesParser

from dotenv import load_dotenv

from analyser.parser import parse_email_bytes
from analyser.pipeline import analyse

from pathlib import Path

from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow


load_dotenv()
IMAP_HOST = os.getenv("IMAP_HOST", "imap.gmail.com")
IMAP_USER = os.getenv("IMAP_USER")
IMAP_PASSWORD = os.getenv("IMAP_PASSWORD")

# OAuth: Google's sign-in page gives us a token, so no password is stored
SCOPES = ["https://mail.google.com/"]
CREDENTIALS_FILE = Path("credentials.json")  # identifies the HookLine app to Google
TOKEN_FILE = Path("token.json")              # the saved token; never commit this


def attached_emails(report):
    """Return the raw bytes of every email attached to a report.

    Forwarded "as attachment", the original email arrives as a part of type
    message/rfc822 with all its headers intact. Some mail apps instead attach
    it as a plain file ending in .eml, so we accept that too.
    """
    found = []
    for part in report.iter_attachments():
        if part.get_content_type() == "message/rfc822":
            found.append(part.get_content().as_bytes())
        elif (part.get_filename() or "").lower().endswith(".eml"):
            found.append(part.get_payload(decode=True))
    return found


def fetch_unread():
    """Download every unread message in the inbox, without marking it read.

    Returns a list of (message number, raw bytes) pairs.
    """
    messages = []
    with imaplib.IMAP4_SSL(IMAP_HOST) as imap:
        sign_in(imap)
        imap.select("INBOX")
        _, data = imap.search(None, "UNSEEN")
        for number in data[0].split():
            # BODY.PEEK[] downloads the whole message WITHOUT marking it as read
            _, msg_data = imap.fetch(number, "(BODY.PEEK[])")
            messages.append((number, msg_data[0][1]))
    return messages

def get_access_token():
    """Return a valid OAuth token, signing in through the browser if needed."""
    creds = None
    if TOKEN_FILE.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)

    if creds and creds.valid:
        return creds.token

    # Tokens only last about an hour, but a "refresh token" can get a new one
    # without asking you again
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
        except RefreshError:
            # In Testing mode Google expires refresh tokens after 7 days
            creds = None

    if not creds or not creds.valid:
        # Opens Google's sign-in page in your browser
        flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_FILE), SCOPES)
        creds = flow.run_local_server(port=0)

    TOKEN_FILE.write_text(creds.to_json())
    return creds.token


def sign_in(imap):
    """Sign in with OAuth if credentials.json exists, otherwise the app password."""
    if CREDENTIALS_FILE.exists():
        token = get_access_token()
        # XOAUTH2 is Gmail's format for signing in to IMAP with a token
        auth_string = f"user={IMAP_USER}\x01auth=Bearer {token}\x01\x01"
        imap.authenticate("XOAUTH2", lambda _: auth_string.encode())
    else:
        imap.login(IMAP_USER, IMAP_PASSWORD)


def mark_read(numbers):
    """Mark messages as read, so they aren't analysed again next time."""
    with imaplib.IMAP4_SSL(IMAP_HOST) as imap:
        sign_in(imap)
        imap.select("INBOX")
        for number in numbers:
            imap.store(number, "+FLAGS", "\\Seen")


def main():
    if not IMAP_USER or not (CREDENTIALS_FILE.exists() or IMAP_PASSWORD):
        print("Add IMAP_USER to .env, plus credentials.json or IMAP_PASSWORD.")
        return

    try:
        messages = fetch_unread()
    except imaplib.IMAP4.error as error:
        # Wrong address, wrong app password, or the account blocks IMAP sign-in
        print(f"Couldn't sign in to {IMAP_HOST} as {IMAP_USER}: {error}")
        return
    except OSError as error:
        # No internet, or the server name is wrong
        print(f"Couldn't reach {IMAP_HOST}: {error}")
        return

    print(f"{len(messages)} unread report(s) in {IMAP_USER}\n")

    done = []
    for number, raw in messages:
        report = BytesParser(policy=policy.default).parsebytes(raw)
        print(f"Report from {report['from']}: {report['subject']}")

        emails = attached_emails(report)
        if not emails:
            print("   No attached email found. Ask the reporter to forward it as an attachment.\n")
            continue

        for email_bytes in emails:
            parsed = parse_email_bytes(email_bytes)
            outcome = analyse(parsed)["outcome"]
            print(f"   {outcome['verdict'].upper():<11} ({outcome['score']} points)  {parsed['subject']}")
            for reason in outcome["reasons"][:3]:
                print(f"      - {reason['detail']}")
        print()
        done.append(number)

    if "--mark" in sys.argv and done:
        mark_read(done)
        print(f"Marked {len(done)} report(s) as read.")


if __name__ == "__main__":
    main()