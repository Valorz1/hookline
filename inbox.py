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

from analyser.checks import run_checks
from analyser.observables import extract_observables
from analyser.parser import parse_email_bytes
from analyser.verdict import decide

load_dotenv()
IMAP_HOST = os.getenv("IMAP_HOST", "imap.gmail.com")
IMAP_USER = os.getenv("IMAP_USER")
IMAP_PASSWORD = os.getenv("IMAP_PASSWORD")


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
        imap.login(IMAP_USER, IMAP_PASSWORD)
        imap.select("INBOX")
        _, data = imap.search(None, "UNSEEN")
        for number in data[0].split():
            # BODY.PEEK[] downloads the whole message WITHOUT marking it as read
            _, msg_data = imap.fetch(number, "(BODY.PEEK[])")
            messages.append((number, msg_data[0][1]))
    return messages


def mark_read(numbers):
    """Mark messages as read, so they aren't analysed again next time."""
    with imaplib.IMAP4_SSL(IMAP_HOST) as imap:
        imap.login(IMAP_USER, IMAP_PASSWORD)
        imap.select("INBOX")
        for number in numbers:
            imap.store(number, "+FLAGS", "\\Seen")


def analyse(raw):
    """The same pipeline as main.py, without VirusTotal to keep it quick."""
    parsed = parse_email_bytes(raw)
    found = extract_observables(parsed)
    outcome = decide(run_checks(parsed, found))
    return parsed, outcome


def main():
    if not IMAP_USER or not IMAP_PASSWORD:
        print("Add IMAP_USER and IMAP_PASSWORD to your .env file first.")
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
            parsed, outcome = analyse(email_bytes)
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