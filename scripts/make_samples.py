"""
make_samples.py - generate fake test emails for HookLine.

Usage (from the project folder):
    python -m scripts.make_samples

Creates 30 phishing and 30 safe emails in samples/fake/.
Every company, person and domain here is made up, and the
"attachments" are harmless text. Nothing in these emails is dangerous or real.
The samples are for testing purposes only.
"""

import random
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples" / "fake"
COUNT = 30  # emails of each kind

# Seeding makes the "random" choices identical every run, so the samples
# never change and test results stay comparable.
random.seed(42)

MY_DOMAIN = "hookline-test.example"  # the pretend company receiving the emails

FIRST_NAMES = ["Alex", "Sam", "Priya", "Jordan", "Aisha", "Tom", "Mei", "Omar", "Lucy", "Dan"]
BANKS = [("Northwind Bank", "northwindbank.com"), ("Woodgrove Bank", "woodgrovebank.com")]


# ===== helper functions =====

def make_recipient():
    name = random.choice(FIRST_NAMES)
    to = f"{name} <{name.lower()}@{MY_DOMAIN}>"
    return name, to


def random_date():
    start = datetime(2026, 9, 1, tzinfo=timezone.utc)
    return start + timedelta(days=random.randint(0, 28), minutes=random.randint(0, 1439))


def build(to, sender, subject, text, html=None, reply_to=None,
          spf="pass", dkim="pass", attachment=None):
    """Assemble an email message from the given parts."""
    # '"Name" <user@domain.com>'  ->  'domain.com'
    sender_domain = sender.split("@")[-1].rstrip(">")

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = format_datetime(random_date())
    msg["Message-ID"] = make_msgid(domain=sender_domain)
    # The receiving mail server records whether SPF/DKIM checks passed
    msg["Authentication-Results"] = (
        f"mx.{MY_DOMAIN}; spf={spf} smtp.mailfrom={sender_domain}; dkim={dkim}"
    )
    if reply_to:
        msg["Reply-To"] = reply_to

    # These run for EVERY email, so they sit at the same level as the if above
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    if attachment:
        filename, data = attachment
        msg.add_attachment(data, maintype="application",
                           subtype="octet-stream", filename=filename)
    return msg


# ---------- phishing templates ----------
# Each one returns the parts of an email. The comment says which
# red flags it contains, so you know what HookLine should catch.

def phish_account_limited(name):
    # Red flags: lookalike domain, Reply-To mismatch, SPF fail, urgency
    brand, real = random.choice(BANKS)
    fake = real.replace(".com", "-secure-login.com")
    link = f"http://{fake}/verify?id={random.randint(10000, 99999)}"
    return dict(
        sender=f'"{brand} Security" <alerts@{fake}>',
        subject=random.choice(["Your account has been limited",
                               "Unusual sign-in activity detected",
                               "Action required: verify your account"]),
        text=(f"Dear customer,\n\nWe noticed unusual activity on your account "
              f"and have limited access.\n\nVerify your identity within 24 hours:\n"
              f"{link}\n\nIf you do not verify, your account will be closed.\n\n"
              f"{brand} Security Team"),
        reply_to=f"help-desk@account-recovery-{random.randint(10, 99)}.net",
        spf="fail", dkim="none",
    )


def phish_parcel_fee(name):
    # Red flags: link to a raw IP address, unusual TLD, small payment request
    ip = ".".join(str(random.randint(11, 220)) for _ in range(4))
    fee = random.choice(["1.99", "2.49", "2.99", "3.49"])
    ref = random.randint(100000, 999999)
    return dict(
        sender=f'"Fabrikam Parcel" <noreply@fabrikam-delivery-{random.randint(1, 9)}.top>',
        subject=f"Your parcel is on hold - unpaid fee of £{fee}",
        text=(f"Hello {name},\n\nYour parcel #{ref} could not be delivered because "
              f"a customs fee of £{fee} is unpaid.\n\nPay now to rebook delivery:\n"
              f"http://{ip}/pay?parcel={ref}\n\nUnpaid parcels are returned after 48 hours."),
        spf="softfail", dkim="none",
    )


def phish_password_expiry(name):
    # Red flags: link text shows one address but actually goes to another.
    # SPF and DKIM PASS here - the attacker owns their domain. Passing
    # checks does not mean an email is safe!
    shown = f"https://login.{MY_DOMAIN}"
    real = "http://mailbox-admin-portal.com/login"
    return dict(
        sender='"IT Helpdesk" <it-support@mailbox-admin-portal.com>',
        subject="Your password expires today",
        text=(f"Hi {name},\n\nYour mailbox password expires today. "
              f"Keep your current password here:\n{real}\n\nIT Helpdesk"),
        html=(f"<p>Hi {name},</p><p>Your mailbox password expires today.</p>"
              f'<p><a href="{real}">{shown}</a></p><p>IT Helpdesk</p>'),
        spf="pass", dkim="pass",
    )


def phish_invoice(name):
    # Red flags: double file extension (.pdf.exe), no SPF/DKIM, unknown sender
    num = random.randint(1000, 9999)
    return dict(
        sender=f'"Accounts Department" <accounts@litware-billing-{random.randint(1, 99)}.biz>',
        subject=f"Overdue invoice #{num}",
        text=(f"Hello,\n\nPlease find attached overdue invoice #{num}. "
              f"Payment is required today to avoid late charges.\n\nAccounts"),
        attachment=(f"Invoice_{num}.pdf.exe", b"HookLine test file - harmless placeholder."),
        spf="none", dkim="none",
    )


def phish_prize(name):
    # Red flags: too good to be true, reply to a free webmail address
    return dict(
        sender='"Tailspin Rewards" <rewards@tailspin-prizes.win>',
        subject="Congratulations! You have won 2 free flights",
        text=(f"Dear {name},\n\nYou have been selected to win two return flights!\n\n"
              f"To claim, reply with your full name, address and date of birth.\n\n"
              f"Tailspin Rewards"),
        reply_to=f"claims.office{random.randint(10, 99)}@freemail.example",
        spf="softfail", dkim="none",
    )


def phish_ceo_giftcard(name):
    # Red flags: display name of the boss but an outside address, secrecy,
    # urgency, gift cards. No link at all - the "attack" is the reply.
    return dict(
        sender='"Sarah Whitfield" <sarah.whitfield.office@freemail.example>',
        subject="Quick favour",
        text=(f"Hi {name},\n\nAre you at your desk? I need you to buy 5 gift cards "
              f"(£100 each) for a client today. Keep this between us for now, "
              f"it's a surprise. Send me the codes once you have them.\n\n"
              f"Sarah Whitfield\nCEO"),
        spf="pass", dkim="pass",
    )


#=====Safe email templates=====
def safe_newsletter(name):
    return dict(
        sender='"Contoso" <news@contoso.com>',
        subject="What's new at Contoso this month",
        text=(f"Hi {name},\n\nHere's our monthly roundup.\n\n"
              f"Read more: https://contoso.com/blog/september\n\n"
              f"Unsubscribe: https://contoso.com/unsubscribe"),
        html=(f"<p>Hi {name},</p><p>Here's our monthly roundup.</p>"
              f'<p><a href="https://contoso.com/blog/september">Read more</a></p>'
              f'<p><a href="https://contoso.com/unsubscribe">Unsubscribe</a></p>'),
    )


def safe_order(name):
    order = random.randint(100000, 999999)
    total = f"{random.randint(10, 150)}.{random.randint(0, 99):02d}"
    return dict(
        sender='"Fabrikam Store" <orders@fabrikam.com>',
        subject=f"Order #{order} confirmed",
        text=(f"Hi {name},\n\nThanks for your order #{order}. Total: £{total}.\n\n"
              f"Track it here: https://fabrikam.com/orders/{order}\n\nFabrikam Store"),
    )


def safe_meeting(name):
    day = random.choice(["Monday", "Tuesday", "Wednesday", "Thursday"])
    return dict(
        sender=f'"Priya Shah" <priya.shah@{MY_DOMAIN}>',
        subject=f"Notes from {day}'s meeting",
        text=(f"Hi {name},\n\nThanks for joining on {day}. Notes are in the shared "
              f"folder as usual. Next catch-up is same time next week.\n\nPriya"),
    )


def safe_password_changed(name):
    # A real security notice. It mentions passwords but has no link and
    # asks for nothing - a good test that HookLine isn't too jumpy.
    return dict(
        sender='"Woodgrove Bank" <no-reply@woodgrovebank.com>',
        subject="Your password was changed",
        text=(f"Hello {name},\n\nThe password for your online banking was changed. "
              f"If this wasn't you, call the number on the back of your card.\n\n"
              f"Woodgrove Bank"),
    )


def safe_flight(name):
    ref = "".join(random.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(6))
    return dict(
        sender='"Tailspin Airlines" <bookings@tailspinair.com>',
        subject=f"Booking confirmed: {ref}",
        text=(f"Dear {name},\n\nYour booking {ref} is confirmed.\n\n"
              f"Manage your booking: https://tailspinair.com/manage/{ref}\n\n"
              f"Tailspin Airlines"),
    )


PHISH = [phish_account_limited, phish_parcel_fee, phish_password_expiry,
         phish_invoice, phish_prize, phish_ceo_giftcard]
SAFE = [safe_newsletter, safe_order, safe_meeting, safe_password_changed, safe_flight]


#=====main=====
def main():
    OUT.mkdir(parents=True, exist_ok=True)

    for kind, templates in [("phish", PHISH), ("safe", SAFE)]:
        for i in range(1, COUNT + 1):
            # Cycle through the templates so each type appears evenly
            template = templates[(i - 1) % len(templates)]
            name, to = make_recipient()
            msg = build(to=to, **template(name))

            # e.g. phish_07_account_limited.eml
            label = template.__name__.split("_", 1)[1]
            path = OUT / f"{kind}_{i:02d}_{label}.eml"
            path.write_bytes(msg.as_bytes())

    print(f"Created {COUNT * 2} emails in {OUT}")


if __name__ == "__main__":
    main()
