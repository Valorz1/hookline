"""Test emails built in code, so each test shows exactly what's in its email.

The headers copy what real mail servers write. GMAIL_AUTH is the
Authentication-Results line Gmail adds to every email it receives, which
is what you get when you download a message from Gmail.
"""

from email.message import EmailMessage

from analyser.parser import parse_email_bytes
from analyser.pipeline import analyse

GMAIL_AUTH = ("mx.google.com; dkim=pass header.i=@{domain} header.s=s1 header.b=Abc123; "
              "spf=pass (google.com: domain of bounce@{domain} designates 192.0.2.1 as "
              "permitted sender) smtp.mailfrom=bounce@{domain}; "
              "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from={domain}")


def passing(domain):
    """An Authentication-Results header where SPF, DKIM and DMARC all passed."""
    return GMAIL_AUTH.format(domain=domain)


def build(sender, subject="Hello", text="Hi, see you on Thursday. Thanks, Sam",
          html=None, reply_to=None, auth=None, attachments=()):
    """Assemble an email and return its raw bytes, like a downloaded .eml file."""
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = "you@example.org"
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    if auth is not None:
        msg["Authentication-Results"] = auth
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    for filename, data in attachments:
        msg.add_attachment(data, maintype="application", subtype="octet-stream",
                           filename=filename)
    return msg.as_bytes()


def run(raw):
    """Analyse raw email bytes; returns (verdict, score, names of the checks that fired)."""
    result = analyse(parse_email_bytes(raw))
    outcome = result["outcome"]
    return outcome["verdict"], outcome["score"], [f["check"] for f in result["findings"]]


# ---------- ordinary emails that should come out Safe ----------
# Each one tripped at least one check before the checks were made more precise.

LEGIT = {
    # Amazon sends from amazon.co.uk in the UK, not amazon.com
    "amazon_uk_order": build(
        '"Amazon.co.uk" <auto-confirm@amazon.co.uk>', "Your Amazon.co.uk order #204-1234567",
        "Hello, thanks for your order. We'll let you know when it has dispatched.",
        auth=passing("amazon.co.uk")),

    # Marketing: Reply-To on the main domain, a sale "within 24 hours", and the
    # visible www address linking through the company's own click tracker
    "marketing_newsletter": build(
        '"Contoso Outdoors" <news@email.contoso-outdoors.com>', "Limited time: 30% off tents",
        "Our biggest sale is here. Limited stock, ends in 24 hours. Shop now at www.contoso-outdoors.com",
        html=('<p>Our biggest sale is here. Limited stock, ends in 24 hours.</p>'
              '<p><a href="https://click.email.contoso-outdoors.com/?qs=8f3a">www.contoso-outdoors.com</a></p>'
              '<p><a href="https://contoso.us12.list-manage.com/track/click?u=1&id=2">'
              'https://contoso-outdoors.com/tents</a></p>'),
        reply_to="help@contoso-outdoors.com", auth=passing("email.contoso-outdoors.com")),

    # Google Calendar invites come from google.com but reply to the organiser
    "calendar_invite": build(
        '"Priya Shah (Google Calendar)" <calendar-notification@google.com>',
        "Invitation: Project catch-up @ Thu 2pm",
        "Priya Shah has invited you to an event. Reply for priya.shah.1990@gmail.com",
        reply_to="priya.shah.1990@gmail.com", auth=passing("google.com")),

    # Outlook rewrites every link through Safe Links; the real address is inside
    "outlook_safelinks": build(
        '"BBC News" <newsletters@bbc.co.uk>', "Your morning briefing",
        "Today's top stories.",
        html=('<p><a href="https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2F'
              'www.bbc.co.uk%2Fnews&amp;data=05%7C01&amp;reserved=0">https://www.bbc.co.uk/news</a></p>'),
        auth=("spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=bbc.co.uk; dkim=pass (signature "
              "was verified) header.d=bbc.co.uk;dmarc=pass action=none header.from=bbc.co.uk;"
              "compauth=pass reason=100")),

    # Two DKIM signatures, the email service's one broken; DMARC still passed
    "second_dkim_signature_failed": build(
        '"Fabrikam" <orders@fabrikam.com>', "Order 1042 confirmed", "Thanks for your order.",
        auth=("mx.google.com; dkim=pass header.i=@fabrikam.com; dkim=fail header.i=@esp.example; "
              "spf=pass smtp.mailfrom=fabrikam.com; dmarc=pass header.from=fabrikam.com")),

    # Emoji with a joiner (🤸‍♂️), invisible padding in the preview text, and
    # X's own t.co links
    "social_with_emoji": build(
        '"X" <info@x.com>', "Trending for you 🤸‍♂️",
        "Trending now ‌ ‌ ‌ ‌ See what's happening: https://t.co/abc123",
        auth=passing("x.com")),

    # "Apple" inside a longer name isn't Apple
    "applebees": build(
        '"Applebee\'s" <offers@applebees.com>', "A treat for you", "Here's a voucher for your next visit.",
        auth=passing("applebees.com")),

    # A real security alert: unrecognised activity, but nothing else wrong
    "security_alert": build(
        '"Google" <no-reply@accounts.google.com>', "Security alert",
        "A new sign-in on Windows. If you don't recognize this activity, check your account. "
        "You received this email to let you know about important changes.",
        auth=passing("accounts.google.com")),

    # Small business emailing from Gmail with an ordinary name
    "friend_on_gmail": build(
        '"Tom Baker" <tom.baker.1987@gmail.com>', "Photos from Saturday",
        "Hi! Here are the photos from Saturday. Speak soon, Tom",
        auth=passing("gmail.com")),
}
