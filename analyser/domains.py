"""What HookLine knows about domains: webmail, famous brands, link shorteners.

Kept apart from the checks so the lists are easy to find and extend, and so
virustotal.py can use them without importing the checks.
"""

import ipaddress
import re
import unicodedata
from email.utils import getaddresses

# Free personal email services. Real organisations don't send from these.
FREEMAIL = {"gmail.com", "googlemail.com", "hotmail.com", "hotmail.co.uk", "outlook.com",
            "live.com", "msn.com", "yahoo.com", "yahoo.co.uk", "ymail.com", "icloud.com",
            "me.com", "aol.com", "gmx.com", "gmx.de", "mail.com", "proton.me",
            "protonmail.com", "zoho.com", "yandex.com", "yandex.ru", "mail.ru"}

# Endings where the organisation's name sits one label further left: in
# "mail.amazon.co.uk" the organisation is amazon.co.uk, not co.uk. The full
# list (the Public Suffix List) has thousands; these cover most email.
TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "nhs.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz",
    "co.za", "co.in", "net.in", "org.in", "gov.in", "co.jp", "ne.jp", "or.jp", "co.kr",
    "com.br", "net.br", "org.br", "gov.br", "com.mx", "com.ar", "com.co", "com.tr",
    "com.cn", "com.hk", "com.sg", "com.my", "com.ph", "com.pk", "com.ng", "com.eg",
    "com.sa", "co.il", "co.id", "co.th", "or.th", "ac.th", "in.th", "go.th", "com.fj",
}

# Famous brands phishing pretends to be, and the domains they really send from.
# A sender also counts as the brand when its organisation's name IS the brand,
# whatever the ending: amazon.co.uk, paypal.de, hmrc.gov.uk.
# Leave out names that are everyday words or surnames (Chase, Norton, Outlook):
# they'd flag ordinary emails.
BRANDS = {
    "amazon": {"amazon.com", "media-amazon.com"},
    "apple": {"apple.com", "icloud.com", "itunes.com"},
    "icloud": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "office365.com",
                  "microsoft365.com", "sharepointonline.com", "azure.com", "xbox.com"},
    "office 365": {"microsoft.com", "microsoftonline.com", "office.com", "office365.com"},
    "microsoft 365": {"microsoft.com", "microsoftonline.com", "office.com", "microsoft365.com"},
    "onedrive": {"microsoft.com", "microsoftonline.com", "onedrive.com", "sharepointonline.com"},
    "sharepoint": {"microsoft.com", "sharepointonline.com", "sharepoint.com"},
    "google": {"google.com", "youtube.com"},
    "paypal": {"paypal.com"},
    "netflix": {"netflix.com"},
    "ebay": {"ebay.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com", "facebookmail.com", "meta.com"},
    "whatsapp": {"whatsapp.com", "facebookmail.com", "meta.com"},
    "linkedin": {"linkedin.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "adobe": {"adobe.com"},
    "dhl": {"dhl.com", "dhlparcel.co.uk", "dpdhl.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "royal mail": {"royalmail.com"},
    "evri": {"evri.com"},
    "hmrc": {"hmrc.gov.uk"},
    "costco": {"costco.com"},
    "walmart": {"walmart.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "metamask": {"metamask.io"},
    "coindesk": {"coindesk.com"},
    "wells fargo": {"wellsfargo.com", "wf.com"},
    "bank of america": {"bankofamerica.com", "bofa.com"},
    "american express": {"americanexpress.com", "aexp.com"},
    "hsbc": {"hsbc.com"},
    "barclays": {"barclays.com", "barclaycard.co.uk"},
    "lloyds bank": {"lloydsbank.com", "lloydsbank.co.uk"},
    "natwest": {"natwest.com"},
    "santander": {"santander.com"},
    "bradesco": {"bradesco.com.br"},
    "banco do brasil": {"bb.com.br"},
}

# Services that hide a link's real destination until you click it. Some
# belong to a company, so their own emails using them are fine: t.co in an
# email from x.com is normal, t.co in an email from a stranger hides something.
SHORTENERS = {"bit.ly": None, "tinyurl.com": None, "is.gd": None, "cutt.ly": None,
              "ow.ly": None, "rebrand.ly": None, "shorturl.at": None, "tiny.cc": None,
              "rb.gy": None, "s.id": None, "t.ly": None, "v.gd": None, "shorturl.gg": None,
              "t.co": {"twitter.com", "x.com"}, "lnkd.in": {"linkedin.com"},
              "amzn.to": {"amazon.com"}, "youtu.be": {"youtube.com", "google.com"},
              "goo.gl": {"google.com"}, "fb.me": {"facebook.com", "facebookmail.com"}}

# Email services that send every click through their own address first, to
# count it. A company linking its own website through these is normal.
CLICK_TRACKERS = {"list-manage.com", "sendgrid.net", "mandrillapp.com", "mcsv.net",
                  "hubspotlinks.com", "hs-sites.com", "rs6.net", "klclick.com",
                  "klclick1.com", "klclick2.com", "awstrack.me", "exct.net", "pstmrk.it",
                  "sparkpostmail.com", "cmail19.com", "cmail20.com", "createsend1.com",
                  "mailgun.org", "mailchimp.com", "urldefense.com", "mimecast.com",
                  "cudasvc.com", "safelinks.protection.outlook.com"}

# Websites that send emails on behalf of their users, with Reply-To set to
# that user: a Google Calendar invite replies to whoever sent it.
SENDS_FOR_USERS = {"google.com", "linkedin.com", "facebookmail.com", "eventbrite.com",
                   "docusign.net", "dropbox.com", "github.com", "gitlab.com", "slack.com",
                   "zoom.us", "indeed.com", "shopify.com", "zendesk.com", "freshdesk.com",
                   "calendly.com", "microsoft.com", "sharepointonline.com"}

# Characters attackers swap in because they look alike: paypa1, rnicrosoft, g00gle
LOOKALIKE_SWAPS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"),
                   ("5", "s"), ("$", "s"), ("@", "a")]

# Ordinary words one letter away from a brand, which real companies use as
# domains: cloud.com isn't pretending to be iCloud, finance.com isn't Binance
REAL_WORDS_NEAR_BRANDS = {"cloud", "finance", "goggle", "paypay"}

# Characters you can't see. Attackers use them to break up words like
# "PayPal" so filters don't match, or to pad out an empty-looking body.
INVISIBLE_CHARS = {"​", "‌", "‍", "﻿", "⁠", "­", "⠀",
                   "⁡", "⁢", "⁣", "⁤", "⁦", "⁧", "⁨", "⁩"}

# Four or more single letters separated by spaces, like "C o i n b a s e"
SPACED_LETTERS = re.compile(r"\b(?:\w ){3,}\w\b")


def is_ip(value):
    """Return True if value is a real IP address (each part 0-255)."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def org_domain(host):
    """The organisation behind a host name: 'email.amazon.co.uk' -> 'amazon.co.uk'.

    Two hosts with the same organisation domain belong to the same owner, so
    'news.example.com' and 'example.com' are not a mismatch.
    """
    host = (host or "").lower().strip(".")
    if not host or is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def org_name(host):
    """Just the name part of the organisation domain: 'mail.paypal.co.uk' -> 'paypal'."""
    return org_domain(host).split(".")[0]


def address_of(header):
    """The email address in a From or Reply-To header, lowercased, or None."""
    # getaddresses copes with messy headers that list several addresses,
    # like '"Microsoft account team", _ <x@evil.com>'. The real address is
    # usually last, so take the last one that has an @.
    for _, address in reversed(getaddresses([str(header or "")])):
        if "@" in address:
            return address.lower()
    return None


def domain_of(header):
    """Name of the domain that sent an email, or None if it can't be determined."""
    address = address_of(header)
    return address.split("@")[-1] if address else None


def display_name_of(header):
    """The name shown before the address: '"PayPal" <x@y.com>' -> 'PayPal'."""
    header = str(header or "")
    if "<" not in header:
        return ""
    return header.rsplit("<", 1)[0].strip().strip('"').strip()


def plain_text(text):
    """Strip disguises: 'Aܿmܿaܿzܿon' -> 'Amazon', '𝕚ℂ𝕝𝕠𝕦𝕕' -> 'iCloud'."""
    # NFKD turns fancy letters into plain ones and splits off accents/marks
    text = unicodedata.normalize("NFKD", text)
    # Drop the combining marks and invisible characters, keep everything else
    return "".join(ch for ch in text
                   if not unicodedata.combining(ch) and ch not in INVISIBLE_CHARS)


def unspace(text):
    """Join letters spaced out to dodge filters: 'C o i n b a s e' -> 'Coinbase'."""
    return SPACED_LETTERS.sub(lambda match: match.group().replace(" ", ""), text)


def brands_named_in(text):
    """Every brand whose name appears as a whole word in a piece of text."""
    text = unspace(plain_text(text)).lower()
    found = []
    for brand in BRANDS:
        # Not part of a longer word: "apple" shouldn't match "Applebee's"
        words = r"\s+".join(map(re.escape, brand.split()))
        if re.search(rf"(?<![a-z0-9]){words}(?![a-z0-9])", text):
            found.append(brand)
    return found


def is_official(brand, host):
    """True if host belongs to the brand: its own domain, or brand-name.anything."""
    if not host:
        return False
    org = org_domain(host)
    return org in BRANDS[brand] or org_name(host) == brand.replace(" ", "")


def deconfuse(label):
    """Undo look-alike swaps so 'paypa1' reads 'paypal' and 'rnicrosoft' reads 'microsoft'."""
    for fake, real in LOOKALIKE_SWAPS:
        label = label.replace(fake, real)
    return label


def one_edit_apart(a, b):
    """True if a becomes b by adding, removing or changing exactly one letter."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    for i in range(len(b)):
        if a[:i] == b[:i]:
            # Skip one letter of b (an insertion), or of both (a change)
            if a[i:] == b[i + 1:] or (len(a) == len(b) and a[i + 1:] == b[i + 1:]):
                return True
    return False


def imitated_brand(host):
    """The brand a domain is pretending to be, or None.

    Catches typos and swapped characters in the organisation's name
    ('paypa1.com', 'arnazon.co.uk', 'micosoft.com'). The brand's real
    domains are never flagged.
    """
    name = org_name(host)
    if not name or is_ip(host or ""):
        return None
    # The whole name, and each word of a hyphenated one: micosoft-support
    words = {word for word in [name] + name.split("-") if word not in REAL_WORDS_NEAR_BRANDS}
    for brand in BRANDS:
        target = brand.replace(" ", "")
        if is_official(brand, host) or len(target) < 6:
            continue  # short names like "dhl" are a letter away from too many real words
        for word in words:
            # Only near misses: the exact brand as one word (ssl-images-amazon.com)
            # is often the brand's own, so brand_in_domain handles that for senders
            if word != target and (deconfuse(word) == target or one_edit_apart(deconfuse(word), target)):
                return brand
    return None


def brand_in_domain(host):
    """A brand used as one word of someone else's domain: 'paypal-secure-login.com' -> 'paypal'."""
    words = re.split(r"[.-]", (host or "").lower())
    for brand in BRANDS:
        if " " not in brand and brand in words and not is_official(brand, host):
            return brand
    return None
