import pytest

from analyser.domains import (brand_in_domain, brands_named_in, display_name_of, domain_of,
                              imitated_brand, is_official, one_edit_apart, org_domain)


@pytest.mark.parametrize("host, org", [
    ("example.com", "example.com"),
    ("news.email.example.com", "example.com"),
    ("mail.amazon.co.uk", "amazon.co.uk"),
    ("hmrc.gov.uk", "hmrc.gov.uk"),
    ("auswestbc.com.au", "auswestbc.com.au"),
    ("192.0.2.10", "192.0.2.10"),
    ("", ""),
])
def test_org_domain(host, org):
    assert org_domain(host) == org


def test_reading_the_from_header():
    header = '"PayPal Service" <Service@PayPal.example>'
    assert domain_of(header) == "paypal.example"
    assert display_name_of(header) == "PayPal Service"
    assert display_name_of("plain@example.com") == ""
    # A messy header listing several addresses: the real one is last
    assert domain_of('"Microsoft account team", _ <x@evil.example>') == "evil.example"


@pytest.mark.parametrize("text, brands", [
    ("Amazon.co.uk", ["amazon"]),
    ("Applebee's", []),                     # not Apple
    ("C o i n b a s e", ["coinbase"]),      # spaced out
    ("Aܿmܿaܿzܿon", ["amazon"]),  # disguised with marks
    ("Bank of America Alerts", ["bank of america"]),
    ("Startups Weekly", []),
])
def test_brands_named_in(text, brands):
    assert brands_named_in(text) == brands


def test_brand_domains():
    assert is_official("amazon", "auto-confirm.amazon.co.uk")
    assert is_official("paypal", "mail.paypal.de")
    assert is_official("hmrc", "notifications.hmrc.gov.uk")
    assert not is_official("amazon", "amazon-security.example")
    assert not is_official("paypal", "paypal.com.evil.example")


@pytest.mark.parametrize("host, brand", [
    ("paypa1.com", "paypal"),
    ("rnicrosoft.com", "microsoft"),
    ("arnazon.co.uk", "amazon"),
    ("micosoft-support.com", "microsoft"),
    ("g00gle.com", "google"),
    ("paypal.com", None),               # the real thing
    ("cloud.com", None),                # a real word, not iCloud
    ("ssl-images-amazon.com", None),    # Amazon's own image server
])
def test_imitated_brand(host, brand):
    assert imitated_brand(host) == brand


def test_brand_in_domain():
    assert brand_in_domain("paypal-secure-login.com") == "paypal"
    assert brand_in_domain("email.paypal.com") is None
    assert brand_in_domain("pineapple.com") is None


def test_one_edit_apart():
    assert one_edit_apart("micosoft", "microsoft")
    assert one_edit_apart("paypai", "paypal")
    assert not one_edit_apart("paypal", "paypal")
    assert not one_edit_apart("amazon", "amazing")
