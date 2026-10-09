"""Each check on its own: ordinary emails it must leave alone, and the trick it must catch."""

import pytest

from tests.emails import LEGIT, build, passing, run

NO_AUTH = "mx.example; spf=none smtp.mailfrom=x; dkim=none; dmarc=none"


# ---------- false alarms: these ordinary emails all used to score 2-9 points ----------

@pytest.mark.parametrize("name", LEGIT)
def test_ordinary_email_is_safe(name):
    verdict, score, fired = run(LEGIT[name])
    assert verdict == "Safe", f"{name} scored {score}: {fired}"


# ---------- sender authentication ----------

def test_dmarc_fail_means_spoofed():
    raw = build('"Costco" <noreply@costco.com>',
                auth="mx; spf=none smtp.mailfrom=x.example; dkim=none; dmarc=fail header.from=costco.com")
    verdict, score, fired = run(raw)
    assert "dmarc_fail" in fired and "spf_weak" in fired
    assert score == 5


def test_microsoft_compauth_fail():
    raw = build("a@x.example", auth="spf=pass smtp.mailfrom=x.example; dmarc=none header.from=x.example;"
                                    "compauth=fail reason=001")
    assert "compauth_fail" in run(raw)[2]


def test_spf_hiccup_ignored_when_dmarc_passes():
    # Forwarding breaks SPF, but DKIM and so DMARC still prove the sender
    raw = build("a@example.com", auth="mx; spf=softfail; dkim=pass header.i=@example.com; dmarc=pass")
    assert run(raw)[2] == []


# ---------- who the sender says it is ----------

def test_reply_to_personal_webmail():
    raw = build("ceo@contoso.example", reply_to="contoso.ceo.office@gmail.com", auth=NO_AUTH)
    verdict, score, fired = run(raw)
    assert fired.count("reply_to_mismatch") == 1 and score >= 3


def test_reply_to_mismatch_counts_less_when_dmarc_passes():
    raw = build("news@shop.example", reply_to="help@zendesk.example", auth=passing("shop.example"))
    assert run(raw)[1] == 1


def test_brand_in_name_but_not_from_the_brand():
    raw = build('"PayPal Service" <service@account-review.example>', auth=passing("account-review.example"))
    assert "brand_mismatch" in run(raw)[2]


def test_brand_hidden_in_the_address():
    raw = build('"Support" <noreply-supportbinancewallet@shop.example>')
    assert "brand_mismatch" in run(raw)[2]


def test_address_in_the_display_name():
    raw = build('"service@paypal.com" <x@evil.example>')
    assert "display_name_spoof" in run(raw)[2]


def test_google_groups_names_are_not_spoofs():
    raw = build("\"'jane@gmail.com' via Book Club\" <bookclub@googlegroups.com>",
                auth=passing("googlegroups.com"))
    assert run(raw)[2] == []


def test_sender_domain_imitates_a_brand():
    assert "lookalike_domain" in run(build("alerts@paypa1.com"))[2]
    assert "lookalike_domain" in run(build("alerts@paypal-secure-login.com"))[2]


# ---------- links ----------

def test_link_to_a_lookalike_domain():
    raw = build("it@contoso.example", html='<a href="https://rnicrosoft.com/login">Sign in</a>')
    assert "lookalike_domain" in run(raw)[2]


def test_punycode_link():
    raw = build("it@contoso.example", html='<a href="https://xn--pple-43d.com/">Apple ID</a>')
    assert "punycode_domain" in run(raw)[2]


def test_link_text_shows_one_address_but_goes_to_another():
    raw = build("it@contoso.example",
                html='<a href="https://evil.example/login">https://www.paypal.com/signin</a>')
    assert "link_text_mismatch" in run(raw)[2]


def test_www_text_without_https():
    raw = build("it@contoso.example", html='<a href="https://evil.example/">www.paypal.com</a>')
    assert "link_text_mismatch" in run(raw)[2]


def test_tracker_hiding_someone_elses_address_is_still_caught():
    # A click tracker is only fine for the sender's OWN website
    raw = build("promo@stranger.example",
                html='<a href="https://u1.ct.sendgrid.net/ls/click?x">https://www.paypal.com/</a>')
    assert "link_text_mismatch" in run(raw)[2]


def test_shortener_from_a_stranger():
    raw = build("promo@stranger.example", text="Claim it here: https://bit.ly/3abc")
    assert "link_shortener" in run(raw)[2]


def test_form_inside_the_email():
    raw = build("it@contoso.example", html='<form action="https://x.example"><input type="password"></form>')
    verdict, score, fired = run(raw)
    assert "html_form" in fired and score >= 5


# ---------- attachments ----------

@pytest.mark.parametrize("filename, check", [
    ("invoice.pdf.exe", "double_extension"),
    ("invoice‮fdp.exe", "double_extension"),   # shows as "invoiceexe.pdf"
    ("setup.iso", "risky_attachment"),
    ("Payment_Remittance.html", "web_page_attachment"),
    ("salary-review.xlsm", "macro_attachment"),
])
def test_dangerous_attachments(filename, check):
    raw = build("hr@contoso.example", attachments=[(filename, b"harmless test bytes")])
    assert check in run(raw)[2]


def test_ordinary_pdf_is_fine():
    raw = build("hr@contoso.example", text="Please find this month's payslip attached.",
                attachments=[("payslip.pdf", b"%PDF-1.7 test")], auth=passing("contoso.example"))
    assert run(raw)[2] == []


# ---------- the words ----------

def test_invisible_character_inside_a_word():
    assert "invisible_chars" in run(build("a@x.example", subject="Your Pay​Pal account"))[2]


def test_pressure_language_in_an_html_only_email():
    # Most real phishing has no plain-text version; the HTML's words count too
    raw = build("a@x.example", text="",
                html="<p>Urgent: your account has been suspended.</p><p>Verify your identity within 24 hours.</p>")
    assert "urgent_language" in run(raw)[2]


def test_one_urgent_phrase_is_not_enough():
    assert run(build("a@x.example", text="Please reply urgently, the meeting moved."))[2] == []
