from analyser.parser import html_to_text, parse_auth_results, parse_email_bytes
from tests.emails import build, passing


def test_gmail_authentication_results():
    auth = parse_auth_results(passing("example.com"))
    assert auth == {"spf": "pass", "dkim": ["pass"], "dmarc": "pass", "compauth": None}


def test_comments_are_ignored():
    # The bracketed comment mentions "fail", which must not be read as a result
    auth = parse_auth_results("mx.example; spf=pass (spf=fail would be bad) smtp.mailfrom=x.com")
    assert auth["spf"] == "pass"


def test_microsoft_results_with_compauth():
    auth = parse_auth_results(
        "spf=none (sender IP is 192.0.2.1) smtp.mailfrom=x.example; dkim=none (message not "
        "signed) header.d=none;dmarc=none action=none header.from=x.example;compauth=fail reason=001")
    assert auth == {"spf": "none", "dkim": ["none"], "dmarc": "none", "compauth": "fail"}


def test_several_dkim_signatures():
    auth = parse_auth_results("mx; dkim=pass header.i=@a.com; dkim=fail header.i=@b.com")
    assert auth["dkim"] == ["pass", "fail"]


def test_no_header_at_all():
    assert parse_auth_results(None) == {"spf": None, "dkim": [], "dmarc": None, "compauth": None}


def test_html_to_text():
    page = ("<html><head><style>p { color: red }</style><title>Hi</title>"
            "<body><p>Verify&nbsp;your&amp;account</p><script>alert(1)</script></body></head></html>")
    # The body sits inside <head> (broken on purpose); browsers still show it
    assert html_to_text(page) == "Verify your&account"


def test_html_body_is_turned_into_text():
    parsed = parse_email_bytes(build("a@example.com", html="<p>Hello <b>there</b></p>"))
    assert parsed["html_text"] == "Hello there"


def test_unknown_charset_does_not_crash():
    raw = (b"From: a@example.com\r\nSubject: hi\r\nContent-Type: text/plain; charset=x-made-up\r\n"
           b"\r\nPlease verify \xff\xfe now\r\n")
    parsed = parse_email_bytes(raw)
    assert "Please verify" in parsed["body"]
