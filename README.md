# 🎣 HookLine

A phishing email analyser. Give it a suspicious email and HookLine pulls out the links, domains, IP addresses and attachments, checks for red flags, looks the evidence up on VirusTotal, and gives a verdict, **Safe**, **Suspicious** or **Malicious**, explaining exactly why.

Use it three ways: from the **terminal**, in a **web page**, or by forwarding emails to a **reporting inbox**.

![HookLine's result page showing a Malicious verdict](docs/screenshot.png)

> 🚧 **Nearly there.** The analysis engine, web interface and reporting inbox all work. Live progress updates in the browser are next. See the roadmap below.

## How it works

1. **Parse**: read the email and extract the headers, plain text body, HTML body and attachments
2. **Extract**: find every link, domain, IP address and email address
3. **Check**: look for 13 red flags and score each one by how strong the evidence is
4. **Look up**: optionally ask VirusTotal whether the attachments, IPs, domains and links are known to be malicious
5. **Verdict**: add up the evidence and decide: Safe (0–1 points), Suspicious (2–5) or Malicious (6+, or if 5+ VirusTotal engines agree)

## Red flags HookLine checks for

| Check | Example |
|---|---|
| SPF failed or missing | The sending server isn't allowed to send for that domain |
| DKIM or DMARC failed | The email's signature is broken, or the From address is spoofed |
| Reply-To mismatch | Replies go to a different domain from the sender |
| Brand mismatch | Claims to be Microsoft or Amazon but sent from an unrelated domain, even when the name is disguised |
| Organisation on personal email | A "bank" or "support team" sending from Gmail or Hotmail |
| Spaced-out sender name | `C o i n b a s e` written letter by letter to dodge filters |
| Raw IP link | `http://33.162.119.19/pay` instead of a website name |
| Link text mismatch | The link *shows* one address but *goes* to another |
| Link shortener | Links hidden behind `t.co` or `tinyurl.com` so you can't see where they go |
| Risky attachment | Programs like `.exe`, `.iso` or `.lnk`, or double extensions like `invoice.pdf.exe` |
| Empty body with attachment | The body is a decoy and the real message is in the file |
| Invisible characters | Hidden characters used to disguise words like "Amazon" |
| Pressure language | "Verify within 24 hours", "account suspended", "gift cards" |

## VirusTotal lookups

HookLine checks attachment fingerprints (SHA-256 hashes), IP addresses, domains and links against [VirusTotal](https://www.virustotal.com), which combines the results of around 90 security engines. Attachments are never uploaded, only their fingerprints.

It's designed around the free API's limits (4 lookups a minute, 500 a day):

- **Rate limiting**: waits 15 seconds between lookups
- **Cache**: every answer is saved in `vt_cache.json`, so nothing is looked up twice
- **Allowlist**: skips well-known infrastructure like Google Fonts, and webmail domains like gmail.com
- **Priority**: attachments first, then IPs, domains and links, up to 8 lookups per email
- **No double counting**: one malicious website counts once, however many links point to it

## Accuracy

Measured with `python batch.py`, without VirusTotal:

| Test set | Result |
|---|---|
| 30 fake phishing emails | 30 caught |
| 50 real phishing emails ([Phishing Pot](https://github.com/rf-peixoto/phishing_pot)) | 47 caught (94%) |
| 30 fake safe emails | 30 passed, no false alarms |

The fake samples were written alongside the checks, so their results are optimistic. The real samples are the more honest measure. Of the three real emails missed, two are Portuguese-language scams and one looks like genuine marketing that ended up in the collection.

## Setup

You need Python 3.14 and a free [VirusTotal account](https://www.virustotal.com).

```
git clone https://github.com/Valorz1/hookline.git
cd hookline
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Then create a file called `.env` in the project folder:

```
VT_API_KEY=your_virustotal_key
IMAP_HOST=imap.gmail.com
IMAP_USER=your.reporting.inbox@gmail.com
IMAP_PASSWORD=your_16_letter_app_password
```

The VirusTotal key is under your VirusTotal profile → **API key**. The `IMAP_` lines are only needed for the reporting inbox (see below). `.env` is in `.gitignore`, so these are never uploaded.

## Use it from the terminal

```
python make_samples.py
python main.py samples/real/sample-1020.eml
```

`make_samples.py` creates 60 safe, made-up test emails. `main.py` analyses one and shows everything it found. Here it is on a real phishing email pretending to be from Costco:

```
RED FLAGS (2 found, 4 points)
   [1] SPF is missing or only a soft fail
   [3] DMARC failed: the From domain didn't authorise this email (likely spoofed)

VIRUSTOTAL (6 lookups, about 15 seconds each)
   domain thebandalisty.com  ->  11 malicious, 1 suspicious (of 91)
   ...

==================================================
VERDICT: MALICIOUS
==================================================
   - VirusTotal: 11 of 91 engines flag domain thebandalisty.com
   - DMARC failed: the From domain didn't authorise this email (likely spoofed)
   - SPF is missing or only a soft fail
```

To skip VirusTotal and only run the quick checks, add `--no-vt`. To measure accuracy across every sample, run `python batch.py`.

## Use it in the browser

```
python app.py
```

Then open http://127.0.0.1:5000, drop in an `.eml` file, and choose whether to check VirusTotal. To get an `.eml` file in Gmail, open the email, click the ⋮ menu, then **Download message**.

## Use it as a reporting inbox

People forward suspicious emails **as an attachment** to a dedicated Gmail inbox, and HookLine checks them:

```
python inbox.py          analyse unread reports, leave them unread
python inbox.py --mark   analyse them, then mark them as read
```

To set it up, create a separate Gmail account for reports, turn on 2-Step Verification, then create an **app password** at myaccount.google.com/apppasswords and put it in `.env`.

Emails must be forwarded **as an attachment** (in Gmail: ⋮ → **Forward as attachment**). A normal forward throws away the original headers, such as the real sender and the SPF/DKIM/DMARC results, which most of the checks rely on.

It's also worth adding a Gmail filter on the reporting inbox so emails with attachments are never sent to Spam, or the reports can disappear.

## Security notes

HookLine handles malicious emails, so it's built to be careful with them:

- **Nothing is saved.** Uploaded emails are read in memory and discarded.
- **Nothing from the email runs.** The email's own HTML is never displayed, and everything shown on the page is escaped, so code hidden in a subject line can't run in your browser.
- **Attachments are never opened or uploaded.** Only their SHA-256 fingerprints are checked.
- **Secrets stay in `.env`**, which is never committed.
- **The reporting inbox uses an app password** on a dedicated account. That's simpler than OAuth, Google's modern sign-in method, but less secure, which is why the account should be used only for reports. OAuth is a planned improvement.
- **The web server is for local use.** It runs in Flask's debug mode, which must never be exposed to a network.

## Roadmap

- [x] Read and parse `.eml` files
- [x] Extract links, domains, IP addresses and attachments
- [x] Red-flag checks
- [x] Brand mismatch check, including disguised names
- [x] VirusTotal lookups
- [x] Verdict scoring
- [x] Accuracy measurement on real phishing samples
- [x] Web interface
- [x] Fetch reported emails from a mailbox (IMAP)
- [ ] Live progress updates in the browser
- [ ] One shared analysis function for the terminal, web page and inbox
- [ ] OAuth sign-in for the reporting inbox

## Project structure

```
hookline/
├── analyser/
│   ├── parser.py        read the email
│   ├── observables.py   find links, domains, IPs and email addresses
│   ├── checks.py        look for red flags
│   ├── virustotal.py    VirusTotal lookups with rate limiting and caching
│   └── verdict.py       combine the evidence into a final verdict
├── templates/
│   ├── base.html        the parts every page shares
│   ├── index.html       the home page
│   └── result.html      the verdict, reasons and evidence
├── static/
│   ├── app.css          styling
│   └── hookline.js      file picker, drag and drop, progress
├── samples/
│   ├── fake/            60 generated test emails (30 phishing, 30 safe)
│   └── real/            real phishing samples (not included, see below)
├── docs/
│   └── screenshot.png
├── main.py              analyse one email from the terminal
├── app.py               the web interface
├── inbox.py             analyse emails reported to a mailbox
├── batch.py             measure accuracy across every sample
├── make_samples.py      generate the fake test emails
├── vt_test.py           a single test lookup to check your API key works
└── requirements.txt     packages to install
```

## Testing with real phishing emails

HookLine is also tested against real phishing samples from [Phishing Pot](https://github.com/rf-peixoto/phishing_pot). These aren't included in this repository because they contain live malicious links and attachments. To use them, download the collection and copy some `.eml` files into `samples/real/`.

⚠️ Only open real samples as text or with HookLine. Never double-click them or click their links.

## Tech

- **Python 3.14**
- **Standard library**: `email`, `imaplib`, `re`, `hashlib`, `ipaddress`, `urllib`, `unicodedata`, `json`, `base64`, `collections`
- **Packages**: `flask` (web interface), `requests` (VirusTotal API), `python-dotenv` (reads secrets from `.env`)
- **Threat intelligence**: VirusTotal public API
- **Design**: interface inspired by [Watermelon UI](https://ui.watermelon.sh) (MIT)

## Author

Built by [Valorz1](https://github.com/Valorz1)