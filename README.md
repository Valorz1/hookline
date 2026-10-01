# 🎣 HookLine

A phishing email analyser. Give it a suspicious email and HookLine pulls out the links, domains, IP addresses and attachments, checks for red flags, looks the evidence up on VirusTotal, and gives a verdict, **Safe**, **Suspicious** or **Malicious**, explaining exactly why.

> 🚧 **Work in progress.** The analysis engine works from the terminal. A web interface is next. See the roadmap below.

## How it works

1. **Parse**: read the `.eml` file and extract the headers, plain text body, HTML body and attachments
2. **Extract**: find every link, domain, IP address and email address
3. **Check**: look for red flags and score each one by how strong the evidence is
4. **Look up**: ask VirusTotal whether the attachments, IPs, domains and links are known to be malicious
5. **Verdict**: add up the evidence and decide: Safe (0–1 points), Suspicious (2–5) or Malicious (6+, or if 5+ VirusTotal engines agree)

## Red flags HookLine checks for

| Check | Example |
|---|---|
| SPF failed or missing | The sending server isn't allowed to send for that domain |
| DKIM or DMARC failed | The email's signature is broken, or the From address is spoofed |
| Reply-To mismatch | Replies go to a different domain from the sender |
| Brand mismatch | Claims to be Microsoft or Amazon but sent from an unrelated domain, even when the name is disguised |
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
- **Allowlist**: skips well-known infrastructure like Google Fonts
- **Priority**: attachments first, then IPs, domains and links, up to 8 lookups per email
- **No double counting**: one malicious website counts once, however many links point to it

## Accuracy

Measured with `python batch.py`, without VirusTotal:

| Test set | Result |
|---|---|
| 30 fake phishing emails | 30 caught |
| 50 real phishing emails ([Phishing Pot](https://github.com/rf-peixoto/phishing_pot)) | 43 caught (86%) |
| 30 fake safe emails | 30 passed, no false alarms |

The fake samples were written alongside the checks, so their results are optimistic. The real samples are the more honest measure.

## Setup

You need Python 3.14 and a free [VirusTotal account](https://www.virustotal.com).

```
git clone https://github.com/Valorz1/hookline.git
cd hookline
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Then create a file called `.env` in the project folder with your VirusTotal API key (found under your profile → **API key**):

```
VT_API_KEY=your_key_here
```

`.env` is in `.gitignore`, so your key is never uploaded.

## Try it

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
   domain costco.com  ->  0 malicious, 0 suspicious (of 91)
   domain thebandalisty.com  ->  11 malicious, 1 suspicious (of 91)
   ...

==================================================
VERDICT: MALICIOUS
==================================================
   - VirusTotal: 11 of 91 engines flag domain thebandalisty.com
   - DMARC failed: the From domain didn't authorise this email (likely spoofed)
   - SPF is missing or only a soft fail
```

To skip the VirusTotal lookups and only run the quick checks:

```
python main.py samples/real/sample-1020.eml --no-vt
```

To measure accuracy across every sample:

```
python batch.py
```

## Roadmap

- [x] Read and parse `.eml` files
- [x] Extract links, domains, IP addresses and attachments
- [x] Red-flag checks
- [x] Brand mismatch check, including disguised names
- [x] VirusTotal lookups
- [x] Verdict scoring
- [x] Accuracy measurement on real phishing samples
- [ ] Web interface
- [ ] Fetch reported emails from a mailbox (IMAP)
- [ ] Live progress updates in the browser

## Project structure

```
hookline/
├── analyser/
│   ├── parser.py        read the .eml file
│   ├── observables.py   find links, domains, IPs and email addresses
│   ├── checks.py        look for red flags
│   ├── virustotal.py    VirusTotal lookups with rate limiting and caching
│   └── verdict.py       combine the evidence into a final verdict
├── samples/
│   ├── fake/            60 generated test emails (30 phishing, 30 safe)
│   └── real/            real phishing samples (not included, see below)
├── templates/           web page (coming soon)
├── static/              CSS and JavaScript (coming soon)
├── main.py              analyse one email from the terminal
├── batch.py             measure accuracy across every sample
├── make_samples.py      generate the fake test emails
├── vt_test.py           a single test lookup to check your API key works
├── app.py               web server (coming soon)
├── mailbox.py           fetch emails over IMAP (coming soon)
└── requirements.txt     packages to install
```

## Testing with real phishing emails

HookLine is also tested against real phishing samples from [Phishing Pot](https://github.com/rf-peixoto/phishing_pot). These aren't included in this repository because they contain live malicious links and attachments. To use them, download the collection and copy some `.eml` files into `samples/real/`.

⚠️ Only open real samples as text or with HookLine. Never double-click them or click their links.

## Tech

- **Python 3.14**
- **Standard library**: `email`, `re`, `hashlib`, `ipaddress`, `urllib`, `unicodedata`, `json`, `base64`, `collections`
- **Packages**: `requests` (VirusTotal API), `python-dotenv` (reads the API key from `.env`)
- **Threat intelligence**: VirusTotal public API

## Author

Built by [Valorz1](https://github.com/Valorz1)