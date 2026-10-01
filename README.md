# 🎣 HookLine

A phishing email analyser. Give it a suspicious email and HookLine pulls out the links, domains, IP addresses and attachments, checks for red flags, and looks the evidence up on VirusTotal, explaining everything it finds. Soon it will combine all of that into a single verdict: **Safe**, **Suspicious** or **Malicious**.

> 🚧 **Work in progress.** HookLine is being built step by step. See the roadmap below for what's done so far.

## How it works

1. **Parse**: read the `.eml` file and extract the headers, plain text body, HTML body and attachments
2. **Extract**: find every link, domain, IP address and email address
3. **Check**: look for red flags and score each one by how strong the evidence is
4. **Look up**: ask VirusTotal whether the attachments, IPs, domains and links are known to be malicious
5. **Verdict**: combine all the evidence into a final verdict *(coming next)*

## Red flags HookLine checks for

| Check | Example |
|---|---|
| SPF failed or missing | The sending server isn't allowed to send for that domain |
| Reply-To mismatch | Replies go to a different domain from the sender |
| Raw IP link | `http://33.162.119.19/pay` instead of a website name |
| Link text mismatch | The link *shows* one address but *goes* to another |
| Risky attachment | Programs like `.exe`, `.iso` or `.lnk`, or double extensions like `invoice.pdf.exe` |
| Empty body with attachment | The body is a decoy and the real message is in the file |
| Invisible characters | Hidden characters used to disguise words like "Amazon" |
| Pressure language | "Verify within 24 hours", "account suspended", "gift cards" |
| Brand mismatch | Claims to be Microsoft or Amazon but sent from an unrelated domain, even when the name is disguised |

## VirusTotal lookups

HookLine checks attachment fingerprints (SHA-256 hashes), IP addresses, domains and links against [VirusTotal](https://www.virustotal.com), which combines the results of around 70 security engines. Attachments are never uploaded, only their fingerprints.

It's designed around the free API's limits (4 lookups a minute, 500 a day):

- **Rate limiting**: waits 15 seconds between lookups
- **Cache**: every answer is saved in `vt_cache.json`, so nothing is looked up twice
- **Allowlist**: skips well-known infrastructure like Google Fonts
- **Priority**: attachments first, then IPs, domains and links, up to 8 lookups per email

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
python main.py samples/real/sample-1014.eml
```

`make_samples.py` creates 60 safe, made-up test emails. `main.py` analyses one and shows everything it found. Here it is on a real phishing email pretending to be Amazon:

```
RED FLAGS (4 found, 12 points)
   [3] The body is (almost) empty: the real message is in the attachment
   [3] Hidden or disguising characters found (6)
   [2] Pressure language (2 phrases)
   [4] From header mentions amazon but the email came from arulnotes.com

VIRUSTOTAL (2 lookups, about 15 seconds each)
   file   73a0e5d5582ec223...  ->  25 malicious, 0 suspicious (of 62)
```

To skip the VirusTotal lookups and only run the quick checks:

```
python main.py samples/real/sample-1014.eml --no-vt
```

To check the parser handles every sample without crashing:

```
python batch.py
```

## Roadmap

- [x] Read and parse `.eml` files
- [x] Extract links, domains, IP addresses and attachments
- [x] Red-flag checks
- [x] Brand mismatch check, including disguised names
- [x] VirusTotal lookups
- [ ] Verdict scoring
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
│   └── verdict.py       final verdict (coming soon)
├── samples/
│   ├── fake/            60 generated test emails (30 phishing, 30 safe)
│   └── real/            real phishing samples (not included, see below)
├── templates/           web page (coming soon)
├── static/              CSS and JavaScript (coming soon)
├── main.py              analyse one email from the terminal
├── batch.py             check the parser works on every sample
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
- **Standard library**: `email`, `re`, `hashlib`, `ipaddress`, `urllib`, `unicodedata`, `json`, `base64`
- **Packages**: `requests` (VirusTotal API), `python-dotenv` (reads the API key from `.env`)
- **Threat intelligence**: VirusTotal public API

## Author

Built by [Valorz1](https://github.com/Valorz1)