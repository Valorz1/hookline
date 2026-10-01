# 🎣 HookLine

A phishing email analyser. Give it a suspicious email and HookLine pulls out the links, domains, IP addresses and attachments, checks for red flags, and explains what it found. Soon it will look the evidence up with threat intelligence services and give a verdict: **Safe**, **Suspicious** or **Malicious**.

> 🚧 **Work in progress.** HookLine is being built step by step. See the roadmap below for what's done so far.

## How it works

1. **Parse**: read the `.eml` file and extract the headers, plain text body, HTML body and attachments
2. **Extract**: find every link, domain, IP address and email address
3. **Check**: look for red flags and score each one by how strong the evidence is
4. **Look up**: ask VirusTotal whether the links, domains and attachments are known to be malicious
5. **Verdict**: combine all the evidence into a final verdict

## Red flags HookLine checks for

| Check | Example |
|---|---|
| SPF failed or missing | The sending server isn't allowed to send for that domain |
| Reply-To mismatch | Replies go to a different domain from the sender |
| Raw IP link | `http://33.162.119.19/pay` instead of a website name |
| Link text mismatch | The link *shows* one address but *goes* to another |
| Risky attachment | Programs like `.exe`, or double extensions like `invoice.pdf.exe` |
| Empty body with attachment | The body is a decoy and the real message is in the file |
| Invisible characters | Hidden characters used to disguise words like "Amazon" |
| Pressure language | "Verify within 24 hours", "account suspended", "gift cards" |

## Roadmap

- [x] Read and parse `.eml` files
- [x] Extract links, domains, IP addresses and attachments
- [x] Red-flag checks
- [ ] Brand mismatch check (e.g. "Microsoft" sent from an unrelated domain)
- [ ] VirusTotal lookups
- [ ] Verdict scoring
- [ ] Web interface
- [ ] Fetch reported emails from a mailbox (IMAP)
- [ ] Live progress updates in the browser

## Try it

```
python make_samples.py
python main.py samples/fake/phish_01_account_limited.eml
```

`make_samples.py` creates 60 safe, made-up test emails. `main.py` analyses one and shows everything it found, ending with the red flags:

```
RED FLAGS (3 found, 8 points)
   [3] SPF failed: the sending server isn't allowed to send for this domain
   [3] Reply-To domain account-recovery-38.net doesn't match sender northwindbank-secure-login.com
   [2] Pressure language (6 phrases)
```

To check the parser handles every sample without crashing:

```
python batch.py
```

## Project structure

```
hookline/
├── analyser/
│   ├── parser.py        read the .eml file
│   ├── observables.py   find links, domains, IPs and email addresses
│   ├── checks.py        look for red flags
│   ├── virustotal.py    threat intelligence lookups (coming soon)
│   └── verdict.py       final verdict (coming soon)
├── samples/
│   ├── fake/            60 generated test emails (30 phishing, 30 safe)
│   └── real/            real phishing samples (not included, see below)
├── templates/           web page (coming soon)
├── static/              CSS and JavaScript (coming soon)
├── main.py              analyse one email from the terminal
├── batch.py             check the parser works on every sample
├── make_samples.py      generate the fake test emails
├── app.py               web server (coming soon)
└── mailbox.py           fetch emails over IMAP (coming soon)
```

## Testing with real phishing emails

HookLine is also tested against real phishing samples from [Phishing Pot](https://github.com/rf-peixoto/phishing_pot). These aren't included in this repository because they contain live malicious links and attachments. To use them, download the collection and copy some `.eml` files into `samples/real/`.

⚠️ Only open real samples as text or with HookLine. Never double-click them or click their links.

## Tech

Python 3.12, using only the standard library so