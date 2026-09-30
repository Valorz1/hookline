- [x] Read and parse `.eml` files
- [x] Extract links, domains and IP addresses

## Project structure

```
hookline/
├── analyser/          the analysis engine, one file per job
├── samples/           test emails
│   └── fake/          60 generated test emails (30 phishing, 30 safe)
├── templates/         web page
├── static/            CSS and JavaScript
├── main.py            analyse one email from the terminal
├── batch.py           check the parser works on every sample
├── make_samples.py    generate the fake test emails
├── app.py             web server
└── mailbox.py         fetch emails over IMAP
```


`make_samples.py` creates safe, made-up test emails, and 
`main.py` analyses one and lists the links, domains, IPs and email addresses it finds.