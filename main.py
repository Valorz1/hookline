import sys

from analyser.parser import read_email
from analyser.observables import extract_observables
from analyser.checks import run_checks
from analyser.virustotal import choose_targets, describe, lookup
from analyser.verdict import decide, vt_findings

# Anything starting with -- is an option; the rest is the file to analyse
args = [arg for arg in sys.argv[1:] if not arg.startswith("--")]
use_virustotal = "--no-vt" not in sys.argv

if args:
    path = args[0]
else:
    path = "samples/fake/phish_03_password_expiry.eml"

parsed = read_email(path)
found = extract_observables(parsed)

print("Subject:", parsed["subject"])

for kind, items in found.items():
    print(f"\n{kind.upper()} ({len(items)})")
    for item in items:
        print("  ", item)

attachments = parsed["attachments"]
print(f"\nATTACHMENTS ({len(attachments)})")
for attachment in attachments:
    print(f"   {attachment['filename']}  ({attachment['content_type']}, {attachment['size']} bytes)")
    print(f"   sha256: {attachment['sha256']}")

findings = run_checks(parsed, found)
total = sum(flag["points"] for flag in findings)

print(f"\nRED FLAGS ({len(findings)} found, {total} points)")
for flag in findings:
    print(f"   [{flag['points']}] {flag['detail']}")

vt_results = []
if use_virustotal:
    targets = choose_targets(found, parsed["attachments"])
    print(f"\nVIRUSTOTAL ({len(targets)} lookups, about 15 seconds each)")
    for kind, value in targets:
        result = lookup(kind, value)
        vt_results.append(result)
        print("  ", describe(result))

# Combine the red flags and the VirusTotal evidence into one answer
outcome = decide(findings + vt_findings(vt_results))

print(f"\n{'=' * 50}")
print(f"VERDICT: {outcome['verdict'].upper()}  ({outcome['score']} points)")
print("=" * 50)
for reason in outcome["reasons"][:3]:
    print(f"   - {reason['detail']}")