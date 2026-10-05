import sys

from analyser.parser import read_email
from analyser.pipeline import analyse
from analyser.virustotal import describe

# Anything starting with -- is an option; the rest is the file to analyse
args = [arg for arg in sys.argv[1:] if not arg.startswith("--")]
use_virustotal = "--no-vt" not in sys.argv

if args:
    path = args[0]
else:
    path = "samples/fake/phish_03_password_expiry.eml"

parsed = read_email(path)
print("Subject:", parsed["subject"])

if use_virustotal:
    print("\nVIRUSTOTAL (about 15 seconds per lookup)")


def show_lookup(result):
    # analyse() calls this the moment each lookup finishes,
    # so results appear one by one instead of all at the end
    print("  ", describe(result))


result = analyse(parsed, use_virustotal=use_virustotal, on_lookup=show_lookup)
found = result["found"]

for kind, items in found.items():
    print(f"\n{kind.upper()} ({len(items)})")
    for item in items:
        print("  ", item)

attachments = parsed["attachments"]
print(f"\nATTACHMENTS ({len(attachments)})")
for attachment in attachments:
    print(f"   {attachment['filename']}  ({attachment['content_type']}, {attachment['size']} bytes)")
    print(f"   sha256: {attachment['sha256']}")

findings = result["findings"]
total = sum(flag["points"] for flag in findings)
print(f"\nRED FLAGS ({len(findings)} found, {total} points)")
for flag in findings:
    print(f"   [{flag['points']}] {flag['detail']}")

outcome = result["outcome"]
print(f"\n{'=' * 50}")
print(f"VERDICT: {outcome['verdict'].upper()}  ({outcome['score']} points)")
print("=" * 50)
for reason in outcome["reasons"][:3]:
    print(f"   - {reason['detail']}")