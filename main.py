import sys

from analyser.parser import read_email
from analyser.observables import extract_observables

# Use the file named on the command line, or a default sample if none is given
if len(sys.argv) > 1:
    path = sys.argv[1]
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