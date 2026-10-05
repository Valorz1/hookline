from collections import Counter
from pathlib import Path

from analyser.pipeline import analyse
from analyser.parser import read_email



def expected(path):
    """What the right answer is: fake safe_ emails are safe, everything else is phishing."""
    return "safe" if path.name.startswith("safe_") else "phishing"


# Counts how many emails of each kind got each verdict,
# e.g. results[("phishing", "Malicious")] = 25
results = Counter()

# VirusTotal is left out on purpose: 110 emails would take hours and use up the daily limit
for path in sorted(Path("samples").rglob("*.eml")):
    try:
        parsed = read_email(path)
        verdict = analyse(parsed)["outcome"]["verdict"]
    except Exception as error:
        # One malformed email shouldn't stop the rest from being checked
        print(f"ERROR   {path.name}: {error}")
        continue

    results[(expected(path), verdict)] += 1

    # Only print the mistakes, so they stand out
    if expected(path) == "phishing" and verdict == "Safe":
        print(f"MISSED  {path.name}  (phishing marked Safe)")
    if expected(path) == "safe" and verdict != "Safe":
        print(f"FALSE ALARM  {path.name}  (safe marked {verdict})")

for kind in ("phishing", "safe"):
    total = sum(count for (exp, _), count in results.items() if exp == kind)
    breakdown = ", ".join(f"{results[(kind, v)]} {v}" for v in ("Malicious", "Suspicious", "Safe"))
    print(f"\n{kind.upper()} ({total}): {breakdown}")

phishing_total = sum(c for (exp, _), c in results.items() if exp == "phishing")
caught = phishing_total - results[("phishing", "Safe")]
safe_total = sum(c for (exp, _), c in results.items() if exp == "safe")
print(f"\nCaught {caught} of {phishing_total} phishing emails")
print(f"Passed {results[('safe', 'Safe')]} of {safe_total} safe emails")