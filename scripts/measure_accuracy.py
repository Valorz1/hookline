"""
measure_accuracy.py - run every sample email through HookLine and count the mistakes.

Usage (from the project folder):
    python -m scripts.measure_accuracy

Fake safe_ emails and anything in samples/legit/ should come out Safe;
everything else should be caught as Suspicious or Malicious.
"""

from collections import Counter
from pathlib import Path

from analyser.parser import read_email
from analyser.pipeline import analyse

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def expected(path):
    """What the right answer is.

    Fake safe_ emails and anything in samples/legit/ (your own real, harmless
    emails) are safe. Everything else is phishing.
    """
    if path.name.startswith("safe_") or "legit" in path.parts:
        return "safe"
    return "phishing"


# Counts how many emails of each kind got each verdict,
# e.g. results[("phishing", "Malicious")] = 25
results = Counter()

# VirusTotal is left out on purpose: 110 emails would take hours and use up the daily limit
for path in sorted(SAMPLES.rglob("*.eml")):
    try:
        parsed = read_email(path)
        outcome = analyse(parsed)["outcome"]
    except Exception as error:
        # One malformed email shouldn't stop the rest from being checked
        print(f"ERROR   {path.name}: {error}")
        continue

    verdict = outcome["verdict"]
    results[(expected(path), verdict)] += 1

    # Only print the mistakes, so they stand out, with what caused them
    reasons = "; ".join(r["detail"] for r in outcome["reasons"])
    if expected(path) == "phishing" and verdict == "Safe":
        print(f"MISSED  {path.name}  (phishing marked Safe, {outcome['score']} points) {reasons}")
    if expected(path) == "safe" and verdict != "Safe":
        print(f"FALSE ALARM  {path.name}  (safe marked {verdict}, {outcome['score']} points) {reasons}")

for kind in ("phishing", "safe"):
    total = sum(count for (exp, _), count in results.items() if exp == kind)
    breakdown = ", ".join(f"{results[(kind, v)]} {v}" for v in ("Malicious", "Suspicious", "Safe"))
    print(f"\n{kind.upper()} ({total}): {breakdown}")

phishing_total = sum(c for (exp, _), c in results.items() if exp == "phishing")
caught = phishing_total - results[("phishing", "Safe")]
safe_total = sum(c for (exp, _), c in results.items() if exp == "safe")
print(f"\nCaught {caught} of {phishing_total} phishing emails")
print(f"Passed {results[('safe', 'Safe')]} of {safe_total} safe emails")
