from analyser.checks import finding
from analyser.observables import host_of

SUSPICIOUS_AT = 2
MALICIOUS_AT = 6

# How many VirusTotal engines must call something malicious before we believe
# it on its own. One engine alone is often a false alarm, especially for the
# tracking domains that ordinary marketing emails are full of.
VT_CONFIDENT = 5
VT_SEVERAL = 2


def vt_level(result):
    """How worrying one VirusTotal answer is: "bad", "warn", "weak", "clean" or None (no answer)."""
    if result.get("status") != "found":
        return None
    if result["malicious"] >= VT_CONFIDENT:
        return "bad"
    if result["malicious"] >= VT_SEVERAL:
        return "warn"
    if result["malicious"] or result["suspicious"]:
        return "weak"
    return "clean"


def vt_findings(vt_results):
    """Turn VirusTotal results into findings, in the same shape as the red flags."""
    findings = []
    # Sites we've already counted, so one bad website isn't counted
    # again for every link that points to it
    counted = set()
    for result in vt_results:
        level = vt_level(result)
        if level in (None, "clean"):
            continue  # "never seen", an error, or nothing found isn't evidence

        # For a URL, the "site" is its domain; for anything else it's the value itself
        site = host_of(result["value"]) if result["kind"] == "url" else result["value"]
        if site in counted:
            continue
        counted.add(site)

        what = f"{result['kind']} {result['value'][:60]}"
        if level == "bad":
            findings.append(finding("vt_malicious", 6,
                f"VirusTotal: {result['malicious']} of {result['engines']} engines flag {what}"))
        elif level == "warn":
            findings.append(finding("vt_suspicious", 3,
                f"VirusTotal: {result['malicious']} of {result['engines']} engines flag {what}"))
        else:
            wary = result["malicious"] + result["suspicious"]
            findings.append(finding("vt_weak", 1,
                f"VirusTotal: {wary} engine{'s' if wary > 1 else ''} wary of {what} "
                f"(on its own, often a false alarm)"))
    return findings


def vt_good_signs(vt_results):
    """A reassuring line when VirusTotal knew everything it was asked and flagged none of it."""
    answered = [r for r in vt_results if vt_level(r) is not None]
    if answered and all(vt_level(r) == "clean" for r in answered):
        return [f"VirusTotal: none of the {len(answered)} things it knew about were flagged"]
    return []


def decide(findings, good_signs=()):
    """Add up the evidence and decide if the email is suspicious or malicious."""
    score = sum(f["points"] for f in findings)

    # Many security engines agreeing is strong enough evidence on its own
    known_bad = any(f["check"] == "vt_malicious" for f in findings)

    if known_bad or score >= MALICIOUS_AT:
        verdict = "Malicious"
    elif score >= SUSPICIOUS_AT:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    # Strongest evidence first
    reasons = sorted(findings, key=lambda f: f["points"], reverse=True)
    return {"verdict": verdict, "score": score, "reasons": reasons, "good_signs": list(good_signs)}
