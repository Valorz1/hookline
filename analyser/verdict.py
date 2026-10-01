from analyser.checks import finding


SUSPICIOUS_AT = 2
MALICIOUS_AT = 6




VT_CONFIDENT = 5 


def vt_findings(vt_result):
    """Turn VirusTotal results into findings, in the same shape as the red flags."""
    findings = []
    for result in vt_result:
        if result["status"] != "found":
            continue  # "never seen" or an error isn't evidence either way
        what = f"{result['kind']} {result['value'][:60]}"
        if result["malicious"] >= VT_CONFIDENT:
            findings.append(finding("vt_malicious", 6,
                f"VirusTotal: {result['malicious']} of {result['engines']} engines flag {what}"))
        elif result["malicious"] or result["suspicious"]:
            findings.append(finding("vt_suspicious", 2,
                f"VirusTotal: a few engines are wary of {what}"))
    return findings

def decide(findings):
    """Add up the evidence and decide if the email is suspicious or malicious."""
    score = sum(f["points"] for f in findings)

    # many security engines agreeing is strong enough evidence on its own.
    known_bad = any(f["check"] == "vt_malicious" for f in findings)

    if known_bad or score >= MALICIOUS_AT:
        verdict = "Malicious"
    elif score >= SUSPICIOUS_AT:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    # strongest evidence is VirusTotal, then red flags, then allowlist. If nothing is found, it's safe.
    reasons = sorted(findings, key=lambda f: f["points"], reverse=True)
    return {"verdict": verdict, "score": score, "reasons": reasons}
    