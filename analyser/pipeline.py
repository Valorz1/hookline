from analyser.checks import good_signs, run_checks
from analyser.observables import extract_observables
from analyser.verdict import decide, vt_findings, vt_good_signs
from analyser.virustotal import choose_targets, lookup


def analyse(parsed, use_virustotal=False, on_lookup=None, should_stop=None):
    """Run every step of the analysis on a parsed email.

    This is the one place the steps are defined. main.py, inbox.py,
    app.py and scripts/measure_accuracy.py all call this, so they can never disagree.

    Args:
        parsed (dict): an email from read_email() or parse_email_bytes().
        use_virustotal (bool): also look the evidence up on VirusTotal (slow).
        on_lookup (function, optional): called with each VirusTotal result
            as soon as it arrives, e.g. to print it or show it on a web page.
        should_stop (function, optional): checked before each lookup; return
            True to skip the rest, e.g. because nobody is watching any more.

    Returns:
        dict: "found", "findings", "vt_results", "vt_stopped" (True if
        should_stop cut the lookups short) and "outcome".
    """
    found = extract_observables(parsed)
    findings = run_checks(parsed, found)

    vt_results = []
    vt_stopped = False
    if use_virustotal:
        for kind, value in choose_targets(found, parsed["attachments"]):
            if should_stop and should_stop():
                vt_stopped = True
                break
            result = lookup(kind, value)
            vt_results.append(result)
            if on_lookup:
                on_lookup(result)

    outcome = decide(findings + vt_findings(vt_results),
                     good_signs(parsed, found) + vt_good_signs(vt_results))
    return {"found": found, "findings": findings, "vt_results": vt_results,
            "vt_stopped": vt_stopped, "outcome": outcome}
