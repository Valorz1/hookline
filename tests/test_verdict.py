from analyser.checks import finding
from analyser.verdict import decide, vt_findings, vt_good_signs, vt_level


def vt(value, malicious, suspicious=0, kind="domain"):
    return {"kind": kind, "value": value, "status": "found",
            "malicious": malicious, "suspicious": suspicious, "engines": 90}


def test_vt_levels():
    assert vt_level(vt("a.example", 0)) == "clean"
    assert vt_level(vt("a.example", 1)) == "weak"
    assert vt_level(vt("a.example", 0, suspicious=2)) == "weak"
    assert vt_level(vt("a.example", 3)) == "warn"
    assert vt_level(vt("a.example", 9)) == "bad"
    assert vt_level({"kind": "url", "value": "x", "status": "not_found"}) is None


def test_one_engine_alone_is_weak_evidence():
    assert [f["points"] for f in vt_findings([vt("tracker.example", 1)])] == [1]


def test_many_engines_are_enough_on_their_own():
    outcome = decide(vt_findings([vt("evil.example", 11)]))
    assert outcome["verdict"] == "Malicious"


def test_one_website_counts_once():
    results = [vt("evil.example", 11),
               vt("http://evil.example/a", 11, kind="url"),
               vt("http://evil.example/b", 11, kind="url")]
    # The domain and both links to it are one website
    assert len(vt_findings(results)) == 1


def test_score_thresholds():
    assert decide([finding("x", 1, "")])["verdict"] == "Safe"
    assert decide([finding("x", 2, "")])["verdict"] == "Suspicious"
    assert decide([finding("x", 3, ""), finding("y", 3, "")])["verdict"] == "Malicious"


def test_vt_good_sign_only_when_everything_is_clean():
    assert vt_good_signs([vt("a.example", 0), vt("b.example", 0)])
    assert not vt_good_signs([vt("a.example", 0), vt("b.example", 1)])
    assert not vt_good_signs([])
