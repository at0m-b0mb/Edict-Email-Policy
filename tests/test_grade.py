"""End-to-end: read, judge, and the honesty ceiling that caps the letter."""

import base64
import os
import random

import pytest

from edict.core.grade import analyze, _cap, _letter_for_score
from edict.core.model import Severity, Stance

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def _sample(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return fh.read()


def _titles(zone):
    return {f.title for f in zone.findings}


def _stance(zone, key):
    return zone.pillar(key).stance


# --- a 2048-bit key to build synthetic zones around --------------------------

def _der_len(n):
    return bytes([n]) if n < 0x80 else (
        bytes([0x80 | ((n.bit_length() + 7) // 8)])
        + n.to_bytes((n.bit_length() + 7) // 8, "big"))


def _tlv(tag, body):
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(i):
    b = i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")
    return _tlv(0x02, b"\x00" + b if b[0] & 0x80 else b)


def key(bits=2048, seed=11):
    rng = random.Random(seed)
    n = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
    rsa = _tlv(0x30, _der_int(n) + _der_int(65537))
    alg = _tlv(0x30, bytes.fromhex("06092a864886f70d010101") + b"\x05\x00")
    return base64.b64encode(_tlv(0x30, alg + _tlv(0x03, b"\x00" + rsa))).decode()


def zone_text(spf="v=spf1 mx -all", dmarc="v=DMARC1; p=reject; rua=mailto:d@e.example",
              dkim=None, mx=True, caa=True):
    if dkim is None:
        dkim = f"v=DKIM1; k=rsa; p={key()}"
    lines = []
    if mx:
        lines.append("e.example. 300 IN MX 10 mail.e.example.")
    if spf:
        lines.append(f'e.example. 300 IN TXT "{spf}"')
    if dmarc:
        lines.append(f'_dmarc.e.example. 300 IN TXT "{dmarc}"')
    if dkim:
        lines.append(f's._domainkey.e.example. 300 IN TXT "{dkim}"')
    if caa:
        lines.append('e.example. 300 IN CAA 0 issue "ca.example"')
    return "\n".join(lines) + "\n"


# --- the letter scale --------------------------------------------------------

@pytest.mark.parametrize("score,letter", [
    (100, "A+"), (97, "A+"), (96, "A"), (93, "A"), (90, "A-"),
    (83, "B"), (73, "C"), (67, "D+"), (66, "D"), (60, "D-"), (59, "F"), (0, "F"),
])
def test_scores_fall_into_the_right_band(score, letter):
    assert _letter_for_score(score) == letter


def test_a_cap_can_only_lower_a_letter():
    assert _cap("A+", "B-") == "B-"
    assert _cap("D", "B-") == "D"
    assert _cap("C", "C") == "C"


# --- the samples -------------------------------------------------------------

def test_the_hardened_sample_is_the_only_one_that_reaches_the_top():
    zone = analyze(_sample("hardened.dns"))
    assert zone.grade.letter == "A+"
    assert zone.grade.score == 100
    assert all(p.stance is Stance.ENFORCING for p in zone.pillars)


def test_the_top_grade_still_requires_a_clean_sheet():
    zone = analyze(_sample("hardened.dns"))
    assert not any(f.severity.rank >= Severity.NOTICE.rank for f in zone.findings)


def test_the_monitoring_sample_lands_in_the_middle():
    zone = analyze(_sample("monitoring-only.dns"))
    assert zone.grade.letter[0] == "C"
    assert "DMARC is monitoring only (p=none)" in _titles(zone)
    assert _stance(zone, "dmarc") is Stance.PERMISSIVE


def test_the_subdomain_gap_sample_is_caught_despite_a_strong_apex():
    zone = analyze(_sample("subdomain-gap.dns"))
    assert zone.grade.letter[0] == "D"
    assert "Subdomains are weaker than the apex" in _titles(zone)
    assert _stance(zone, "spf") is Stance.ENFORCING   # the apex really is hard


def test_the_over_budget_sample_fails_on_one_line():
    zone = analyze(_sample("over-budget.dns"))
    assert zone.grade.letter[0] in ("D", "F")
    assert _stance(zone, "spf") is Stance.BROKEN
    assert zone.primary_spf.lookup_cost > 10


def test_the_wide_open_sample_fails():
    zone = analyze(_sample("wide-open.dns"))
    assert zone.grade.letter == "F"
    assert "SPF ends in +all — anyone may send as you" in _titles(zone)
    assert "No DMARC record" in _titles(zone)


def test_every_sample_grades_without_raising():
    for name in sorted(os.listdir(SAMPLES)):
        if name.endswith(".dns"):
            zone = analyze(_sample(name))
            assert zone.grade is not None
            assert len(zone.pillars) == 3


def test_the_samples_span_the_scale():
    letters = {analyze(_sample(n)).grade.letter
               for n in os.listdir(SAMPLES) if n.endswith(".dns")}
    assert "A+" in letters
    assert "F" in letters
    assert len(letters) >= 4


# --- the ceiling -------------------------------------------------------------

def test_every_grade_carries_a_ceiling_note():
    for name in sorted(os.listdir(SAMPLES)):
        if name.endswith(".dns"):
            note = analyze(_sample(name)).grade.ceiling_note
            assert note and len(note) > 80


def test_the_ceiling_says_the_lookup_count_is_a_floor():
    note = analyze(zone_text()).grade.ceiling_note
    assert "include: chains" in note
    assert "floor" in note


def test_the_ceiling_refuses_the_word_safe_as_a_verdict():
    note = analyze(zone_text()).grade.ceiling_note
    assert "never that your domain cannot be spoofed" in note


@pytest.mark.parametrize("name", ["hardened.dns", "monitoring-only.dns",
                                  "wide-open.dns", "over-budget.dns",
                                  "subdomain-gap.dns"])
def test_no_verdict_ever_calls_a_domain_secure(name):
    zone = analyze(_sample(name))
    blob = " ".join([zone.grade.headline] +
                    [f.title for f in zone.findings]).lower()
    assert "is secure" not in blob
    assert "is safe" not in blob
    assert "cannot be spoofed" not in blob


def test_a_missing_selector_caps_the_grade_rather_than_scoring_it():
    zone = analyze(zone_text(dkim=""))
    assert _stance(zone, "dkim") is Stance.UNKNOWN
    assert zone.grade.letter == "B-"
    assert "capped" in zone.grade.headline


def test_the_cap_does_not_rescue_a_bad_policy():
    zone = analyze(zone_text(spf="v=spf1 +all", dmarc="", dkim=""))
    assert zone.grade.letter == "F"


def test_a_domain_that_declares_nothing_is_an_f():
    zone = analyze("e.example. 300 IN MX 10 mail.e.example.\n")
    assert zone.grade.letter == "F"
    assert zone.grade.headline == "This domain declares nothing about its own mail"


def test_an_empty_paste_is_graded_f_without_inventing_findings():
    zone = analyze("   \n; nothing here\n")
    assert zone.grade.letter == "F"
    assert zone.grade.score == 0
    assert zone.findings == []
    assert zone.grade.ceiling_note


# --- findings ----------------------------------------------------------------

def test_findings_are_sorted_most_severe_first():
    zone = analyze(_sample("wide-open.dns"))
    ranks = [f.severity.rank for f in zone.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_good_and_info_findings_never_cost_points():
    for name in os.listdir(SAMPLES):
        if not name.endswith(".dns"):
            continue
        for f in analyze(_sample(name)).findings:
            if f.severity in (Severity.GOOD, Severity.INFO):
                assert f.points == 0, f.title


def test_every_finding_has_a_title_and_an_actionable_detail():
    for name in os.listdir(SAMPLES):
        if not name.endswith(".dns"):
            continue
        for f in analyze(_sample(name)).findings:
            assert f.title and not f.title.endswith(".")
            assert len(f.detail) > 40
            assert f.category in ("spf", "dmarc", "dkim", "zone", "general")


def test_the_score_is_exactly_what_the_findings_subtract():
    for name in os.listdir(SAMPLES):
        if not name.endswith(".dns"):
            continue
        zone = analyze(_sample(name))
        expected = max(0, min(100, 100 - sum(f.points for f in zone.findings)))
        assert zone.grade.score == expected


# --- SPF findings ------------------------------------------------------------

@pytest.mark.parametrize("spf,title", [
    ("v=spf1 mx -all", "SPF ends in -all"),
    ("v=spf1 mx ~all", "SPF ends in ~all, not -all"),
    ("v=spf1 mx ?all", "SPF ends in ?all and commits to nothing"),
    ("v=spf1 mx +all", "SPF ends in +all — anyone may send as you"),
    ("v=spf1 mx", "SPF never says what to do with everyone else"),
    ("v=spf1 ptr -all", "SPF uses the ptr mechanism"),
    ("v=spf1 ip4:0.0.0.0/0 -all", "An SPF range authorises the whole internet"),
    ("v=spf1 ip4:10.0.0.0/8 -all",
     "An SPF range is far wider than one mail estate"),
    ("v=spf1 -all mx", "SPF terms written after all can never match"),
    ("v=spf1 frobnicate -all", "SPF contains terms Edict does not recognise"),
    ("v=spf1 ip4:nonsense -all", "An SPF term is malformed"),
    ("v=spf1 -all redirect=o.example",
     "SPF has both an all mechanism and a redirect"),
    ("v=spf1 exp=w.example -all", "SPF publishes an explanation string"),
])
def test_an_spf_property_produces_its_finding(spf, title):
    assert title in _titles(analyze(zone_text(spf=spf)))


def test_a_missing_spf_record_is_an_alert():
    zone = analyze(zone_text(spf=""))
    assert "No SPF record" in _titles(zone)
    assert _stance(zone, "spf") is Stance.ABSENT


def test_two_spf_records_break_spf_entirely():
    text = zone_text() + 'e.example. 300 IN TXT "v=spf1 ip4:198.51.100.0/24 -all"\n'
    zone = analyze(text)
    assert "2 SPF records published" in _titles(zone)
    assert _stance(zone, "spf") is Stance.BROKEN


@pytest.mark.parametrize("count,title", [
    (2, "SPF fits in 3 of 10 DNS lookups"),
    (6, "SPF uses 7 of 10 DNS lookups"),
    (8, "SPF already uses 9 of 10 DNS lookups"),
    (11, "SPF needs 12 DNS lookups — the limit is 10"),
])
def test_the_budget_finding_tracks_the_count(count, title):
    spf = "v=spf1 mx " + " ".join(f"include:s{i}.example"
                                  for i in range(count)) + " -all"
    assert title in _titles(analyze(zone_text(spf=spf)))


def test_going_over_budget_breaks_spf_whatever_the_ending_says():
    spf = "v=spf1 " + " ".join(f"include:s{i}.example" for i in range(12)) + " -all"
    zone = analyze(zone_text(spf=spf))
    assert _stance(zone, "spf") is Stance.BROKEN
    assert "SPF ends in -all" in _titles(zone)   # still reported honestly


# --- DMARC findings ----------------------------------------------------------

@pytest.mark.parametrize("dmarc,title", [
    ("v=DMARC1; p=reject; rua=mailto:d@e.example", "DMARC is at p=reject"),
    ("v=DMARC1; p=quarantine; rua=mailto:d@e.example",
     "DMARC quarantines rather than rejects"),
    ("v=DMARC1; p=none; rua=mailto:d@e.example",
     "DMARC is monitoring only (p=none)"),
    ("v=DMARC1; rua=mailto:d@e.example", "The DMARC record has no usable policy"),
    ("v=DMARC1; p=reject", "DMARC asks for no aggregate reports"),
    ("v=DMARC1; p=reject; sp=none; rua=mailto:d@e.example",
     "Subdomains are weaker than the apex"),
    ("v=DMARC1; p=reject; pct=50; rua=mailto:d@e.example",
     "DMARC only applies to 50% of mail"),
    ("v=DMARC1; p=reject; pct=abc; rua=mailto:d@e.example",
     "The DMARC pct tag is not a valid percentage"),
    ("v=DMARC1; p=reject; rua=mailto:d@analytics.example",
     "DMARC reports go to another domain"),
    ("v=DMARC1; p=reject; ruf=mailto:f@e.example; rua=mailto:d@e.example",
     "DMARC also asks for failure reports"),
])
def test_a_dmarc_property_produces_its_finding(dmarc, title):
    assert title in _titles(analyze(zone_text(dmarc=dmarc)))


def test_a_missing_dmarc_record_is_an_alert():
    zone = analyze(zone_text(dmarc=""))
    assert "No DMARC record" in _titles(zone)
    assert _stance(zone, "dmarc") is Stance.ABSENT


def test_a_dmarc_record_in_the_wrong_place_is_broken():
    text = (zone_text(dmarc="") +
            'e.example. 300 IN TXT "v=DMARC1; p=reject; rua=mailto:d@e.example"\n')
    zone = analyze(text)
    assert "The DMARC record is not at _dmarc" in _titles(zone)
    assert _stance(zone, "dmarc") is Stance.BROKEN


def test_a_dmarc_record_with_no_owner_is_unknown_not_wrong():
    text = ('"v=spf1 mx -all"\n'
            '"v=DMARC1; p=reject; rua=mailto:d@e.example"\n'
            f'"v=DKIM1; k=rsa; p={key()}"\n')
    zone = analyze(text)
    assert "Edict cannot tell where this DMARC record lives" in _titles(zone)
    assert "The DMARC record is not at _dmarc" not in _titles(zone)


def test_two_dmarc_records_leave_the_domain_with_none():
    text = (zone_text() +
            '_dmarc.e.example. 300 IN TXT "v=DMARC1; p=none"\n')
    zone = analyze(text)
    assert "2 DMARC records published" in _titles(zone)
    assert _stance(zone, "dmarc") is Stance.BROKEN


def test_a_full_reject_without_an_sp_tag_still_enforces():
    zone = analyze(zone_text(dmarc="v=DMARC1; p=reject; rua=mailto:d@e.example"))
    assert _stance(zone, "dmarc") is Stance.ENFORCING
    assert "Subdomains inherit the apex DMARC policy" in _titles(zone)


def test_alignment_is_reported_once_when_both_sides_match():
    zone = analyze(zone_text(
        dmarc="v=DMARC1; p=reject; aspf=s; adkim=s; rua=mailto:d@e.example"))
    assert "Alignment is strict for both SPF and DKIM" in _titles(zone)


def test_alignment_is_reported_separately_when_they_differ():
    zone = analyze(zone_text(
        dmarc="v=DMARC1; p=reject; aspf=s; rua=mailto:d@e.example"))
    assert "Alignment is strict for SPF, relaxed for DKIM" in _titles(zone)


# --- DKIM findings -----------------------------------------------------------

@pytest.mark.parametrize("bits,title_part,severity", [
    (512, "512-bit RSA key", Severity.ALERT),
    (1024, "1024-bit RSA key", Severity.WARNING),
    (1536, "1536-bit RSA key", Severity.NOTICE),
    (2048, "2048-bit RSA key", Severity.GOOD),
    (4096, "4096-bit RSA key", Severity.GOOD),
])
def test_the_key_size_drives_the_severity(bits, title_part, severity):
    zone = analyze(zone_text(dkim=f"v=DKIM1; k=rsa; p={key(bits)}"))
    hits = [f for f in zone.findings if title_part in f.title]
    assert len(hits) == 1
    assert hits[0].severity is severity


@pytest.mark.parametrize("dkim,title", [
    ("v=DKIM1; k=rsa; p=", "The key for selector s is revoked"),
    ("v=DKIM1; k=rsa; p=!!!not base64!!!",
     "The key for selector s could not be read"),
    ("v=DKIM1; k=rsa", "selector s publishes no key"),
    ("v=DKIM1; k=elgamal; p=AA",
     "selector s uses an algorithm Edict does not know"),
])
def test_a_broken_key_produces_its_finding(dkim, title):
    assert title in _titles(analyze(zone_text(dkim=dkim)))


def test_the_testing_flag_is_reported_on_top_of_the_size():
    zone = analyze(zone_text(dkim=f"v=DKIM1; k=rsa; t=y; p={key(2048)}"))
    titles = _titles(zone)
    assert "selector s is flagged testing (t=y)" in titles
    assert "selector s has a 2048-bit RSA key" in titles
    assert _stance(zone, "dkim") is Stance.BROKEN


def test_a_sha1_only_key_is_a_warning():
    zone = analyze(zone_text(dkim=f"v=DKIM1; k=rsa; h=sha1; p={key(2048)}"))
    assert "selector s allows only sha1" in _titles(zone)


def test_a_missing_version_tag_is_noticed():
    zone = analyze(zone_text(dkim=f"k=rsa; p={key(2048)}"))
    assert "selector s has no v=DKIM1 tag" in _titles(zone)


def test_several_selectors_are_read_as_rotation():
    text = (zone_text() +
            f's2._domainkey.e.example. 300 IN TXT "v=DKIM1; k=rsa; p={key(2048, 3)}"\n')
    zone = analyze(text)
    assert "2 DKIM selectors published" in _titles(zone)


def test_a_strong_key_beside_a_weak_one_sets_the_stance():
    text = (zone_text(dkim=f"v=DKIM1; k=rsa; p={key(1024)}") +
            f's2._domainkey.e.example. 300 IN TXT "v=DKIM1; k=rsa; p={key(4096, 5)}"\n')
    assert _stance(analyze(text), "dkim") is Stance.ENFORCING


# --- the rest of the zone ----------------------------------------------------

def test_a_missing_mx_is_noticed():
    assert "No MX record among the records given" in _titles(
        analyze(zone_text(mx=False)))


def test_a_null_mx_is_read_as_a_deliberate_declaration():
    text = ('e.example. 300 IN MX 0 .\n'
            'e.example. 300 IN TXT "v=spf1 -all"\n'
            '_dmarc.e.example. 300 IN TXT "v=DMARC1; p=reject; rua=mailto:d@e.example"\n')
    assert "A null MX declares this domain handles no mail" in _titles(analyze(text))


def test_a_missing_caa_is_noticed():
    assert "No CAA record among the records given" in _titles(
        analyze(zone_text(caa=False)))


def test_caa_names_its_issuers():
    zone = analyze(zone_text())
    hits = [f for f in zone.findings
            if f.title == "CAA names the authorities allowed to issue"]
    assert hits and "ca.example" in hits[0].detail


def test_a_forbidding_caa_is_reported_without_praise():
    text = zone_text(caa=False) + 'e.example. 300 IN CAA 0 issue ";"\n'
    assert "CAA forbids all certificate issuance" in _titles(analyze(text))


def test_neighbouring_policies_are_reported_not_graded():
    text = zone_text() + '_mta-sts.e.example. 300 IN TXT "v=STSv1; id=1"\n'
    zone = analyze(text)
    hits = [f for f in zone.findings if "MTA-STS" in f.title]
    assert hits and hits[0].points == 0


def test_a_sender_id_record_is_recognised_as_withdrawn():
    text = zone_text() + 'e.example. 300 IN TXT "spf2.0/pra include:x.example -all"\n'
    assert "A Sender ID record is published alongside SPF" in _titles(analyze(text))


# --- the pillars -------------------------------------------------------------

@pytest.mark.parametrize("spf,stance", [
    ("v=spf1 mx -all", Stance.ENFORCING),
    ("v=spf1 mx ~all", Stance.PARTIAL),
    ("v=spf1 mx ?all", Stance.PERMISSIVE),
    ("v=spf1 mx", Stance.PERMISSIVE),
    ("v=spf1 mx +all", Stance.BROKEN),
    ("v=spf1 ip4:0.0.0.0/0 -all", Stance.BROKEN),
    ("v=spf1 redirect=o.example", Stance.UNKNOWN),
    ("", Stance.ABSENT),
])
def test_the_spf_pillar_says_how_far_the_record_commits(spf, stance):
    assert _stance(analyze(zone_text(spf=spf)), "spf") is stance


@pytest.mark.parametrize("dmarc,stance", [
    ("v=DMARC1; p=reject; rua=mailto:d@e.example", Stance.ENFORCING),
    ("v=DMARC1; p=reject; pct=50; rua=mailto:d@e.example", Stance.PARTIAL),
    ("v=DMARC1; p=reject; sp=none; rua=mailto:d@e.example", Stance.PARTIAL),
    ("v=DMARC1; p=quarantine; rua=mailto:d@e.example", Stance.PARTIAL),
    ("v=DMARC1; p=none; rua=mailto:d@e.example", Stance.PERMISSIVE),
    ("v=DMARC1; rua=mailto:d@e.example", Stance.BROKEN),
    ("", Stance.ABSENT),
])
def test_the_dmarc_pillar_says_how_far_the_policy_commits(dmarc, stance):
    assert _stance(analyze(zone_text(dmarc=dmarc)), "dmarc") is stance


def test_an_unreadable_key_leaves_dkim_unknown_rather_than_condemned():
    zone = analyze(zone_text(dkim="v=DKIM1; k=rsa; p=!!!"))
    assert _stance(zone, "dkim") is Stance.UNKNOWN


def test_every_stance_has_a_word_and_a_colour_token():
    for stance in Stance:
        assert stance.word and stance.word.isupper()
        assert stance.token.startswith("sev_")


def test_the_pillars_are_always_the_same_three_in_the_same_order():
    for name in os.listdir(SAMPLES):
        if name.endswith(".dns"):
            zone = analyze(_sample(name))
            assert [p.key for p in zone.pillars] == ["spf", "dkim", "dmarc"]


# --- shapes of input ---------------------------------------------------------

def test_mixed_shapes_in_one_paste_all_land():
    text = (
        'v=spf1 mx -all\n'
        '_dmarc.e.example. 300 IN TXT "v=DMARC1; p=reject; rua=mailto:d@e.example"\n'
        f'"v=DKIM1; k=rsa; p={key()}"\n'
        'e.example. 300 IN MX 10 mail.e.example.\n'
        'e.example. IN CAA 0 issue "ca.example"\n'
    )
    zone = analyze(text)
    assert len(zone.spf) == len(zone.dmarc) == len(zone.dkim) == 1
    assert len(zone.mx) == len(zone.caa) == 1


def test_grading_is_deterministic():
    text = _sample("subdomain-gap.dns")
    first, second = analyze(text), analyze(text)
    assert first.grade == second.grade
    assert [f.title for f in first.findings] == [f.title for f in second.findings]


def test_the_domain_is_inferred_from_the_records():
    assert analyze(zone_text()).domain == "e.example"


def test_no_domain_is_invented_when_the_paste_has_no_owner_names():
    assert analyze('"v=spf1 -all"\n').domain == ""
