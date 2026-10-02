"""Reading the paste: shapes, quotes, continuations, classification."""

import pytest

from edict.core.records import (
    _apex_of,
    infer_domain,
    join_continuations,
    parse_caa,
    parse_line,
    parse_mx,
    parse_records,
    read_zone,
)
from edict.core.model import RecordKind


# --- shapes ------------------------------------------------------------------

def test_bare_policy_string_has_no_owner():
    rec = parse_line("v=spf1 include:_spf.example.com ~all")
    assert rec.kind is RecordKind.SPF
    assert rec.owner == ""
    assert rec.value == "v=spf1 include:_spf.example.com ~all"


def test_zone_line_gives_owner_ttl_class_type():
    rec = parse_line('example.com.  300  IN  TXT  "v=spf1 -all"')
    assert rec.owner == "example.com."
    assert rec.rtype == "TXT"
    assert rec.value == "v=spf1 -all"


def test_zone_line_without_ttl_or_class():
    rec = parse_line('example.com. TXT "v=spf1 -all"')
    assert rec.owner == "example.com."
    assert rec.rtype == "TXT"


def test_dig_short_output_is_just_a_quoted_string():
    rec = parse_line('"v=DMARC1; p=none; rua=mailto:a@b.example"')
    assert rec.kind is RecordKind.DMARC
    assert rec.owner == ""
    assert rec.value.startswith("v=DMARC1;")


def test_split_txt_chunks_are_joined_with_nothing_between():
    rec = parse_line('example.com. IN TXT "v=DKIM1; k=rsa; " "p=ABCD"')
    assert rec.value == "v=DKIM1; k=rsa; p=ABCD"
    assert rec.chunks == 2


def test_parentheses_are_dropped():
    rec = parse_line('example.com. IN TXT ( "v=spf1 " "-all" )')
    assert rec.value == "v=spf1 -all"


def test_escaped_quote_inside_a_string_survives():
    rec = parse_line(r'example.com. IN TXT "a\"b"')
    assert rec.value == 'a"b'


def test_unterminated_quote_does_not_crash():
    rec = parse_line('example.com. IN TXT "v=spf1 -all')
    assert rec.value == "v=spf1 -all"


def test_blank_and_comment_lines_are_skipped():
    recs = parse_records("\n; a comment\n# another\n\nv=spf1 -all\n")
    assert len(recs) == 1


def test_a_semicolon_inside_a_record_is_not_a_comment():
    recs = parse_records('"v=DMARC1; p=reject; rua=mailto:a@b.example"')
    assert len(recs) == 1
    assert "rua=" in recs[0].value


def test_line_numbers_point_at_the_original_text():
    recs = parse_records("\n\n; note\nv=spf1 -all\n")
    assert recs[0].line_no == 4


# --- continuations -----------------------------------------------------------

def test_continuation_joins_wrapped_lines():
    text = 'sel._domainkey.example.com. IN TXT ( "v=DKIM1; "\n    "k=rsa; p=AA" )'
    joined = join_continuations(text)
    assert len(joined) == 1
    assert joined[0][0] == 1


def test_continuation_record_parses_as_one_dkim_record():
    text = 'sel._domainkey.example.com. IN TXT ( "v=DKIM1; k=rsa; "\n "p=AA" )'
    recs = parse_records(text)
    assert len(recs) == 1
    assert recs[0].kind is RecordKind.DKIM
    assert recs[0].value == "v=DKIM1; k=rsa; p=AA"


def test_unclosed_paren_at_end_of_input_is_still_returned():
    joined = join_continuations('example.com. IN TXT ( "v=spf1 -all"')
    assert len(joined) == 1


def test_a_paren_inside_a_quoted_string_is_not_grouping():
    recs = parse_records('example.com. IN TXT "v=spf1 exp=a(b) -all"')
    assert len(recs) == 1
    assert "(b)" in recs[0].value


# --- classification ----------------------------------------------------------

@pytest.mark.parametrize("line,kind", [
    ("v=spf1 -all", RecordKind.SPF),
    ("v=DMARC1; p=none", RecordKind.DMARC),
    ("v=DKIM1; k=rsa; p=AA", RecordKind.DKIM),
    ("example.com. IN MX 10 mail.example.com.", RecordKind.MX),
    ('example.com. IN CAA 0 issue "letsencrypt.org"', RecordKind.CAA),
    ('example.com. IN TXT "google-site-verification=abc"', RecordKind.TXT),
    ("example.com. IN A 198.51.100.1", RecordKind.OTHER),
])
def test_records_are_classified_by_what_they_say(line, kind):
    assert parse_line(line).kind is kind


def test_the_version_tag_is_case_insensitive():
    assert parse_line("V=SPF1 -all").kind is RecordKind.SPF
    assert parse_line("v=dmarc1; p=none").kind is RecordKind.DMARC


def test_a_dkim_record_without_a_version_tag_is_found_by_its_owner():
    rec = parse_line("sel._domainkey.example.com. IN TXT \"k=rsa; p=AA\"")
    assert rec.kind is RecordKind.DKIM


def test_a_dmarc_record_without_a_version_tag_is_found_by_its_owner():
    rec = parse_line('_dmarc.example.com. IN TXT "p=reject"')
    assert rec.kind is RecordKind.DMARC


def test_the_v_tag_is_lifted_onto_the_record():
    assert parse_line('"v=STSv1; id=20260101000000Z"').tag == "STSv1"


# --- MX and CAA fields -------------------------------------------------------

def test_mx_keeps_its_preference_and_host():
    mx = parse_mx(parse_line("example.com. 300 IN MX 10 mail.example.com."))
    assert mx.preference == 10
    assert mx.host == "mail.example.com"
    assert not mx.is_null


def test_a_null_mx_is_recognised():
    mx = parse_mx(parse_line("example.com. IN MX 0 ."))
    assert mx.is_null


def test_caa_keeps_all_three_fields_despite_the_quoted_value():
    caa = parse_caa(parse_line('example.com. IN CAA 0 issue "letsencrypt.org"'))
    assert (caa.flags, caa.tag, caa.value) == (0, "issue", "letsencrypt.org")


def test_caa_iodef_value_survives():
    caa = parse_caa(parse_line('example.com. IN CAA 0 iodef "mailto:a@b.example"'))
    assert caa.tag == "iodef"
    assert caa.value == "mailto:a@b.example"


def test_a_mixed_quoted_record_is_not_treated_as_chunked():
    rec = parse_line('example.com. IN CAA 0 issue "letsencrypt.org"')
    assert rec.chunks == 1
    assert rec.value == '0 issue letsencrypt.org'


# --- the shapes `dig +short` prints for MX and CAA ---------------------------
# No owner, no RR type, nothing but the data. Typing these on sight is what
# keeps the grader from telling a reader they pasted no MX when they plainly
# did — but only an unquoted line is guessed at, because a quoted string is TXT
# data whatever it happens to look like.

@pytest.mark.parametrize("line,pref,host", [
    ("10 mail.example.com.", 10, "mail.example.com"),
    ("0 .", 0, "."),
    ("20 alt2.aspmx.l.google.com.", 20, "alt2.aspmx.l.google.com"),
])
def test_a_bare_dig_short_mx_line_is_typed_as_an_mx(line, pref, host):
    rec = parse_line(line)
    assert rec.kind is RecordKind.MX
    mx = parse_mx(rec)
    assert (mx.preference, mx.host) == (pref, host)


@pytest.mark.parametrize("line,tag,value", [
    ('0 issue "letsencrypt.org"', "issue", "letsencrypt.org"),
    ('128 issuewild "sectigo.com"', "issuewild", "sectigo.com"),
    ('0 iodef "mailto:a@b.example"', "iodef", "mailto:a@b.example"),
])
def test_a_bare_dig_short_caa_line_is_typed_as_a_caa(line, tag, value):
    rec = parse_line(line)
    assert rec.kind is RecordKind.CAA
    caa = parse_caa(rec)
    assert (caa.tag, caa.value) == (tag, value)


@pytest.mark.parametrize("line", [
    '"10 mail.example.com."',            # quoted: TXT data, not an MX
    '"0 issue \\"letsencrypt.org\\""',   # quoted: TXT data, not a CAA
    "10 reasons",                        # a host name has a dot in it
    "v=spf1 -all",                       # a policy, which wins on its v= tag
    "0 frobnicate \"x.example\"",        # not a CAA property tag
    "10 mail.example.com. extra",        # too many fields for an MX
    "70000 mail.example.com.",           # not a preference a zone can hold
])
def test_a_line_that_is_not_one_of_those_shapes_is_not_guessed_at(line):
    assert parse_line(line).kind is not RecordKind.MX
    assert parse_line(line).kind is not RecordKind.CAA


# --- which domain ------------------------------------------------------------

@pytest.mark.parametrize("owner,apex", [
    ("example.com.", "example.com"),
    ("_dmarc.example.com.", "example.com"),
    ("sel._domainkey.example.com.", "example.com"),
    ("a.b._domainkey.example.com.", "example.com"),
    ("_mta-sts.example.com.", "example.com"),
    ("_smtp._tls.example.com.", "example.com"),
    ("", ""),
])
def test_underscore_labels_are_stripped_to_find_the_apex(owner, apex):
    assert _apex_of(owner) == apex


def test_the_most_named_domain_wins():
    recs = parse_records(
        "a.example. IN TXT \"v=spf1 -all\"\n"
        "_dmarc.a.example. IN TXT \"v=DMARC1; p=none\"\n"
        "other.example. IN TXT \"x=1\"\n")
    assert infer_domain(recs) == "a.example"


def test_no_owner_names_means_no_domain_is_invented():
    recs = parse_records('"v=spf1 -all"\n"v=DMARC1; p=none"\n')
    assert infer_domain(recs) == ""


# --- the whole paste ---------------------------------------------------------

def test_read_zone_sorts_mx_by_preference():
    zone = read_zone("e. IN MX 20 b.e.\ne. IN MX 10 a.e.\n")
    assert [m.preference for m in zone.mx] == [10, 20]


def test_read_zone_files_each_record_in_its_own_list():
    zone = read_zone(
        'e.example. IN TXT "v=spf1 -all"\n'
        '_dmarc.e.example. IN TXT "v=DMARC1; p=reject"\n'
        's._domainkey.e.example. IN TXT "v=DKIM1; k=rsa; p=AA"\n'
        'e.example. IN MX 10 m.e.example.\n'
        'e.example. IN CAA 0 issue "x.example"\n'
        'e.example. IN TXT "unrelated=1"\n')
    assert len(zone.spf) == 1 and len(zone.dmarc) == 1 and len(zone.dkim) == 1
    assert len(zone.mx) == 1 and len(zone.caa) == 1 and len(zone.other) == 1


def test_ungraded_lines_are_accounted_for_in_the_notes():
    zone = read_zone('e.example. IN TXT "verification=abc"\n')
    assert zone.notes and "line 1" in zone.notes[0]


def test_a_recognised_neighbour_policy_is_not_repeated_in_the_notes():
    zone = read_zone('_mta-sts.e.example. IN TXT "v=STSv1; id=1"\n')
    assert zone.notes == []


def test_an_empty_paste_makes_an_empty_zone():
    zone = read_zone("   \n\n; only a comment\n")
    assert zone.is_empty
    assert zone.records == []


# --- the trap: SPF mechanisms that are also RR types -------------------------
# ``mx``, ``a`` and ``ptr`` name both an SPF mechanism and a DNS record type, so
# a bare policy string is one careless split away from being torn in half.

@pytest.mark.parametrize("line", [
    "v=spf1 mx -all",
    "v=spf1 a -all",
    "v=spf1 a mx ptr -all",
    "v=spf1 mx:mail.example.com -all",
    "v=spf1 ns -all",
])
def test_a_bare_spf_string_is_never_split_on_its_own_mechanisms(line):
    rec = parse_line(line)
    assert rec.kind is RecordKind.SPF
    assert rec.owner == ""
    assert rec.rtype == ""
    assert rec.value == line


def test_a_quoted_bare_spf_string_with_mx_survives_too():
    rec = parse_line('"v=spf1 a mx -all"')
    assert rec.kind is RecordKind.SPF
    assert rec.value == "v=spf1 a mx -all"


def test_a_real_zone_line_is_still_split():
    rec = parse_line("example.com. 300 IN MX 10 mail.example.com.")
    assert rec.rtype == "MX"
    assert rec.owner == "example.com."


def test_an_rr_type_with_no_owner_at_all_is_accepted():
    rec = parse_line('TXT "v=spf1 -all"')
    assert rec.rtype == "TXT"
    assert rec.owner == ""


@pytest.mark.parametrize("tok,ok", [
    ("example.com.", True), ("_dmarc.example.com.", True), ("*.example.com", True),
    ("@", True), ("v=spf1", False), ("include:a.example", False),
    ("ip4:1.2.3.0/24", False), ("", False),
])
def test_owner_tokens_are_told_apart_from_policy_terms(tok, ok):
    from edict.core.records import _looks_like_owner
    assert _looks_like_owner(tok) is ok


def test_an_spf_record_in_a_zone_line_keeps_both_its_owner_and_its_mechanisms():
    rec = parse_line('example.com. 300 IN TXT "v=spf1 a mx ptr -all"')
    assert rec.owner == "example.com."
    assert rec.value == "v=spf1 a mx ptr -all"
