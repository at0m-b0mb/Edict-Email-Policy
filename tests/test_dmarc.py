"""DMARC: tags, where the record lives, and who the reports go to."""

import pytest

from edict.core.dmarc import (
    external_report_domains,
    parse_dmarc,
    policy_rank,
    report_domains,
)


def d(text, owner="_dmarc.example.com."):
    return parse_dmarc(text, owner)


# --- tags --------------------------------------------------------------------

def test_a_minimal_record_parses():
    policy = d("v=DMARC1; p=none")
    assert policy.version_ok
    assert policy.p == "none"


def test_tag_names_fold_to_lower_case():
    assert d("v=DMARC1; P=Reject").tags["p"] == "Reject"


def test_whitespace_around_tags_is_ignored():
    assert d("v=DMARC1 ;  p = reject ;  pct = 50 ").p == "reject"


def test_a_repeated_tag_keeps_the_first_as_a_receiver_would():
    assert d("v=DMARC1; p=reject; p=none").p == "reject"


def test_a_trailing_semicolon_is_harmless():
    assert d("v=DMARC1; p=reject;").p == "reject"


def test_the_version_must_be_dmarc1():
    assert not d("v=DMARC2; p=none").version_ok
    assert not d("p=none").version_ok


def test_an_unknown_tag_is_kept_and_not_merged_in():
    policy = d("v=DMARC1; p=none; wiggle=1")
    assert policy.unknown_tags == ["wiggle=1"]
    assert "wiggle" not in policy.tags


def test_a_tag_without_an_equals_sign_is_unknown():
    assert d("v=DMARC1; p=none; junk").unknown_tags == ["junk"]


# --- the policy --------------------------------------------------------------

@pytest.mark.parametrize("name,rank", [
    ("none", 0), ("quarantine", 1), ("reject", 2),
    ("REJECT", 2), ("", -1), ("nonsense", -1),
])
def test_policies_rank_weakest_to_strongest(name, rank):
    assert policy_rank(name) == rank


def test_pct_defaults_to_a_hundred():
    assert d("v=DMARC1; p=reject").pct == 100


def test_pct_is_read_as_a_number():
    assert d("v=DMARC1; p=reject; pct=25").pct == 25


@pytest.mark.parametrize("value", ["abc", "-1", "101"])
def test_an_out_of_range_pct_is_invalid(value):
    assert not d(f"v=DMARC1; p=reject; pct={value}").pct_valid


def test_a_missing_pct_is_valid():
    assert d("v=DMARC1; p=reject").pct_valid


def test_subdomains_inherit_the_apex_policy_when_sp_is_absent():
    assert d("v=DMARC1; p=reject").effective_sp == "reject"


def test_sp_overrides_what_subdomains_get():
    assert d("v=DMARC1; p=reject; sp=none").effective_sp == "none"


@pytest.mark.parametrize("tag,default", [("aspf", "r"), ("adkim", "r")])
def test_alignment_defaults_to_relaxed(tag, default):
    assert getattr(d("v=DMARC1; p=none"), tag) == default


def test_strict_alignment_is_read():
    policy = d("v=DMARC1; p=none; aspf=s; adkim=s")
    assert policy.aspf == "s" and policy.adkim == "s"


# --- where it lives ----------------------------------------------------------

def test_a_record_at_dmarc_is_recognised():
    assert d("v=DMARC1; p=none", "_dmarc.example.com.").at_dmarc is True


def test_a_bare_dmarc_label_counts():
    assert d("v=DMARC1; p=none", "_dmarc").at_dmarc is True


def test_a_record_at_the_apex_is_in_the_wrong_place():
    assert d("v=DMARC1; p=none", "example.com.").at_dmarc is False


def test_a_line_with_no_owner_leaves_the_location_unknown():
    assert parse_dmarc("v=DMARC1; p=none", "").at_dmarc is None


def test_the_governed_domain_is_derived_from_the_dmarc_owner():
    assert d("v=DMARC1; p=none", "_dmarc.example.com.").domain == "example.com"


def test_the_domain_is_empty_when_no_owner_was_given():
    assert parse_dmarc("v=DMARC1; p=none", "").domain == ""


# --- reporting ---------------------------------------------------------------

def test_rua_splits_on_commas():
    policy = d("v=DMARC1; p=none; rua=mailto:a@x.example,mailto:b@y.example")
    assert policy.rua == ["mailto:a@x.example", "mailto:b@y.example"]


def test_a_missing_rua_is_an_empty_list():
    assert d("v=DMARC1; p=none").rua == []


def test_ruf_is_read_separately():
    assert d("v=DMARC1; p=none; ruf=mailto:f@x.example").ruf == \
        ["mailto:f@x.example"]


def test_report_domains_are_pulled_out_of_the_mailto_uris():
    policy = d("v=DMARC1; p=none; rua=mailto:a@x.example,mailto:b@y.example")
    assert report_domains(policy) == ["x.example", "y.example"]


def test_a_size_limit_on_a_report_uri_is_stripped():
    policy = d("v=DMARC1; p=none; rua=mailto:a@x.example!10m")
    assert report_domains(policy) == ["x.example"]


def test_reports_to_the_same_domain_are_not_external():
    policy = d("v=DMARC1; p=none; rua=mailto:a@example.com",
               "_dmarc.example.com.")
    assert external_report_domains(policy) == []


def test_reports_to_a_subdomain_are_not_external():
    policy = d("v=DMARC1; p=none; rua=mailto:a@reports.example.com",
               "_dmarc.example.com.")
    assert external_report_domains(policy) == []


def test_reports_to_somebody_else_are_external():
    policy = d("v=DMARC1; p=none; rua=mailto:a@analytics.example",
               "_dmarc.example.com.")
    assert external_report_domains(policy) == ["analytics.example"]


def test_nothing_is_external_when_the_domain_is_unknown():
    policy = parse_dmarc("v=DMARC1; p=none; rua=mailto:a@x.example", "")
    assert external_report_domains(policy) == []
