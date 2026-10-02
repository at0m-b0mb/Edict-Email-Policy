"""SPF: evaluation order, the ending, and the ten-lookup budget."""

import pytest

from edict.core.model import SPF_LOOKUP_LIMIT
from edict.core.spf import (
    budget_line,
    covers_everything,
    ip_prefix_len,
    modifier_note,
    parse_spf,
)


def p(text):
    return parse_spf(text)


# --- mechanisms --------------------------------------------------------------

def test_the_version_tag_must_come_first():
    assert p("v=spf1 -all").version_ok
    assert not p("include:a.example v=spf1 -all").version_ok


def test_mechanisms_keep_the_order_they_were_written_in():
    policy = p("v=spf1 ip4:198.51.100.0/24 mx include:a.example -all")
    assert [m.kind for m in policy.mechanisms] == ["ip4", "mx", "include", "all"]


@pytest.mark.parametrize("term,qualifier", [
    ("all", "+"), ("+all", "+"), ("-all", "-"), ("~all", "~"), ("?all", "?"),
])
def test_a_missing_qualifier_means_pass(term, qualifier):
    assert p(f"v=spf1 {term}").mechanisms[0].qualifier == qualifier


def test_a_mechanism_argument_is_split_on_a_colon():
    mech = p("v=spf1 include:_spf.example.com -all").mechanisms[0]
    assert mech.kind == "include"
    assert mech.value == "_spf.example.com"


def test_a_cidr_suffix_without_a_colon_stays_with_the_mechanism():
    mech = p("v=spf1 a/24 -all").mechanisms[0]
    assert mech.kind == "a"
    assert mech.value == "/24"


def test_bare_a_and_mx_carry_no_argument():
    policy = p("v=spf1 a mx -all")
    assert policy.mechanisms[0].value == ""
    assert policy.mechanisms[1].value == ""


@pytest.mark.parametrize("term,rendered", [
    ("include:a.example", "include:a.example"),
    ("-all", "-all"),
    ("~all", "~all"),
    ("mx", "mx"),
    ("ip4:198.51.100.0/24", "ip4:198.51.100.0/24"),
])
def test_a_mechanism_renders_back_to_what_it_was(term, rendered):
    assert p(f"v=spf1 {term}").mechanisms[0].rendered == rendered


# --- the ending --------------------------------------------------------------

@pytest.mark.parametrize("text,qualifier", [
    ("v=spf1 -all", "-"),
    ("v=spf1 ~all", "~"),
    ("v=spf1 ?all", "?"),
    ("v=spf1 +all", "+"),
    ("v=spf1 mx", None),
])
def test_the_ending_is_read_off_the_first_all(text, qualifier):
    assert p(text).all_qualifier == qualifier


def test_the_first_all_decides_because_the_second_is_unreachable():
    policy = p("v=spf1 -all +all")
    assert policy.all_qualifier == "-"
    assert [m.rendered for m in policy.unreachable] == ["+all"]


def test_terms_before_all_are_reachable():
    assert p("v=spf1 mx include:a.example -all").unreachable == []


# --- the budget --------------------------------------------------------------

@pytest.mark.parametrize("term,cost", [
    ("include:a.example", 1), ("a", 1), ("mx", 1), ("ptr", 1),
    ("exists:%{i}.a.example", 1),
    ("ip4:198.51.100.0/24", 0), ("ip6:2001:db8::/32", 0), ("-all", 0),
])
def test_only_mechanisms_that_ask_dns_a_question_cost_a_lookup(term, cost):
    assert p(f"v=spf1 {term}").lookup_cost == cost


def test_redirect_costs_a_lookup_when_there_is_no_all_to_ignore_it():
    policy = p("v=spf1 redirect=other.example")
    assert not policy.redirect_ignored
    assert policy.lookup_cost == 1


def test_exp_costs_nothing_because_it_is_only_read_on_failure():
    assert p("v=spf1 exp=why.example -all").lookup_cost == 0
    assert p("v=spf1 exp=why.example -all").modifiers["exp"] == "why.example"


def test_the_budget_is_the_sum_of_every_spender():
    policy = p("v=spf1 a mx include:one.example include:two.example "
               "ip4:198.51.100.0/24 -all")
    assert policy.lookup_cost == 4


def test_a_record_can_cost_more_than_the_limit():
    text = "v=spf1 " + " ".join(f"include:s{i}.example" for i in range(13)) + " ~all"
    assert p(text).lookup_cost == 13 > SPF_LOOKUP_LIMIT


def test_the_spenders_are_listed_in_evaluation_order():
    policy = p("v=spf1 ip4:198.51.100.0/24 mx include:a.example -all")
    assert [m.rendered for m in policy.costly] == ["mx", "include:a.example"]


def test_a_redirect_appears_last_among_the_spenders():
    policy = p("v=spf1 mx redirect=other.example")
    assert [m.rendered for m in policy.costly] == ["mx", "redirect=other.example"]


def test_a_synthesised_redirect_is_spelled_the_way_spf_spells_it():
    """``redirect=host``, with an equals sign. ``redirect:host`` is not SPF."""
    cell = p("v=spf1 mx redirect=other.example").costly[-1]
    assert cell.rendered == "redirect=other.example"
    assert ":" not in cell.rendered


# RFC 7208 §6.1: "if the record has an all mechanism, the redirect modifier MUST
# be ignored". A lookup a receiver will never make cannot be spent, and a budget
# that charges for one is not counting the thing the gauge claims to count.

def test_an_all_mechanism_makes_the_redirect_free():
    policy = p("v=spf1 mx -all redirect=o.example")
    assert policy.redirect_ignored
    assert policy.lookup_cost == 1
    assert [m.rendered for m in policy.costly] == ["mx"]


def test_an_ignored_redirect_cannot_push_a_record_over_budget():
    text = ("v=spf1 " + " ".join(f"include:s{i}.example" for i in range(10))
            + " -all redirect=legacy.example")
    policy = p(text)
    assert policy.lookup_cost == SPF_LOOKUP_LIMIT
    assert "redirect" not in " ".join(m.rendered for m in policy.costly)


def test_the_all_may_sit_anywhere_in_the_record_to_ignore_a_redirect():
    # The RFC says "has an all mechanism", not "ends in one".
    assert p("v=spf1 -all mx redirect=o.example").redirect_ignored
    assert p("v=spf1 ?all redirect=o.example").redirect_ignored


def test_a_record_with_a_redirect_and_no_all_still_pays_for_both():
    policy = p("v=spf1 mx redirect=other.example")
    assert not policy.redirect_ignored
    assert policy.lookup_cost == 2


@pytest.mark.parametrize("record,name,note", [
    ("v=spf1 mx redirect=o.example", "redirect", "1 lookup"),
    ("v=spf1 mx -all redirect=o.example", "redirect",
     "ignored — all matches first"),
    ("v=spf1 exp=why.example -all", "exp", "no lookup"),
])
def test_the_evaluation_table_agrees_with_the_budget_about_a_modifier(
        record, name, note):
    assert modifier_note(p(record), name) == note


# --- addresses ---------------------------------------------------------------

@pytest.mark.parametrize("term", [
    "ip4:198.51.100.0/24", "ip4:198.51.100.7", "ip6:2001:db8::/32", "ip6:::1",
])
def test_well_formed_addresses_are_accepted(term):
    assert p(f"v=spf1 {term} -all").malformed == []


@pytest.mark.parametrize("term", [
    "ip4:not-an-address", "ip4:2001:db8::/32", "ip6:198.51.100.0/24",
    "ip4:198.51.100.0/99", "ip4:",
])
def test_malformed_addresses_are_flagged_not_counted(term):
    policy = p(f"v=spf1 {term} -all")
    assert policy.malformed == [term]
    assert all(m.kind != "ip4" and m.kind != "ip6" for m in policy.mechanisms)


@pytest.mark.parametrize("term,expected", [
    ("ip4:0.0.0.0/0", True), ("ip6:::/0", True),
    ("ip4:198.51.100.0/24", False), ("-ip4:0.0.0.0/0", False),
])
def test_a_zero_length_prefix_is_plus_all_in_disguise(term, expected):
    assert covers_everything(p(f"v=spf1 {term} -all").mechanisms[0]) is expected


def test_the_prefix_length_is_readable_for_the_grader():
    mech = p("v=spf1 ip4:10.0.0.0/8 -all").mechanisms[0]
    assert ip_prefix_len(mech) == 8


def test_a_bare_address_has_a_full_length_prefix():
    assert ip_prefix_len(p("v=spf1 ip4:198.51.100.7 -all").mechanisms[0]) == 32


def test_a_non_address_mechanism_has_no_prefix_length():
    assert ip_prefix_len(p("v=spf1 mx -all").mechanisms[0]) is None


# --- syntax ------------------------------------------------------------------

def test_an_unknown_mechanism_is_kept_as_an_unknown_term():
    policy = p("v=spf1 frobnicate:a.example -all")
    assert policy.unknown_terms == ["frobnicate:a.example"]


def test_an_unknown_modifier_is_kept_as_an_unknown_term():
    assert p("v=spf1 wiggle=1 -all").unknown_terms == ["wiggle=1"]


def test_an_include_with_no_argument_is_malformed():
    assert p("v=spf1 include -all").malformed == ["include"]


def test_a_bare_qualifier_is_an_unknown_term():
    assert p("v=spf1 - -all").unknown_terms == ["-"]


def test_a_very_long_single_string_is_noticed():
    long = "v=spf1 " + " ".join(f"ip4:198.51.{i}.0/24" for i in range(20)) + " -all"
    assert p(long).long_string
    assert not parse_spf(long, chunks=2).long_string


def test_a_short_record_is_not_flagged_as_a_long_string():
    assert not p("v=spf1 -all").long_string


# --- the sentence under the gauge -------------------------------------------

def test_the_budget_line_always_says_the_count_is_a_floor():
    line = budget_line(p("v=spf1 mx -all"), SPF_LOOKUP_LIMIT)
    assert "1 of 10 used" in line
    assert "at least" in line
    assert "include: chains are not followed" in line


def test_the_budget_line_says_so_when_it_is_over():
    text = "v=spf1 " + " ".join(f"include:s{i}.example" for i in range(12)) + " ~all"
    line = budget_line(p(text), SPF_LOOKUP_LIMIT)
    assert "Over budget" in line
    assert "permerror" in line


def test_there_is_a_budget_line_even_with_no_record():
    assert budget_line(None, SPF_LOOKUP_LIMIT) == "No SPF record to budget."
