"""The command line: exit codes, the text report, and the JSON shape."""

import json
import os

import pytest

from edict.cli import main

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def _path(name):
    return os.path.join(SAMPLES, name)


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# --- exit codes --------------------------------------------------------------

def test_a_graded_file_exits_zero(capsys):
    code, out, _ = run(capsys, _path("hardened.dns"), "--no-color")
    assert code == 0
    assert out.strip()


def test_a_missing_file_exits_two(capsys):
    code, _, err = run(capsys, _path("no-such-file.dns"))
    assert code == 2
    assert "cannot read" in err


def test_empty_input_exits_two(monkeypatch, capsys):
    import io
    import sys
    monkeypatch.setattr(sys, "stdin", io.StringIO("   \n\n"))
    code, _, err = run(capsys, "-")
    assert code == 2
    assert "no records given" in err


def test_standard_input_is_read(monkeypatch, capsys):
    import io
    import sys
    monkeypatch.setattr(sys, "stdin", io.StringIO('"v=spf1 -all"\n'))
    code, out, _ = run(capsys, "-", "--no-color")
    assert code == 0
    assert "SPF ends in -all" in out


# --- the text report ---------------------------------------------------------

def test_the_report_leads_with_the_grade_and_the_ceiling(capsys):
    _, out, _ = run(capsys, _path("hardened.dns"), "--no-color")
    lines = out.splitlines()
    assert lines[0].strip().startswith("A+")
    assert "never that your domain cannot be spoofed" in lines[1]


def test_the_report_shows_the_three_pillars(capsys):
    _, out, _ = run(capsys, _path("hardened.dns"), "--no-color")
    assert "What this domain declares" in out
    for name in ("SPF", "DKIM", "DMARC"):
        assert name in out
    assert "ENFORCING" in out


def test_the_report_draws_the_budget_with_its_caveat(capsys):
    _, out, _ = run(capsys, _path("hardened.dns"), "--no-color")
    assert "SPF lookup budget" in out
    assert "|" in out
    assert "include: chains are not followed" in out


def test_an_over_budget_record_shows_overflow_past_the_limit(capsys):
    _, out, _ = run(capsys, _path("over-budget.dns"), "--no-color")
    gauge = [ln for ln in out.splitlines() if ln.strip().startswith("[")][0]
    assert "##########|#" in gauge
    assert "Over budget" in out


def test_the_report_lists_every_finding(capsys):
    _, out, _ = run(capsys, _path("wide-open.dns"), "--no-color")
    assert "Findings (" in out
    assert "[ alert ]" in out
    assert "+all" in out


def test_no_color_means_no_escape_codes(capsys):
    _, out, _ = run(capsys, _path("wide-open.dns"), "--no-color")
    assert "\033[" not in out


def test_the_report_names_the_dkim_selectors_and_their_sizes(capsys):
    _, out, _ = run(capsys, _path("monitoring-only.dns"), "--no-color")
    assert "DKIM selectors" in out
    assert "2048-bit" in out


def test_a_zone_with_no_spf_still_reports(capsys, tmp_path):
    path = tmp_path / "bare.dns"
    path.write_text('e.example. IN MX 10 m.e.example.\n')
    code, out, _ = run(capsys, str(path), "--no-color")
    assert code == 0
    assert "No SPF record" in out


@pytest.mark.parametrize("name", ["hardened.dns", "monitoring-only.dns",
                                  "subdomain-gap.dns", "over-budget.dns",
                                  "wide-open.dns"])
def test_every_sample_prints_without_raising(capsys, name):
    code, out, _ = run(capsys, _path(name), "--no-color")
    assert code == 0
    assert "Findings (" in out


# --- JSON --------------------------------------------------------------------

@pytest.mark.parametrize("name", ["hardened.dns", "monitoring-only.dns",
                                  "subdomain-gap.dns", "over-budget.dns",
                                  "wide-open.dns"])
def test_json_output_parses(capsys, name):
    code, out, _ = run(capsys, _path(name), "--json")
    assert code == 0
    json.loads(out)


def test_json_carries_the_grade_and_the_ceiling(capsys):
    _, out, _ = run(capsys, _path("hardened.dns"), "--json")
    data = json.loads(out)
    assert data["grade"]["letter"] == "A+"
    assert data["grade"]["ceiling_note"]


def test_json_says_the_lookup_count_is_a_floor(capsys):
    _, out, _ = run(capsys, _path("over-budget.dns"), "--json")
    data = json.loads(out)
    assert data["spf"]["lookup_cost"] == 11
    assert data["spf"]["lookup_limit"] == 10
    assert data["spf"]["lookup_cost_is_a_floor"] is True


def test_json_reports_the_pillars_as_stances(capsys):
    _, out, _ = run(capsys, _path("wide-open.dns"), "--json")
    stances = {p["key"]: p["stance"] for p in json.loads(out)["pillars"]}
    assert stances == {"spf": "broken", "dkim": "broken", "dmarc": "absent"}


def test_json_reports_the_derived_key_size(capsys):
    _, out, _ = run(capsys, _path("wide-open.dns"), "--json")
    key = json.loads(out)["dkim"][0]
    assert key["bits"] == 1024
    assert key["testing"] is True
    assert key["strong"] is False


def test_json_is_null_where_nothing_was_published(capsys):
    _, out, _ = run(capsys, _path("wide-open.dns"), "--json")
    assert json.loads(out)["dmarc"] is None


def test_json_findings_keep_their_severity_and_points(capsys):
    _, out, _ = run(capsys, _path("wide-open.dns"), "--json")
    findings = json.loads(out)["findings"]
    assert findings[0]["severity"] == "alert"
    assert findings[0]["points"] > 0
    assert all(set(f) == {"severity", "title", "detail", "points", "category"}
               for f in findings)
