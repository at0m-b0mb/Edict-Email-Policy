"""
Edict on the command line.

The same engine the window uses, with no Qt in sight — so it runs on a server,
in a pipe, or inside a deployment check. Point it at a file of DNS records or
pipe them in; add ``--json`` for machine-readable output.

    edict records.dns
    dig +short TXT example.com | edict -
    edict records.dns --json
"""

from __future__ import annotations

import argparse
import json
import sys

from .core import dkim as dkim_mod
from .core.grade import analyze
from .core.model import SPF_LOOKUP_LIMIT, Stance, Zone
from .core.spf import budget_line

_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "good": "\033[32m", "notice": "\033[33m", "warning": "\033[33m",
    "alert": "\033[31m", "info": "\033[90m", "brass": "\033[33m",
}

_STANCE_KEY = {
    Stance.ENFORCING: "good",
    Stance.PARTIAL: "notice",
    Stance.PERMISSIVE: "warning",
    Stance.BROKEN: "alert",
    Stance.ABSENT: "alert",
    Stance.UNKNOWN: "info",
}


def _paint(text: str, key: str, color: bool) -> str:
    if not color:
        return text
    return f"{_C.get(key, '')}{text}{_C['reset']}"


def _gauge(zone: Zone, color: bool) -> str:
    """The lookup budget as a bar, overflow and all.

    ``[####......|]`` inside budget; ``[##########|###]`` when the record costs
    more lookups than a receiver will ever spend.
    """
    policy = zone.primary_spf
    if policy is None:
        return ""
    used = policy.lookup_cost
    inside = min(used, SPF_LOOKUP_LIMIT)
    over = max(0, used - SPF_LOOKUP_LIMIT)
    bar = "#" * inside + "." * (SPF_LOOKUP_LIMIT - inside)
    key = "alert" if over else ("warning" if used >= 8 else "good")
    body = _paint(bar, key, color) + _paint("|", "brass", color)
    if over:
        body += _paint("#" * over, "alert", color)
    return f"  [{body}]  {budget_line(policy, SPF_LOOKUP_LIMIT)}"


def _report_text(zone: Zone, color: bool) -> str:
    g = zone.grade
    out: list[str] = []
    out.append(_paint(f"  {g.letter}  ", "bold", color) + f" {g.headline}  "
               + _paint(f"({g.score}/100)", "dim", color))
    out.append(_paint(g.ceiling_note, "dim", color))
    out.append("")

    out.append(f"Domain       {zone.domain or '(not named in the records given)'}")
    out.append(f"Records      {len(zone.records)} read")
    out.append("")

    out.append("What this domain declares")
    for p in zone.pillars:
        word = _paint(f"{p.stance.word:<14}", _STANCE_KEY[p.stance], color)
        out.append(f"  {p.label:<6} {word} " + _paint(p.note, "dim", color))
    out.append("")

    policy = zone.primary_spf
    if policy is not None:
        out.append("SPF lookup budget")
        out.append(_gauge(zone, color))
        for i, mech in enumerate(policy.costly, start=1):
            out.append(_paint(f"    {i:>2}. {mech.rendered}", "dim", color))
        if not policy.costly:
            out.append(_paint("     no mechanism in this record costs a lookup",
                              "dim", color))
        out.append("")
        out.append("SPF mechanisms, in evaluation order")
        for mech in policy.mechanisms:
            cost = "1 lookup" if mech.cost else "no lookup"
            out.append(f"  {mech.rendered:<40} " + _paint(cost, "dim", color))
        for name, val in policy.modifiers.items():
            out.append(f"  {name}={val}")
        out.append("")

    dmarc = zone.primary_dmarc
    if dmarc is not None:
        out.append("DMARC")
        for key in ("p", "sp", "pct", "aspf", "adkim", "rua", "ruf", "fo"):
            if key in dmarc.tags:
                out.append(f"  {key:<6} {dmarc.tags[key]}")
        where = {True: "at _dmarc", False: "NOT at _dmarc", None: "location unknown"}
        out.append(_paint(f"  {where[dmarc.at_dmarc]}", "dim", color))
        out.append("")

    if zone.dkim:
        out.append("DKIM selectors")
        for key in zone.dkim:
            size = dkim_mod.size_verdict(key)
            flags = ",".join(key.flags) or "-"
            out.append(f"  {key.selector or '(unnamed)':<12} {key.key_type:<8} "
                       f"{size:<12} flags={flags}")
        out.append("")

    if zone.mx or zone.caa:
        out.append("Zone")
        for m in zone.mx:
            out.append(f"  MX   {m.preference:<4} {m.host}")
        for c in zone.caa:
            out.append(f"  CAA  {c.flags:<4} {c.tag} {c.value}")
        out.append("")

    out.append(f"Findings ({len(zone.findings)})")
    for f in zone.findings:
        tag = _paint(f"[{f.severity.value:^7}]", f.severity.value, color)
        pts = _paint(f" -{f.points}", "dim", color) if f.points else ""
        out.append(f"  {tag} {f.title}{pts}")
        out.append(_paint(f"          {f.detail}", "dim", color))

    for note in zone.notes:
        out.append(_paint(f"  note: {note}", "dim", color))
    return "\n".join(out)


def _report_json(zone: Zone) -> str:
    policy = zone.primary_spf
    dmarc = zone.primary_dmarc
    data = {
        "grade": {
            "letter": zone.grade.letter, "score": zone.grade.score,
            "headline": zone.grade.headline,
            "ceiling_note": zone.grade.ceiling_note,
        },
        "domain": zone.domain,
        "record_count": len(zone.records),
        "pillars": [
            {"key": p.key, "label": p.label, "stance": p.stance.value,
             "note": p.note}
            for p in zone.pillars
        ],
        "spf": None if policy is None else {
            "raw": policy.raw,
            "owner": policy.owner,
            "all_qualifier": policy.all_qualifier,
            "lookup_cost": policy.lookup_cost,
            "lookup_limit": SPF_LOOKUP_LIMIT,
            "lookup_cost_is_a_floor": True,
            "mechanisms": [
                {"qualifier": m.qualifier, "kind": m.kind, "value": m.value,
                 "cost": m.cost, "rendered": m.rendered}
                for m in policy.mechanisms
            ],
            "modifiers": policy.modifiers,
            "unknown_terms": policy.unknown_terms,
            "malformed_terms": policy.malformed,
        },
        "spf_record_count": len(zone.spf),
        "dmarc": None if dmarc is None else {
            "raw": dmarc.raw,
            "owner": dmarc.owner,
            "at_dmarc": dmarc.at_dmarc,
            "tags": dmarc.tags,
            "p": dmarc.p,
            "sp": dmarc.sp,
            "effective_sp": dmarc.effective_sp,
            "pct": dmarc.pct,
            "rua": dmarc.rua,
            "ruf": dmarc.ruf,
            "aspf": dmarc.aspf,
            "adkim": dmarc.adkim,
            "unknown_tags": dmarc.unknown_tags,
        },
        "dmarc_record_count": len(zone.dmarc),
        "dkim": [
            {"owner": k.owner, "selector": k.selector, "domain": k.domain,
             "key_type": k.key_type, "bits": k.bits,
             "size": dkim_mod.size_verdict(k), "revoked": k.revoked,
             "testing": k.testing, "flags": k.flags, "hashes": k.hashes,
             "key_error": k.key_error, "usable": k.usable, "strong": k.strong}
            for k in zone.dkim
        ],
        "mx": [{"preference": m.preference, "host": m.host,
                "null_mx": m.is_null} for m in zone.mx],
        "caa": [{"flags": c.flags, "tag": c.tag, "value": c.value}
                for c in zone.caa],
        "findings": [
            {"severity": f.severity.value, "title": f.title, "detail": f.detail,
             "points": f.points, "category": f.category}
            for f in zone.findings
        ],
        "notes": zone.notes,
    }
    return json.dumps(data, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="edict",
        description="Grade the mail policy a domain publishes about itself.")
    parser.add_argument("source", nargs="?", default="-",
                        help="path to a file of DNS records, or - for standard input")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--no-color", action="store_true", help="plain text, no ANSI")
    args = parser.parse_args(argv)

    if args.source == "-":
        raw = sys.stdin.read()
    else:
        try:
            with open(args.source, encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError as exc:
            print(f"edict: cannot read {args.source}: {exc}", file=sys.stderr)
            return 2

    if not raw.strip():
        print("edict: no records given", file=sys.stderr)
        return 2

    zone = analyze(raw)
    if args.json:
        print(_report_json(zone))
    else:
        color = sys.stdout.isatty() and not args.no_color
        print(_report_text(zone, color))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
