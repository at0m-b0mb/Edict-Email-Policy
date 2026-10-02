"""
Reading the paste — one line at a time, in whatever shape it arrived.

Nobody copies DNS records out of one place. The same policy reaches this tool as
a bare string from a wiki page, as a zone-file line from a registrar's export,
as the quoted fragment ``dig +short`` prints, or as the full answer section
``dig`` prints when nobody passed ``+short``. Edict accepts all of them, mixed
freely in one paste, and turns each line into a :class:`RawRecord`:

* **continuations are joined** — a zone file wraps a long DKIM key in
  parentheses across several lines, so an unclosed ``(`` keeps reading;
* **quotes come off and chunks join** — a TXT record longer than 255 characters
  is published as several strings, and ``"v=DKIM1; k=rsa; " "p=MIIBI..."`` is
  one record, not two;
* **the owner is found when it is there** — a zone line puts a name, a TTL and a
  class in front of the RR type; ``dig +short`` throws all of that away. A line
  with no owner is not an error, it is simply a record whose location is
  *unknown*, and the grader is careful to say so rather than guess.

Classification is by what the record says about itself: the ``v=`` tag first,
then the RR type, then the owner's underscore labels. Nothing here judges.
"""

from __future__ import annotations

import re

from .model import RawRecord, RecordKind

# RR types a line may announce. Anything else on the left of the data is read as
# part of an owner/TTL/class preamble and ignored.
_RR_TYPES = {
    "TXT", "MX", "CAA", "SPF", "A", "AAAA", "CNAME", "NS", "SOA", "PTR",
    "SRV", "TLSA", "DS", "DNSKEY", "NAPTR", "SVCB", "HTTPS",
}
_CLASSES = {"IN", "CH", "HS", "CS"}

_V_TAG = re.compile(r"^v\s*=\s*([A-Za-z0-9_.+-]+)", re.IGNORECASE)
_TTL = re.compile(r"^\d+$")
# A domain name, or the wildcard/apex shorthands a zone file uses. Crucially
# it admits no "=", ":" or "/", which is what separates a name from a policy
# term like ``v=spf1`` or ``include:a.example``.
_OWNER = re.compile(r"^[A-Za-z0-9_*@][A-Za-z0-9_.\-]*\.?$")


# --- lexing ------------------------------------------------------------------

def _split_tokens(line: str) -> list[tuple[str, bool]]:
    """Split a line into ``(text, was_quoted)`` tokens, respecting quotes.

    Parentheses are dropped: they are zone-file grouping, never data. A quoted
    string keeps its interior verbatim, including the spaces and semicolons that
    make up a DMARC or DKIM record.
    """
    out: list[tuple[str, bool]] = []
    buf: list[str] = []
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if ch == '"':
            if buf:
                out.append(("".join(buf), False))
                buf = []
            i += 1
            inner: list[str] = []
            while i < n and line[i] != '"':
                if line[i] == "\\" and i + 1 < n:
                    inner.append(line[i + 1])
                    i += 2
                    continue
                inner.append(line[i])
                i += 1
            i += 1  # closing quote, or end of line for an unterminated string
            out.append(("".join(inner), True))
            continue
        if ch in "()":
            if buf:
                out.append(("".join(buf), False))
                buf = []
            i += 1
            continue
        if ch.isspace():
            if buf:
                out.append(("".join(buf), False))
                buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if buf:
        out.append(("".join(buf), False))
    return out


def _is_comment(line: str) -> bool:
    """A comment is a line that *starts* with ``;`` or ``#``.

    Only at the start. A semicolon is the field separator inside every DMARC and
    DKIM record, so stripping mid-line comments would quietly eat policy.
    """
    s = line.strip()
    return s.startswith(";") or s.startswith("#")


def join_continuations(text: str) -> list[tuple[int, str]]:
    """Fold parenthesised zone-file continuations into single logical lines.

    Returns ``(line_number, text)`` pairs, numbered from the first physical line
    of each record so a note can point at something the reader can find.
    """
    out: list[tuple[int, str]] = []
    depth = 0
    start = 0
    parts: list[str] = []
    for no, raw in enumerate(text.splitlines(), start=1):
        if depth == 0 and (not raw.strip() or _is_comment(raw)):
            continue
        if depth == 0:
            start = no
            parts = []
        parts.append(raw.strip())
        depth += _paren_delta(raw)
        if depth <= 0:
            depth = 0
            out.append((start, " ".join(parts)))
    if depth > 0 and parts:   # an unclosed paren at end of input
        out.append((start, " ".join(parts)))
    return out


def _paren_delta(line: str) -> int:
    """Count parentheses outside quoted strings."""
    delta, in_q, i = 0, False, 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and in_q:
            i += 2
            continue
        if ch == '"':
            in_q = not in_q
        elif not in_q and ch == "(":
            delta += 1
        elif not in_q and ch == ")":
            delta -= 1
        i += 1
    return delta


# --- one line ----------------------------------------------------------------

def _looks_like_owner(tok: str) -> bool:
    """Could this token be a domain name sitting in front of an RR type?

    This guard is what keeps a bare policy string from being torn apart. ``mx``,
    ``a`` and ``ptr`` are SPF mechanisms *and* RR types, so in
    ``v=spf1 mx -all`` the token ``mx`` looks exactly like the ``MX`` in a zone
    line. The difference is everything to its left: a zone line has a name, a
    TTL and a class there, and ``v=spf1`` is none of those — it has an ``=`` in
    it, and no domain name does.
    """
    return bool(_OWNER.match(tok))


def _strip_preamble(tokens: list[tuple[str, bool]]) -> tuple[str, str, list[tuple[str, bool]]]:
    """Pull an owner name and an RR type off the front, if the line has them.

    Returns ``(owner, rtype, rest)``. A line that never announces an RR type —
    ``dig +short`` output, or a bare policy string — yields ``("", "", tokens)``
    untouched, because guessing an owner would be inventing information.
    """
    # Find an RR type among the first few unquoted tokens, but only accept one
    # whose left-hand side reads as a real owner/TTL/class preamble.
    idx = -1
    for i, (tok, quoted) in enumerate(tokens[:5]):
        if quoted or tok.upper() not in _RR_TYPES:
            continue
        before = [t for t, q in tokens[:i] if not q]
        if all(_TTL.match(t) or t.upper() in _CLASSES or _looks_like_owner(t)
               for t in before):
            idx = i
            break
    if idx < 0:
        return "", "", tokens

    rtype = tokens[idx][0].upper()
    pre = [t for t, q in tokens[:idx] if not q]
    owner = ""
    for tok in pre:
        if _TTL.match(tok) or tok.upper() in _CLASSES:
            continue
        owner = tok
        break
    return owner, rtype, tokens[idx + 1:]


def _normalise_data(rest: list[tuple[str, bool]]) -> tuple[str, int]:
    """Join the record's data, concatenating quoted chunks.

    Returns ``(value, chunk_count)``.

    A record whose data is *entirely* quoted is a TXT record that was published
    in chunks, because a single DNS string may hold only 255 characters. Those
    chunks are glued with no separator at all, which is exactly how a resolver
    reassembles them: ``"v=DKIM1; k=rsa; " "p=MIIBI..."`` is one record.

    A record with a mix — ``0 issue "letsencrypt.org"`` — is not chunked; the
    quotes are just how CAA writes a string field. Those tokens keep their
    spaces, so the field order survives.
    """
    if rest and all(q for _, q in rest):
        chunks = [t for t, _ in rest]
        return "".join(chunks), len(chunks)
    return " ".join(t for t, _ in rest).strip(), 1


# Property tags defined for CAA. A bare line is only guessed at as CAA when its
# middle field is one of these, which is what keeps an ordinary two-or-three
# word TXT string from being read as a certificate policy.
_CAA_TAGS = {"issue", "issuewild", "issuemail", "iodef", "contactemail",
             "contactphone"}


def _looks_like_bare_mx(value: str) -> bool:
    """Is this the shape ``dig +short MX`` prints — ``10 mail.example.com.``?

    Two fields: a preference a zone can actually hold, and a host name. The
    host must carry a dot, or be the bare ``.`` of a null MX, which is what
    separates an MX from a TXT string that happens to start with a number.
    """
    bits = value.split()
    if len(bits) != 2 or not bits[0].isdigit() or int(bits[0]) > 65535:
        return False
    host = bits[1]
    if host == ".":
        return True        # a null MX: the deliberate "no mail here"
    return bool(_OWNER.match(host)) and "." in host.rstrip(".")


def _looks_like_bare_caa(value: str) -> bool:
    """Is this the shape ``dig +short CAA`` prints — ``0 issue "a.example"``?"""
    bits = value.split(None, 2)
    if len(bits) != 3 or not bits[0].isdigit() or int(bits[0]) > 255:
        return False
    return bits[1].lower() in _CAA_TAGS and bool(bits[2].strip())


def _classify(owner: str, rtype: str, value: str,
              quoted: bool = False) -> tuple[RecordKind, str]:
    """Decide what a record is, and lift its ``v=`` tag if it has one."""
    low_owner = owner.rstrip(".").lower()
    tag = ""
    m = _V_TAG.match(value.strip())
    if m:
        tag = m.group(1)
    low_tag = tag.lower()

    if rtype == "MX":
        return RecordKind.MX, tag
    if rtype == "CAA":
        return RecordKind.CAA, tag

    if low_tag == "spf1":
        return RecordKind.SPF, tag
    if low_tag == "dmarc1":
        return RecordKind.DMARC, tag
    if low_tag == "dkim1":
        return RecordKind.DKIM, tag

    # No usable v= tag: fall back to where the record lives. Both DKIM and DMARC
    # records are found at reserved underscore labels, and a DKIM record is
    # allowed to omit its version tag entirely (RFC 6376 §3.6.1).
    if "_domainkey" in low_owner:
        return RecordKind.DKIM, tag
    if low_owner == "_dmarc" or low_owner.startswith("_dmarc."):
        return RecordKind.DMARC, tag

    if rtype in ("", "TXT", "SPF"):
        # A line that announced no RR type at all may still be an MX or a CAA:
        # that is all ``dig +short`` prints for either. Only an unquoted line
        # is guessed at — a fully quoted string is TXT data, whatever it
        # happens to look like — and only these two exact shapes, because the
        # alternative is telling a reader there was no MX among records in
        # which they can plainly see one.
        if not rtype and not quoted:
            if _looks_like_bare_mx(value):
                return RecordKind.MX, tag
            if _looks_like_bare_caa(value):
                return RecordKind.CAA, tag
        return RecordKind.TXT, tag
    return RecordKind.OTHER, tag


def parse_line(line: str, line_no: int = 1) -> RawRecord | None:
    """Turn one logical line into a record, or ``None`` if there is nothing in it."""
    tokens = _split_tokens(line)
    if not tokens:
        return None
    owner, rtype, rest = _strip_preamble(tokens)
    value, chunks = _normalise_data(rest)
    if not value:
        return None
    quoted = bool(rest) and all(q for _, q in rest)
    kind, tag = _classify(owner, rtype, value, quoted=quoted)
    return RawRecord(kind=kind, owner=owner, value=value, line_no=line_no,
                     raw=line.strip(), rtype=rtype, tag=tag, chunks=chunks,
                     quoted=quoted)


def parse_records(text: str) -> list[RawRecord]:
    """Read a whole paste into records, in the order they were given."""
    out: list[RawRecord] = []
    for no, line in join_continuations(text):
        rec = parse_line(line, no)
        if rec is not None:
            out.append(rec)
    return out


# --- the parts of an MX or CAA line ------------------------------------------

def parse_mx(rec: RawRecord):
    """``10 mail.example.com.`` — a preference and a host."""
    from .model import MxRecord

    bits = rec.value.split()
    pref, host = 0, ""
    if len(bits) >= 2:
        try:
            pref = int(bits[0])
        except ValueError:
            pref = 0
        host = bits[1].rstrip(".") or "."
        if bits[1] == ".":
            host = "."
    elif bits:
        host = bits[0].rstrip(".") or "."
        if bits[0] == ".":
            host = "."
    return MxRecord(owner=rec.owner, preference=pref, host=host, raw=rec.raw)


def parse_caa(rec: RawRecord):
    """``0 issue "letsencrypt.org"`` — flags, a property tag, and its value."""
    from .model import CaaRecord

    bits = rec.value.split(None, 2)
    flags, tag, value = 0, "", ""
    if bits:
        try:
            flags = int(bits[0])
        except ValueError:
            flags = 0
    if len(bits) >= 2:
        tag = bits[1].lower()
    if len(bits) >= 3:
        value = bits[2].strip().strip('"')
    return CaaRecord(owner=rec.owner, flags=flags, tag=tag, value=value,
                     raw=rec.raw)


# --- which domain is this? ---------------------------------------------------

def _apex_of(owner: str) -> str:
    """Strip the reserved labels a policy record hides behind.

    ``_dmarc.example.com`` and ``sel._domainkey.example.com`` both describe
    ``example.com``; so does a bare ``example.com``.
    """
    labels = [lab for lab in owner.rstrip(".").lower().split(".") if lab]
    if not labels:
        return ""
    if "_domainkey" in labels:
        labels = labels[labels.index("_domainkey") + 1:]
    while labels and labels[0].startswith("_"):
        labels = labels[1:]
    return ".".join(labels)


def infer_domain(records: list[RawRecord]) -> str:
    """Guess which domain the paste is about, from the owner names in it.

    The most frequently named apex wins; a tie goes to the shorter name, which
    is the one more likely to be the zone rather than a host inside it. A paste
    with no owner names at all yields ``""``, and the report says so rather than
    inventing a domain.
    """
    counts: dict[str, int] = {}
    for rec in records:
        apex = _apex_of(rec.owner)
        if apex:
            counts[apex] = counts.get(apex, 0) + 1
    if not counts:
        return ""
    return sorted(counts.items(), key=lambda kv: (-kv[1], len(kv[0]), kv[0]))[0][0]


# --- the whole paste ---------------------------------------------------------

#: TXT records whose ``v=`` tag Edict recognises but does not grade. They are
#: adjacent policies, worth reporting because publishing them is a good sign.
NEIGHBOUR_TAGS = {
    "stsv1": "MTA-STS",
    "tlsrptv1": "TLS reporting",
    "bimi1": "BIMI",
}


def read_zone(text: str):
    """Read a paste into a :class:`~edict.core.model.Zone`, parsed but ungraded.

    Every line becomes a record; every record Edict understands becomes a parsed
    policy; everything else is kept in ``zone.other`` and listed in the notes, so
    the report can account for each line the reader handed over.
    """
    from .dkim import parse_dkim
    from .dmarc import parse_dmarc
    from .model import Zone
    from .spf import parse_spf

    zone = Zone()
    zone.records = parse_records(text)
    zone.domain = infer_domain(zone.records)

    for rec in zone.records:
        if rec.kind is RecordKind.SPF:
            zone.spf.append(parse_spf(rec.value, rec.owner, rec.chunks))
        elif rec.kind is RecordKind.DMARC:
            zone.dmarc.append(parse_dmarc(rec.value, rec.owner))
        elif rec.kind is RecordKind.DKIM:
            zone.dkim.append(parse_dkim(rec.value, rec.owner))
        elif rec.kind is RecordKind.MX:
            zone.mx.append(parse_mx(rec))
        elif rec.kind is RecordKind.CAA:
            zone.caa.append(parse_caa(rec))
        else:
            zone.other.append(rec)

    zone.mx.sort(key=lambda m: (m.preference, m.host))
    zone.notes = _account_for(zone.other)
    return zone


def _account_for(others: list[RawRecord]) -> list[str]:
    """Say, line by line, what Edict read but did not grade."""
    notes: list[str] = []
    # Records with a tag Edict recognises are reported as a finding instead, so
    # the notes stay a list of what nothing else accounted for.
    unaccounted = [r for r in others if r.tag.lower() not in NEIGHBOUR_TAGS]
    for rec in unaccounted[:12]:
        shown = rec.value if len(rec.value) <= 56 else rec.value[:53] + "..."
        kind = rec.rtype or "a bare string"
        notes.append(f"line {rec.line_no}: {kind} not graded — \"{shown}\"")
    if len(unaccounted) > 12:
        notes.append(f"...and {len(unaccounted) - 12} more lines read but "
                     f"not graded.")
    return notes
