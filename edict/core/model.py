"""
The shapes the analysis produces.

Edict reads the DNS records a domain publishes about its own mail — SPF, DMARC,
DKIM, MX, CAA — and reports on the policy they add up to. These dataclasses are
that result: each record normalised and classified, each policy parsed into its
parts, the three pillars resolved to a state for the strength row, and the
findings and grade built on top.

Nothing here parses or judges. These are the nouns, defined once, so the engine
and the window never disagree about what a "mechanism" or a "finding" is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# RFC 7208 §4.6.4 — an SPF evaluation may cost at most ten DNS lookups before
# the receiver must give up and return permerror.
SPF_LOOKUP_LIMIT = 10


class Severity(Enum):
    """How much a single finding should worry the reader."""

    GOOD = "good"        # a published decision that holds, not a problem
    INFO = "info"        # worth knowing, not alarming
    NOTICE = "notice"    # a soft gap
    WARNING = "warning"  # a real gap in the policy
    ALERT = "alert"      # the policy fails or invites forgery

    @property
    def rank(self) -> int:
        return {
            Severity.GOOD: 0, Severity.INFO: 1, Severity.NOTICE: 2,
            Severity.WARNING: 3, Severity.ALERT: 4,
        }[self]


class RecordKind(Enum):
    """What one pasted line turned out to be."""

    SPF = "spf"
    DMARC = "dmarc"
    DKIM = "dkim"
    MX = "mx"
    CAA = "caa"
    TXT = "txt"          # a TXT record that is not one of the policies above
    OTHER = "other"      # an A/NS/CNAME line and the like — read, not graded


class Stance(Enum):
    """How far one pillar of the policy actually commits.

    The order matters: these are the six honest answers to "what does this
    domain declare?", and ``UNKNOWN`` is one of them. A domain whose DKIM
    selector was simply never pasted has not failed anything — Edict does not
    know, and a tool that scored that as "absent" would be guessing.
    """

    ENFORCING = "enforcing"     # published, and it asks receivers to act
    PARTIAL = "partial"         # published, but it stops short
    PERMISSIVE = "permissive"   # published, and it commits to nothing
    BROKEN = "broken"           # published, but a receiver cannot use it
    ABSENT = "absent"           # nothing published among the records given
    UNKNOWN = "unknown"         # not in the paste, so not knowable

    @property
    def word(self) -> str:
        """The word the chip and the CLI print."""
        return {
            Stance.ENFORCING: "ENFORCING",
            Stance.PARTIAL: "PARTIAL",
            Stance.PERMISSIVE: "PERMISSIVE",
            Stance.BROKEN: "BROKEN",
            Stance.ABSENT: "NOT PUBLISHED",
            Stance.UNKNOWN: "UNKNOWN",
        }[self]

    @property
    def token(self) -> str:
        """Which severity colour this stance wears."""
        return {
            Stance.ENFORCING: "sev_good",
            Stance.PARTIAL: "sev_notice",
            Stance.PERMISSIVE: "sev_warning",
            Stance.BROKEN: "sev_alert",
            Stance.ABSENT: "sev_alert",
            Stance.UNKNOWN: "sev_info",
        }[self]


@dataclass
class RawRecord:
    """One pasted line, normalised: quotes stripped, split chunks joined."""

    kind: RecordKind
    owner: str              # the name on the left, "" when the line had none
    value: str              # the joined record data
    line_no: int            # 1-based, for the notes
    raw: str = ""           # the line exactly as pasted
    rtype: str = ""         # the RR type token, when the line carried one
    tag: str = ""           # the v= value, e.g. "spf1", "DMARC1", "STSv1"
    chunks: int = 1         # how many quoted strings were joined
    # Was the data a quoted string? ``dig +short TXT`` prints one, and a quoted
    # string is TXT data whatever is inside it — so a record with no RR type is
    # still *typed* when it arrived in quotes, and only an unquoted fragment is
    # a line Edict genuinely could not identify.
    quoted: bool = False


@dataclass(frozen=True)
class Mechanism:
    """One SPF term: a qualifier, a kind, and what it costs to evaluate."""

    qualifier: str          # "+", "-", "~" or "?"
    kind: str               # all, include, a, mx, ptr, ip4, ip6, exists
    value: str              # the argument; "" for a bare `all`, `a` or `mx`
    cost: int               # DNS lookups this term costs: 1 or 0
    raw: str = ""
    # True for the term Edict synthesises to represent a ``redirect=`` modifier
    # on the gauge. A modifier is written ``name=value``, never ``name:value``,
    # and a reader who copies the gauge's text has to get valid SPF back.
    is_modifier: bool = False

    @property
    def rendered(self) -> str:
        """The term exactly as it was written, for the gauge and the CLI.

        The original text is preferred over a reconstruction, because the two
        differ in ways that matter: ``+all`` and ``all`` mean the same thing to
        a receiver, but only one of them *looks* like a domain that authorised
        the whole internet on purpose. A term Edict synthesised (the lookup a
        ``redirect=`` modifier costs) has no original, and is built instead.
        """
        if self.raw:
            return self.raw
        sep = "=" if self.is_modifier else ":"
        body = f"{self.kind}{sep}{self.value}" if self.value else self.kind
        return body if self.qualifier == "+" else f"{self.qualifier}{body}"

    @property
    def is_all(self) -> bool:
        return self.kind == "all"


@dataclass
class SpfPolicy:
    """One ``v=spf1`` record, read in evaluation order."""

    owner: str = ""
    raw: str = ""
    version_ok: bool = True
    mechanisms: list[Mechanism] = field(default_factory=list)
    modifiers: dict[str, str] = field(default_factory=dict)   # redirect, exp, ...
    unknown_terms: list[str] = field(default_factory=list)
    malformed: list[str] = field(default_factory=list)        # bad ip4/ip6 args
    long_string: bool = False     # a single quoted chunk over 255 characters

    @property
    def all_qualifier(self) -> Optional[str]:
        """The qualifier on the first ``all`` — the one that actually decides.

        SPF is evaluated left to right and the first match wins, so a second
        ``all`` can never be reached.
        """
        for m in self.mechanisms:
            if m.is_all:
                return m.qualifier
        return None

    @property
    def redirect_ignored(self) -> bool:
        """Is this record's ``redirect=`` modifier dead text?

        RFC 7208 §6.1: "if the record has an ``all`` mechanism, the
        ``redirect`` modifier MUST be ignored". ``all`` always matches, so the
        receiver never reaches the point of consulting the redirect — it never
        resolves it, and it never charges a lookup for it. Anywhere in the
        record is enough; the RFC says *has*, not *ends in*.
        """
        return ("redirect" in self.modifiers
                and any(m.is_all for m in self.mechanisms))

    @property
    def lookup_cost(self) -> int:
        """DNS lookups this record costs *before* any include is followed."""
        total = sum(m.cost for m in self.mechanisms)
        if "redirect" in self.modifiers and not self.redirect_ignored:
            total += 1
        return total

    @property
    def costly(self) -> list[Mechanism]:
        """The terms that spend a lookup, in the order they are evaluated."""
        spenders = [m for m in self.mechanisms if m.cost]
        if "redirect" in self.modifiers and not self.redirect_ignored:
            # A modifier, not a mechanism — but it costs a lookup like one, so
            # it gets a cell on the gauge. No raw text: it was never a term.
            spenders.append(Mechanism("+", "redirect",
                                      self.modifiers["redirect"], 1, "",
                                      is_modifier=True))
        return spenders

    @property
    def unreachable(self) -> list[Mechanism]:
        """Terms written after the first ``all``, which can never be reached."""
        seen_all = False
        out: list[Mechanism] = []
        for m in self.mechanisms:
            if seen_all:
                out.append(m)
            if m.is_all:
                seen_all = True
        return out


@dataclass
class DmarcPolicy:
    """One ``v=DMARC1`` record, read tag by tag."""

    owner: str = ""
    raw: str = ""
    version_ok: bool = True
    tags: dict[str, str] = field(default_factory=dict)
    unknown_tags: list[str] = field(default_factory=list)
    # ``None`` means the pasted line carried no owner name, so Edict cannot
    # tell where the record lives. Unknown is not the same as wrong.
    at_dmarc: Optional[bool] = None

    @property
    def p(self) -> str:
        return self.tags.get("p", "")

    @property
    def sp(self) -> str:
        return self.tags.get("sp", "")

    @property
    def pct(self) -> int:
        try:
            return int(self.tags.get("pct", "100"))
        except ValueError:
            return 100

    @property
    def pct_valid(self) -> bool:
        if "pct" not in self.tags:
            return True
        try:
            return 0 <= int(self.tags["pct"]) <= 100
        except ValueError:
            return False

    @property
    def rua(self) -> list[str]:
        return _uris(self.tags.get("rua", ""))

    @property
    def ruf(self) -> list[str]:
        return _uris(self.tags.get("ruf", ""))

    @property
    def aspf(self) -> str:
        return (self.tags.get("aspf") or "r").lower()

    @property
    def adkim(self) -> str:
        return (self.tags.get("adkim") or "r").lower()

    @property
    def effective_sp(self) -> str:
        """What subdomains actually get: ``sp`` when set, otherwise ``p``."""
        return self.sp or self.p

    @property
    def domain(self) -> str:
        """The domain this policy governs, derived from a ``_dmarc`` owner."""
        o = self.owner.rstrip(".").lower()
        if o.startswith("_dmarc."):
            return o[len("_dmarc."):]
        return o


def _uris(raw: str) -> list[str]:
    return [u.strip() for u in raw.split(",") if u.strip()]


@dataclass
class DkimKey:
    """One ``selector._domainkey`` record and the key it publishes."""

    owner: str = ""
    selector: str = ""
    domain: str = ""
    raw: str = ""
    version_ok: bool = True       # a v=DKIM1 tag was present
    tags: dict[str, str] = field(default_factory=dict)
    unknown_tags: list[str] = field(default_factory=list)
    bits: Optional[int] = None    # read out of the p= key material
    key_error: str = ""           # why the key could not be read

    @property
    def key_type(self) -> str:
        return (self.tags.get("k") or "rsa").lower()

    @property
    def public_key(self) -> str:
        return self.tags.get("p", "")

    @property
    def revoked(self) -> bool:
        """An empty ``p=`` is how a key is withdrawn, not how it is omitted."""
        return "p" in self.tags and not self.tags["p"].strip()

    @property
    def flags(self) -> list[str]:
        return [f.strip().lower() for f in self.tags.get("t", "").split(":")
                if f.strip()]

    @property
    def testing(self) -> bool:
        return "y" in self.flags

    @property
    def strict_subdomains(self) -> bool:
        return "s" in self.flags

    @property
    def hashes(self) -> list[str]:
        return [h.strip().lower() for h in self.tags.get("h", "").split(":")
                if h.strip()]

    @property
    def usable(self) -> bool:
        """A key a receiver could verify a signature against today."""
        if self.revoked or self.testing or self.key_error:
            return False
        if self.key_type == "ed25519":
            return self.bits == 256
        return bool(self.bits)

    @property
    def strong(self) -> bool:
        """Usable *and* big enough that the size is not the weak link."""
        if not self.usable:
            return False
        if self.key_type == "ed25519":
            return True
        return bool(self.bits and self.bits >= 2048)


@dataclass
class MxRecord:
    owner: str = ""
    preference: int = 0
    host: str = ""
    raw: str = ""

    @property
    def is_null(self) -> bool:
        """``0 .`` — the way a domain declares it handles no mail at all."""
        return self.host in (".", "")


@dataclass
class CaaRecord:
    owner: str = ""
    flags: int = 0
    tag: str = ""        # issue, issuewild, iodef, ...
    value: str = ""
    raw: str = ""


@dataclass
class Finding:
    """One observation the grader made, in words a person can act on."""

    severity: Severity
    title: str
    detail: str
    points: int = 0      # subtracted from the score (0 for GOOD/INFO)
    category: str = "general"


@dataclass
class Grade:
    """The final letter, the number behind it, and the honesty caveat."""

    letter: str
    score: int
    headline: str
    ceiling_note: str


@dataclass
class Pillar:
    """One of the three things a domain declares — the strength row's chip."""

    key: str             # spf, dkim, dmarc
    label: str
    stance: Stance
    note: str = ""


@dataclass
class Zone:
    """Everything Edict learned from one paste of records."""

    domain: str = ""
    records: list[RawRecord] = field(default_factory=list)

    spf: list[SpfPolicy] = field(default_factory=list)
    dmarc: list[DmarcPolicy] = field(default_factory=list)
    dkim: list[DkimKey] = field(default_factory=list)
    mx: list[MxRecord] = field(default_factory=list)
    caa: list[CaaRecord] = field(default_factory=list)
    other: list[RawRecord] = field(default_factory=list)

    pillars: list[Pillar] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    grade: Optional[Grade] = None
    notes: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.records

    @property
    def primary_spf(self) -> Optional[SpfPolicy]:
        """The record the gauge draws. With several published, none is used —
        but the first is still the one worth showing."""
        return self.spf[0] if self.spf else None

    @property
    def primary_dmarc(self) -> Optional[DmarcPolicy]:
        return self.dmarc[0] if self.dmarc else None

    def pillar(self, key: str) -> Optional[Pillar]:
        for p in self.pillars:
            if p.key == key:
                return p
        return None
