"""
SPF — the list of who may send as you, and what it costs to read.

An SPF record is a short program a receiver runs against a connecting IP. It is
evaluated strictly left to right, the first mechanism that matches decides the
answer, and the qualifier in front of that mechanism *is* the answer: ``+`` pass,
``-`` fail, ``~`` softfail, ``?`` neutral. So two things matter more than the
length of the record, and this module measures both.

**Where it ends.** Almost every record finishes with an ``all`` mechanism, and
that one term is the whole policy for every sender not named earlier. ``-all``
says *nobody else* — the only ending that asks a receiver to reject. ``~all``
says "probably not, deliver it anyway". ``?all`` says nothing at all, and
``+all`` authorises the entire internet to send as you.

**What it costs.** RFC 7208 §4.6.4 allows an evaluation ten DNS lookups, and no
more: at the eleventh the receiver stops and returns ``permerror``, which most
receivers treat as no SPF record at all. ``include``, ``a``, ``mx``, ``ptr``,
``exists`` and ``redirect`` each spend one; ``ip4``, ``ip6`` and ``all`` spend
none because they are answered from the record itself. Edict counts what it can
see — and because it never resolves anything, every ``include`` it counts as one
may really be five.
"""

from __future__ import annotations

import ipaddress

from .model import Mechanism, SpfPolicy

# One lookup each, or none. The split is the whole reason the budget exists:
# a mechanism that must ask DNS a question costs a question.
MECHANISM_COST = {
    "all": 0,
    "include": 1,
    "a": 1,
    "mx": 1,
    "ptr": 1,
    "ip4": 0,
    "ip6": 0,
    "exists": 1,
}

# ``redirect`` is a mechanism in all but name and costs a lookup. ``exp`` only
# fetches an explanation string after a failure, and RFC 7208 exempts it.
MODIFIER_COST = {"redirect": 1, "exp": 0}

QUALIFIERS = "+-~?"

#: What each ending actually asks a receiver to do.
ALL_MEANING = {
    "-": ("hard fail", "reject mail from anyone not listed above"),
    "~": ("soft fail", "accept but mark mail from anyone not listed above"),
    "?": ("neutral", "treat an unlisted sender as if no policy existed"),
    "+": ("pass", "treat every sender on the internet as authorised"),
}


def _split_term(term: str) -> tuple[str, str]:
    """Separate a mechanism name from its argument.

    ``include:_spf.example.com`` -> ``("include", "_spf.example.com")``
    ``a/24``                     -> ``("a", "/24")``
    ``mx:mail.example.com/24``   -> ``("mx", "mail.example.com/24")``
    ``all``                      -> ``("all", "")``
    """
    for i, ch in enumerate(term):
        if ch == ":":
            return term[:i].lower(), term[i + 1:]
        if ch == "/":
            return term[:i].lower(), term[i:]
    return term.lower(), ""


def _is_modifier(term: str) -> bool:
    """A modifier is ``name=value``, and the name must not contain ``:`` or ``/``."""
    if "=" not in term:
        return False
    name = term.split("=", 1)[0]
    return bool(name) and ":" not in name and "/" not in name


def _ip_ok(kind: str, arg: str) -> bool:
    """Is this a well-formed ``ip4``/``ip6`` argument?"""
    if not arg:
        return False
    try:
        net = ipaddress.ip_network(arg, strict=False)
    except ValueError:
        return False
    if kind == "ip4":
        return net.version == 4
    return net.version == 6


def ip_prefix_len(mech: Mechanism) -> int | None:
    """The prefix length of an ``ip4``/``ip6`` term, or ``None`` if unreadable."""
    if mech.kind not in ("ip4", "ip6"):
        return None
    try:
        return ipaddress.ip_network(mech.value, strict=False).prefixlen
    except ValueError:
        return None


def covers_everything(mech: Mechanism) -> bool:
    """Does this term authorise the whole address space?

    ``ip4:0.0.0.0/0`` and ``ip6:::/0`` are ``+all`` wearing a disguise, and they
    are easy to publish by accident when a tool asks for "the network".
    """
    if mech.qualifier != "+":
        return False
    return ip_prefix_len(mech) == 0


def parse_spf(value: str, owner: str = "", chunks: int = 1) -> SpfPolicy:
    """Read one ``v=spf1`` record into mechanisms, in evaluation order."""
    policy = SpfPolicy(owner=owner, raw=value.strip())
    terms = value.split()
    if not terms:
        policy.version_ok = False
        return policy

    head, rest = terms[0], terms[1:]
    policy.version_ok = head.lower() == "v=spf1"
    if not policy.version_ok:
        # Not an SPF record at all; hand back an empty policy that says so.
        rest = terms

    # A single published string may not exceed 255 characters, so a long record
    # has to arrive in several chunks. Worth knowing when it did not.
    policy.long_string = chunks == 1 and len(policy.raw) > 255

    for term in rest:
        if _is_modifier(term):
            name, _, arg = term.partition("=")
            low = name.lower()
            if low in MODIFIER_COST:
                policy.modifiers[low] = arg
            else:
                policy.unknown_terms.append(term)
            continue

        qualifier = "+"
        body = term
        if body and body[0] in QUALIFIERS:
            qualifier, body = body[0], body[1:]
        if not body:
            policy.unknown_terms.append(term)
            continue

        kind, arg = _split_term(body)
        if kind not in MECHANISM_COST:
            policy.unknown_terms.append(term)
            continue

        if kind in ("ip4", "ip6") and not _ip_ok(kind, arg):
            policy.malformed.append(term)
            continue
        if kind in ("include", "exists") and not arg:
            policy.malformed.append(term)
            continue

        policy.mechanisms.append(
            Mechanism(qualifier=qualifier, kind=kind, value=arg,
                      cost=MECHANISM_COST[kind], raw=term))

    return policy


def budget_segments(policy: SpfPolicy | None, limit: int) -> list[str]:
    """The labels for the gauge: one per lookup spent, in evaluation order.

    Longer than *limit* when the record is over budget — the overflow is the
    point of drawing it.
    """
    if policy is None:
        return []
    return [m.rendered for m in policy.costly]


def budget_line(policy: SpfPolicy | None, limit: int) -> str:
    """The sentence written under the gauge, caveat and all."""
    if policy is None:
        return "No SPF record to budget."
    used = policy.lookup_cost
    tail = "at least, since include: chains are not followed"
    if used > limit:
        return (f"Over budget: {used} of {limit} used — {tail}. A receiver "
                f"stops at {limit} and returns permerror.")
    return f"{used} of {limit} used — {tail}."
