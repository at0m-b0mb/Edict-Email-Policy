"""
DMARC — the instruction a receiver follows when SPF and DKIM do not save you.

SPF and DKIM each prove something narrow, and neither of them is about the name
a human reads. DMARC is the record that ties them to the visible *From* domain
and then says what to do when the tie fails: ``p=none`` means *tell me*,
``p=quarantine`` means *hide it*, ``p=reject`` means *refuse it at the door*.

Three things decide whether a DMARC record does any work, and this module reads
all three. **Where it lives** — a receiver looks for it at exactly
``_dmarc.<domain>``, so the same text published at the apex is invisible.
**What it asks for** — ``p``, and separately ``sp`` for subdomains, which is the
quietest gap in the whole system: a domain can enforce at the apex while leaving
every ``mail.`` and ``news.`` beneath it wide open. **Whether anyone is
listening** — without ``rua`` there are no aggregate reports, so an enforcing
policy is enforcing blind, and a monitoring policy is monitoring nothing.
"""

from __future__ import annotations

from .model import DmarcPolicy

#: Tags defined for a DMARC record. Anything else is reported, not penalised.
KNOWN_TAGS = {"v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo",
              "rf", "ri", "np"}

#: The three policies a receiver can be asked for, weakest first.
POLICIES = ["none", "quarantine", "reject"]

POLICY_MEANING = {
    "none": ("monitoring only", "nothing is rejected or quarantined"),
    "quarantine": ("quarantine", "failing mail is set aside, usually as spam"),
    "reject": ("reject", "failing mail is refused at the door"),
}

ALIGNMENT_MEANING = {
    "r": ("relaxed", "a subdomain of the From domain counts as aligned"),
    "s": ("strict", "the domain must match the From domain exactly"),
}


def policy_rank(name: str) -> int:
    """Where a policy sits on the weak-to-strong scale, or ``-1`` if invalid."""
    try:
        return POLICIES.index((name or "").lower())
    except ValueError:
        return -1


def parse_dmarc(value: str, owner: str = "") -> DmarcPolicy:
    """Read one ``v=DMARC1`` record into its tags.

    Tag names are lower-cased; values keep their case, because a ``rua`` is a
    URI and a mailbox is not ours to fold. A repeated tag keeps the first
    occurrence, which is what a receiver does.
    """
    policy = DmarcPolicy(owner=owner, raw=value.strip())

    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            policy.unknown_tags.append(part)
            continue
        name, _, val = part.partition("=")
        key = name.strip().lower()
        val = val.strip()
        if key not in KNOWN_TAGS:
            policy.unknown_tags.append(part)
            continue
        policy.tags.setdefault(key, val)

    policy.version_ok = policy.tags.get("v", "").lower() == "dmarc1"

    low_owner = owner.rstrip(".").lower()
    if low_owner:
        policy.at_dmarc = low_owner == "_dmarc" or low_owner.startswith("_dmarc.")
    else:
        # The line carried no owner name — ``dig +short`` output, or a bare
        # string from a wiki. Edict does not know where this is published, and
        # saying "unknown" is the honest answer.
        policy.at_dmarc = None

    return policy


def report_domains(policy: DmarcPolicy) -> list[str]:
    """The domains a ``rua``/``ruf`` address would send reports to."""
    out: list[str] = []
    for uri in policy.rua + policy.ruf:
        addr = uri.split("!", 1)[0]          # strip a size limit like !10m
        if addr.lower().startswith("mailto:"):
            addr = addr[len("mailto:"):]
        if "@" in addr:
            dom = addr.rsplit("@", 1)[1].rstrip(".").lower()
            if dom and dom not in out:
                out.append(dom)
    return out


def external_report_domains(policy: DmarcPolicy) -> list[str]:
    """Report destinations outside the policy's own domain.

    Sending reports elsewhere is normal and useful, but it only works if the
    receiving domain publishes an authorisation record of its own — the
    ``<your-domain>._report._dmarc.<their-domain>`` TXT record that almost
    nobody remembers to add.
    """
    own = policy.domain
    if not own:
        return []
    out = []
    for dom in report_domains(policy):
        if dom != own and not dom.endswith("." + own):
            out.append(dom)
    return out
