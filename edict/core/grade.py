"""
The judgement — the three pillars, then the findings, then a letter.

The grader reads the policies :mod:`edict.core.records` assembled and turns them
into plain-English findings a domain owner can act on, then a single A+..F
letter. Three principles shape it, all carried over from the rest of this
catalogue:

* **Honesty ceiling.** Edict never resolves DNS. It does not follow ``include:``
  chains, so the lookup count it reports is a *floor*; it cannot confirm that a
  published DKIM key is the one your mail is actually signed with, or that the
  hosts in your MX and SPF are the servers you meant. A high grade means the
  published policy is sound — never that your domain cannot be spoofed, and the
  word never appears in a verdict.

* **Unknown beats a guess.** A paste with no DKIM selector in it has not proved
  that a domain fails to sign its mail; it has proved that Edict was not told.
  That pillar reads ``UNKNOWN``, and the grade is capped rather than scored as
  though the key were missing.

* **Properties, not brands.** Every penalty is something the record itself says
  — an ending that authorises everyone, a budget a receiver cannot afford, a key
  too small to be worth verifying. Edict never compares a provider against a
  list of who is "good".
"""

from __future__ import annotations

from . import dkim as dkim_mod
from . import dmarc as dmarc_mod
from . import spf as spf_mod
from .model import (
    SPF_LOOKUP_LIMIT,
    DkimKey,
    DmarcPolicy,
    Finding,
    Grade,
    Pillar,
    RawRecord,
    RecordKind,
    Severity,
    SpfPolicy,
    Stance,
    Zone,
)

_LETTERS = ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F"]

_CEILING = (
    "Edict grades only the records you pasted, and never resolves DNS. It does "
    "not follow include: chains, so the lookup count is a floor rather than the "
    "real total; it cannot confirm that a published DKIM key is the one your "
    "mail is signed with, or that the hosts named in your MX and SPF are the "
    "servers you meant. A high grade means the published policy is sound — "
    "never that your domain cannot be spoofed."
)


def _letter_for_score(score: int) -> str:
    bands = [(97, "A+"), (93, "A"), (90, "A-"), (87, "B+"), (83, "B"),
             (80, "B-"), (77, "C+"), (73, "C"), (70, "C-"), (67, "D+"),
             (63, "D"), (60, "D-")]
    for floor, letter in bands:
        if score >= floor:
            return letter
    return "F"


def _cap(letter: str, ceiling: str) -> str:
    """Return the worse (lower) of two letters."""
    return letter if _LETTERS.index(letter) >= _LETTERS.index(ceiling) else ceiling


class _Sink:
    """Collects findings and keeps the running score, so each check is a line."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def add(self, sev: Severity, title: str, detail: str, pts: int = 0,
            cat: str = "general") -> None:
        self.findings.append(Finding(sev, title, detail, pts, cat))

    def titles(self) -> set[str]:
        return {f.title for f in self.findings}


# --- SPF ---------------------------------------------------------------------

def check_spf(zone: Zone, out: _Sink) -> None:
    if not zone.spf:
        out.add(Severity.ALERT, "No SPF record",
                "Nothing published says which servers may send mail using this "
                "domain, so a receiver has no list to check a connecting IP "
                "against. Publish a v=spf1 record that names your senders and "
                "ends in -all.", 30, "spf")
        return

    several = len(zone.spf) > 1
    if several:
        out.add(Severity.ALERT, f"{len(zone.spf)} SPF records published",
                f"A domain may publish exactly one SPF record. With more than "
                f"one a receiver must return permerror and use none of them, so "
                f"two careful records protect less than one. Each record given, "
                f"in order: {_spf_endings(zone)}. Merge them into a single "
                f"v=spf1 string{_merge_warning(zone)}.", 26, "spf")

    policy = zone.spf[0]
    mark = len(out.findings)
    _check_spf_ending(policy, out)
    _check_spf_budget(policy, out)
    _check_spf_mechanisms(policy, out)
    _check_spf_syntax(policy, out)

    if several:
        # Only the first record is examined in detail, and with several
        # published a receiver uses none of them — so a green finding here
        # would be reassurance about a policy that is not in force, and it
        # would be drawn from whichever record happened to be pasted first.
        # The endings of all of them are listed in the alert above instead.
        out.findings[mark:] = [f for f in out.findings[mark:]
                               if f.severity is not Severity.GOOD]


def _spf_ending_of(policy: SpfPolicy) -> str:
    """How one record finishes, in the words the record itself used."""
    qual = policy.all_qualifier
    if qual is not None:
        for m in policy.mechanisms:
            if m.is_all:
                return m.rendered
        return f"{qual}all"
    if "redirect" in policy.modifiers:
        return f"redirect={policy.modifiers['redirect']}"
    return "no all mechanism"


def _spf_endings(zone: Zone) -> str:
    return "; ".join(f"#{i} ends in {_spf_ending_of(pol)}"
                     for i, pol in enumerate(zone.spf, start=1))


def _merge_warning(zone: Zone) -> str:
    """Name a ``+all`` hiding among several records, where it cannot be missed.

    A bare ``all`` is a pass too, and is named in the record's own words rather
    than normalised, because the two spellings read very differently to the
    person who wrote one of them by accident.
    """
    wide = [pol for pol in zone.spf if pol.all_qualifier == "+"]
    if not wide:
        return ""
    return (f" — and take care which ending survives the merge: "
            f"{_spf_ending_of(wide[0])} authorises every sender on the "
            f"internet")


def _check_spf_ending(policy: SpfPolicy, out: _Sink) -> None:
    qual = policy.all_qualifier
    if qual is None:
        if "redirect" in policy.modifiers:
            out.add(Severity.INFO, "SPF ends in a redirect",
                    f"The record has no all mechanism and hands the decision to "
                    f"{policy.modifiers['redirect']} instead. Whatever that "
                    f"record ends with becomes this domain's policy — and Edict "
                    f"cannot read it, because it does not resolve DNS.",
                    0, "spf")
        else:
            out.add(Severity.WARNING, "SPF never says what to do with everyone else",
                    "The record lists senders but has no all mechanism, so a "
                    "receiver reaching the end simply gets no answer and treats "
                    "the sender as neutral. Add -all to finish the sentence.",
                    14, "spf")
        return

    name, meaning = spf_mod.ALL_MEANING[qual]
    if qual == "-":
        out.add(Severity.GOOD, "SPF ends in -all",
                f"The record closes with a {name}: it asks receivers to "
                f"{meaning}. This is the ending that makes SPF worth "
                f"publishing.", 0, "spf")
    elif qual == "~":
        out.add(Severity.NOTICE, "SPF ends in ~all, not -all",
                f"A {name} tells receivers to {meaning} — it discourages a "
                f"forgery without refusing it. ~all is the right place to pause "
                f"while you find senders you forgot, not the place to stop.",
                8, "spf")
    elif qual == "?":
        out.add(Severity.WARNING, "SPF ends in ?all and commits to nothing",
                f"A {name} result asks receivers to {meaning}. Publishing this "
                f"is the same amount of protection as publishing no SPF record "
                f"at all, with the added cost of looking protected.", 16, "spf")
    else:
        out.add(Severity.ALERT, "SPF ends in +all — anyone may send as you",
                f"A leading + makes all a pass, so the record asks receivers "
                f"to {meaning}. Every spammer on the internet is authorised by "
                f"this one character. It is almost always a typo for -all.",
                34, "spf")


def _check_spf_budget(policy: SpfPolicy, out: _Sink) -> None:
    used = policy.lookup_cost
    spenders = ", ".join(m.rendered for m in policy.costly) or "nothing"
    floor = ("and because Edict does not follow include: chains, the real "
             "total can only be higher")

    if used > SPF_LOOKUP_LIMIT:
        out.add(Severity.ALERT,
                f"SPF needs {used} DNS lookups — the limit is {SPF_LOOKUP_LIMIT}",
                f"A receiver stops counting at {SPF_LOOKUP_LIMIT} lookups and "
                f"returns permerror, which most treat as no SPF record at all. "
                f"The spenders here are: {spenders} — {floor}. Flatten the "
                f"chain, or replace includes you control with ip4/ip6 ranges, "
                f"which cost nothing.", 26, "spf")
    elif used >= 8:
        out.add(Severity.WARNING,
                f"SPF already uses {used} of {SPF_LOOKUP_LIMIT} DNS lookups",
                f"This is close enough to the cliff that one provider adding an "
                f"include inside their own record pushes you over it, and SPF "
                f"stops working with no change on your side. Counted here: "
                f"{spenders} — {floor}.", 10, "spf")
    elif used >= 6:
        out.add(Severity.INFO,
                f"SPF uses {used} of {SPF_LOOKUP_LIMIT} DNS lookups",
                f"Inside the limit, with room to spare but not much. Counted "
                f"here: {spenders} — {floor}.", 0, "spf")
    else:
        out.add(Severity.GOOD,
                f"SPF fits in {used} of {SPF_LOOKUP_LIMIT} DNS lookups",
                f"Comfortably inside the limit a receiver will spend. Counted "
                f"here: {spenders} — {floor}.", 0, "spf")


def _check_spf_mechanisms(policy: SpfPolicy, out: _Sink) -> None:
    if any(m.kind == "ptr" for m in policy.mechanisms):
        out.add(Severity.NOTICE, "SPF uses the ptr mechanism",
                "RFC 7208 says plainly not to publish ptr: it makes a receiver "
                "do a reverse lookup and then forward lookups on the result, "
                "which is slow, easy to spoof, and some receivers skip it "
                "entirely. Name the hosts with a or mx instead.", 8, "spf")

    wide = [m for m in policy.mechanisms if spf_mod.covers_everything(m)]
    if wide:
        terms = ", ".join(m.rendered for m in wide)
        out.add(Severity.ALERT, "An SPF range authorises the whole internet",
                f"{terms} covers every address there is, which is +all written "
                f"in a way that does not look like +all. Narrow it to the "
                f"ranges your own mail leaves from.", 30, "spf")

    broad = []
    for m in policy.mechanisms:
        if m.qualifier != "+" or spf_mod.covers_everything(m):
            continue
        plen = spf_mod.ip_prefix_len(m)
        if plen is None:
            continue
        if (m.kind == "ip4" and 1 <= plen <= 15) or (m.kind == "ip6" and 1 <= plen <= 31):
            broad.append(m)
    if broad:
        terms = ", ".join(m.rendered for m in broad)
        out.add(Severity.NOTICE, "An SPF range is far wider than one mail estate",
                f"{terms} authorises a block big enough to contain networks "
                f"that are nothing to do with you. Anyone inside it can send "
                f"mail that passes SPF for this domain.", 6, "spf")

    unreachable = policy.unreachable
    if unreachable:
        terms = ", ".join(m.rendered for m in unreachable)
        out.add(Severity.NOTICE, "SPF terms written after all can never match",
                f"Evaluation stops at the first match, and all always matches, "
                f"so {terms} is dead text. Move it in front of the all "
                f"mechanism if it was meant to do something.", 4, "spf")

    if "redirect" in policy.modifiers and policy.all_qualifier is not None:
        out.add(Severity.NOTICE, "SPF has both an all mechanism and a redirect",
                f"redirect={policy.modifiers['redirect']} is only consulted "
                f"when no mechanism matches, and all always matches, so the "
                f"redirect is never used. One of the two is not doing what it "
                f"looks like it does.", 4, "spf")

    if "exp" in policy.modifiers:
        out.add(Severity.INFO, "SPF publishes an explanation string",
                f"exp={policy.modifiers['exp']} gives receivers wording to put "
                f"in a rejection notice. It costs no lookups against the limit.",
                0, "spf")


def _check_spf_syntax(policy: SpfPolicy, out: _Sink) -> None:
    if policy.malformed:
        terms = ", ".join(policy.malformed)
        out.add(Severity.WARNING, "An SPF term is malformed",
                f"{terms} could not be read as the kind of term it claims to "
                f"be. A receiver may reject the whole record as a syntax error, "
                f"which leaves the domain with no usable SPF policy.", 10, "spf")

    if policy.unknown_terms:
        terms = ", ".join(policy.unknown_terms)
        out.add(Severity.NOTICE, "SPF contains terms Edict does not recognise",
                f"{terms} is neither a defined mechanism nor a defined "
                f"modifier. An unknown modifier is ignored by receivers, but an "
                f"unknown mechanism is a syntax error — check the spelling.",
                6, "spf")

    if policy.long_string:
        out.add(Severity.INFO, "The SPF record arrived as one long string",
                f"It is {len(policy.raw)} characters, and a single DNS string "
                f"may hold 255. Published for real it has to be split into "
                f"several quoted chunks, which a resolver then joins back "
                f"together.", 0, "spf")


# --- DMARC -------------------------------------------------------------------

def check_dmarc(zone: Zone, out: _Sink) -> None:
    if not zone.dmarc:
        out.add(Severity.ALERT, "No DMARC record",
                "Without DMARC, SPF and DKIM prove things about the envelope "
                "and the signature but nothing about the From address a person "
                "actually reads, and no receiver is told what to do when they "
                "fail. Publish a record at _dmarc with p=none and a rua "
                "address, read the reports, then move to reject.", 30, "dmarc")
        return

    if len(zone.dmarc) > 1:
        out.add(Severity.ALERT, f"{len(zone.dmarc)} DMARC records published",
                "A receiver that finds more than one DMARC record at _dmarc "
                "must ignore all of them, so the domain is left with no policy "
                "at all. Keep exactly one.", 24, "dmarc")

    policy = zone.dmarc[0]
    _check_dmarc_location(policy, out)
    _check_dmarc_policy(policy, out)
    _check_dmarc_subdomains(policy, out)
    _check_dmarc_reporting(policy, out)
    _check_dmarc_alignment(policy, out)


def _check_dmarc_location(policy: DmarcPolicy, out: _Sink) -> None:
    if policy.at_dmarc is False:
        out.add(Severity.NOTICE, "The DMARC record is not at _dmarc",
                f"A receiver looks for this record at exactly "
                f"_dmarc.<domain> and nowhere else. Published at "
                f"{policy.owner.rstrip('.')} it is correct text in a place "
                f"nothing reads.", 10, "dmarc")
    elif policy.at_dmarc is None:
        out.add(Severity.INFO, "Edict cannot tell where this DMARC record lives",
                "The line carried no owner name — the shape dig +short prints "
                "— so Edict read the policy but cannot confirm it is published "
                "at _dmarc, which is the only place a receiver looks.",
                0, "dmarc")

    if not policy.version_ok:
        out.add(Severity.NOTICE, "The DMARC record does not start with v=DMARC1",
                "The version tag has to be first, exactly. A receiver that does "
                "not see it there treats the record as something other than a "
                "DMARC policy.", 8, "dmarc")


def _check_dmarc_policy(policy: DmarcPolicy, out: _Sink) -> None:
    rank = dmarc_mod.policy_rank(policy.p)
    if rank < 0:
        shown = policy.p or "(no p tag)"
        out.add(Severity.ALERT, "The DMARC record has no usable policy",
                f"p= must be none, quarantine or reject; this record says "
                f"{shown}. A record a receiver cannot parse is a record a "
                f"receiver does not apply.", 24, "dmarc")
    elif policy.p == "none":
        out.add(Severity.WARNING, "DMARC is monitoring only (p=none)",
                "Nothing is rejected and nothing is quarantined — receivers "
                "report what failed and deliver it anyway. This is the right "
                "first step and the wrong place to stay: a forgery of this "
                "domain still lands in the inbox.", 14, "dmarc")
    elif policy.p == "quarantine":
        out.add(Severity.NOTICE, "DMARC quarantines rather than rejects",
                "Failing mail is set aside, usually as spam, which means it is "
                "still delivered somewhere a person can find and open it. "
                "p=reject is the step that ends the forgery.", 8, "dmarc")
    else:
        out.add(Severity.GOOD, "DMARC is at p=reject",
                "Receivers are asked to refuse mail that fails authentication "
                "for this domain outright. This is the strongest thing a domain "
                "can publish about who may use its name.", 0, "dmarc")

    if not policy.pct_valid:
        out.add(Severity.WARNING, "The DMARC pct tag is not a valid percentage",
                f"pct={policy.tags.get('pct')} has to be a whole number from 0 "
                f"to 100. Receivers may discard the whole record over it.",
                10, "dmarc")
    elif policy.pct < 100 and rank > 0:
        out.add(Severity.NOTICE, f"DMARC only applies to {policy.pct}% of mail",
                f"pct={policy.pct} tells receivers to apply p={policy.p} to "
                f"roughly {policy.pct} messages in every 100 and treat the rest "
                f"as the next weaker policy. A forgery has a "
                f"{100 - policy.pct}-in-100 chance of being delivered. pct is a "
                f"ramp to roll out an enforcing policy, not a setting to leave "
                f"behind.", 6, "dmarc")


def _check_dmarc_subdomains(policy: DmarcPolicy, out: _Sink) -> None:
    p_rank = dmarc_mod.policy_rank(policy.p)
    if not policy.sp:
        if p_rank >= 0:
            out.add(Severity.INFO, "Subdomains inherit the apex DMARC policy",
                    f"No sp tag is published, so every subdomain gets "
                    f"p={policy.p} too. That is the safe default.", 0, "dmarc")
        return

    sp_rank = dmarc_mod.policy_rank(policy.sp)
    if sp_rank < 0:
        out.add(Severity.WARNING, "The DMARC sp tag is not a usable policy",
                f"sp={policy.sp} must be none, quarantine or reject. A "
                f"subdomain policy a receiver cannot read is a subdomain policy "
                f"a receiver does not apply.", 10, "dmarc")
    elif sp_rank < p_rank:
        out.add(Severity.WARNING, "Subdomains are weaker than the apex",
                f"The apex is at p={policy.p} but sp={policy.sp} applies to "
                f"every subdomain, and a forger does not need the apex: mail "
                f"from billing.{policy.domain or 'example.com'} looks like you "
                f"to a person reading it. This is the quietest gap in a DMARC "
                f"deployment.", 12, "dmarc")
    else:
        out.add(Severity.INFO, f"Subdomains are explicitly at sp={policy.sp}",
                "The subdomain policy is published and is no weaker than the "
                "apex policy.", 0, "dmarc")


def _check_dmarc_reporting(policy: DmarcPolicy, out: _Sink) -> None:
    if not policy.rua:
        enforcing = dmarc_mod.policy_rank(policy.p) > 0
        tail = ("you are enforcing a policy with no way to see what it is "
                "rejecting" if enforcing else
                "a monitoring policy with nowhere to send the monitoring is "
                "doing no work at all")
        out.add(Severity.NOTICE, "DMARC asks for no aggregate reports",
                f"There is no rua address, so {tail}. Aggregate reports are the "
                f"only view a domain owner gets of who is sending as them.",
                8, "dmarc")
    else:
        out.add(Severity.GOOD, "DMARC aggregate reports are requested",
                f"Receivers will send daily summaries to "
                f"{', '.join(policy.rua)}, which is how you find the senders "
                f"you forgot before an enforcing policy blocks them.",
                0, "dmarc")

    if policy.ruf:
        out.add(Severity.INFO, "DMARC also asks for failure reports",
                f"ruf={', '.join(policy.ruf)} requests per-message forensic "
                f"reports. Few receivers send them, and those that do may "
                f"redact, because the reports contain message content.",
                0, "dmarc")

    external = dmarc_mod.external_report_domains(policy)
    if external:
        out.add(Severity.NOTICE, "DMARC reports go to another domain",
                f"Reports are addressed to {', '.join(external)}, outside "
                f"{policy.domain or 'this domain'}. That is normal for a hosted "
                f"analytics service, but it only works if that domain publishes "
                f"an authorisation record of its own; without it, receivers "
                f"quietly send nothing.", 6, "dmarc")


def _check_dmarc_alignment(policy: DmarcPolicy, out: _Sink) -> None:
    aspf_name, aspf_meaning = dmarc_mod.ALIGNMENT_MEANING[policy.aspf]
    adkim_name, adkim_meaning = dmarc_mod.ALIGNMENT_MEANING[policy.adkim]
    tail = ("Relaxed is the default and suits most domains; strict is tighter "
            "but breaks any sender that signs as a subdomain.")
    if policy.aspf == policy.adkim:
        title = f"Alignment is {aspf_name} for both SPF and DKIM"
        detail = (f"aspf={policy.aspf} and adkim={policy.adkim}: "
                  f"{aspf_meaning}. {tail}")
    else:
        title = f"Alignment is {aspf_name} for SPF, {adkim_name} for DKIM"
        detail = (f"aspf={policy.aspf}: {aspf_meaning}. "
                  f"adkim={policy.adkim}: {adkim_meaning}. {tail}")
    out.add(Severity.INFO, title, detail, 0, "dmarc")

    if policy.unknown_tags:
        out.add(Severity.INFO, "The DMARC record has tags Edict does not know",
                f"{', '.join(policy.unknown_tags)} is not a tag defined for "
                f"DMARC. Receivers ignore unknown tags, so this is harmless "
                f"unless it was meant to be one of the real ones.", 0, "dmarc")


# --- DKIM --------------------------------------------------------------------

def check_dkim(zone: Zone, out: _Sink) -> None:
    if not zone.dkim:
        out.add(Severity.WARNING, "No DKIM selector was pasted",
                "Edict was given no <selector>._domainkey record, so it cannot "
                "tell whether this domain signs its mail — and it will not "
                "guess. DKIM is the only one of the three that survives "
                "forwarding, so a domain without it loses authentication the "
                "moment a message is relayed. Paste the selector your mail "
                "provider gave you to have it graded.", 12, "dkim")
        return

    if len(zone.dkim) > 1:
        out.add(Severity.INFO, f"{len(zone.dkim)} DKIM selectors published",
                f"Several selectors ({', '.join(k.selector or '(unnamed)' for k in zone.dkim)}) "
                f"is how a key is rotated without a gap: publish the new one, "
                f"switch signing to it, then retire the old.", 0, "dkim")

    for key in zone.dkim:
        _check_one_key(key, out)


def _check_one_key(key: DkimKey, out: _Sink) -> None:
    who = f"selector {key.selector}" if key.selector else "the DKIM record"

    if key.revoked:
        out.add(Severity.NOTICE, f"The key for {who} is revoked",
                "The record is published with an empty p=, which is how a key "
                "is withdrawn while leaving the selector in place. Signatures "
                "made with it no longer verify, so if mail is still being "
                "signed with this selector, that mail now fails DKIM.",
                10, "dkim")
    elif key.key_type not in dkim_mod.KEY_TYPES:
        out.add(Severity.NOTICE, f"{who} uses an algorithm Edict does not know",
                f"k={key.key_type} is neither rsa nor ed25519, the two a "
                f"receiver is expected to understand. Edict cannot read the key "
                f"size, and a receiver that does not know the algorithm cannot "
                f"verify the signature either.", 8, "dkim")
    elif "p" not in key.tags:
        out.add(Severity.WARNING, f"{who} publishes no key",
                "The record has no p= tag at all, so there is nothing for a "
                "receiver to verify against. An empty p= revokes a key; a "
                "missing p= is a broken record.", 10, "dkim")
    elif key.key_error:
        out.add(Severity.WARNING, f"The key for {who} could not be read",
                f"Edict decoded p= and found {key.key_error}. A receiver doing "
                f"the same thing will fail the signature, so a malformed key is "
                f"indistinguishable from no key at all.", 10, "dkim")
    elif key.key_type == "ed25519":
        out.add(Severity.GOOD, f"{who} publishes an ed25519 key",
                "A modern, compact signing key. Not every receiver verifies "
                "ed25519 yet, so it is usually published alongside an RSA "
                "selector rather than instead of one.", 0, "dkim")
    elif key.bits < dkim_mod.RSA_WEAK:
        out.add(Severity.ALERT, f"{who} has a {key.bits}-bit RSA key",
                f"Below {dkim_mod.RSA_WEAK} bits a signature is not evidence of "
                f"anything: the key is cheap to break, and some receivers "
                f"refuse to verify a key this small at all. Generate a "
                f"{dkim_mod.RSA_RECOMMENDED}-bit key and publish it under a new "
                f"selector.", 28, "dkim")
    elif key.bits == dkim_mod.RSA_WEAK:
        out.add(Severity.WARNING, f"{who} has a 1024-bit RSA key",
                f"1024 bits was the default a decade ago and nothing ever "
                f"complains about it, which is exactly why so many domains "
                f"still publish one. It is the weakest link in an otherwise "
                f"sound policy. Rotate to "
                f"{dkim_mod.RSA_RECOMMENDED} bits under a new selector.",
                14, "dkim")
    elif key.bits < dkim_mod.RSA_RECOMMENDED:
        out.add(Severity.NOTICE, f"{who} has a {key.bits}-bit RSA key",
                f"Stronger than 1024 but under the {dkim_mod.RSA_RECOMMENDED}-bit "
                f"floor every current guide gives. An unusual size also hints "
                f"the key was generated by hand some time ago.", 6, "dkim")
    else:
        out.add(Severity.GOOD, f"{who} has a {key.bits}-bit RSA key",
                f"At or above the {dkim_mod.RSA_RECOMMENDED}-bit floor, so the "
                f"key size is not the weak link. Edict read this out of the key "
                f"material itself — it cannot confirm the key is the one your "
                f"mail is actually signed with.", 0, "dkim")

    if key.testing:
        name, meaning = dkim_mod.FLAG_MEANING["y"]
        out.add(Severity.NOTICE, f"{who} is flagged {name} (t=y)",
                f"With t=y published, {meaning}. Whatever the key's size, a "
                f"signature made with it proves nothing while the flag is "
                f"there — and it is the easiest thing in the world to leave "
                f"behind after a rollout.", 8, "dkim")

    if key.strict_subdomains:
        name, meaning = dkim_mod.FLAG_MEANING["s"]
        out.add(Severity.INFO, f"{who} is flagged {name} (t=s)",
                f"The flag means {meaning}, so a signature from a subdomain "
                f"will not be accepted for the parent.", 0, "dkim")

    if key.hashes and "sha256" not in key.hashes:
        out.add(Severity.WARNING, f"{who} allows only {'/'.join(key.hashes)}",
                "h= restricts which hash a signature may use, and SHA-1 has "
                "been unfit for signatures for years. Allow sha256, or drop the "
                "h= tag so receivers use the best they have.", 12, "dkim")

    if not key.version_ok and not key.revoked:
        out.add(Severity.NOTICE, f"{who} has no v=DKIM1 tag",
                "The version tag is meant to come first. A receiver must still "
                "accept a record without it, but its absence usually means the "
                "record was assembled by hand and is worth re-reading.",
                4, "dkim")

    if key.unknown_tags:
        out.add(Severity.INFO, f"{who} has tags Edict does not know",
                f"{', '.join(key.unknown_tags)} is not a tag defined for a DKIM "
                f"key record. Receivers ignore what they do not recognise.",
                0, "dkim")


# --- the rest of the zone ----------------------------------------------------

def check_zone(zone: Zone, out: _Sink) -> None:
    _check_mx(zone, out)
    _check_caa(zone, out)
    _check_neighbours(zone, out)


def _untyped_lines(zone: Zone) -> list[RawRecord]:
    """Lines Edict read but could not give a record type.

    These are the bare fragments a paste arrives with — no owner name, no RR
    type, no quotes to mark them as TXT data, and nothing inside them that says
    what they are. They are listed in the report's own "read, but not graded"
    notes, and they are the reason the absence findings below are careful about
    the word *absent*: a record Edict failed to read is not a record the reader
    failed to publish.
    """
    from .records import NEIGHBOUR_TAGS

    return [r for r in zone.other
            if not r.rtype and not r.quoted and r.kind is RecordKind.TXT
            and r.tag.lower() not in NEIGHBOUR_TAGS]


def _untyped_tail(n: int) -> str:
    return (f"{n} line{'s' if n > 1 else ''} in this paste could not be typed "
            f"at all — they are listed with the report — so one of them may be "
            f"the record Edict is looking for. Nothing is deducted for a line "
            f"Edict simply could not read.")


def _check_mx(zone: Zone, out: _Sink) -> None:
    if not zone.mx:
        untyped = _untyped_lines(zone)
        if untyped:
            out.add(Severity.NOTICE, "No MX record recognised",
                    f"Nothing among these records could be read as an MX, so "
                    f"Edict cannot say where mail for this domain is "
                    f"delivered. {_untyped_tail(len(untyped))}", 0, "zone")
            return
        out.add(Severity.NOTICE, "No MX record among the records given",
                "Nothing here says where mail for this domain should be "
                "delivered, so the domain may not receive mail at all. If that "
                "is deliberate, say so on purpose: publish a null MX (a "
                "preference of 0 pointing at \".\") together with an SPF record "
                "of \"v=spf1 -all\", and receivers will stop trying.", 5, "zone")
        return

    if any(m.is_null for m in zone.mx):
        out.add(Severity.GOOD, "A null MX declares this domain handles no mail",
                "A preference of 0 pointing at \".\" is the explicit way to say "
                "a domain neither sends nor receives. Paired with an SPF record "
                "of -all it is the tidiest policy a non-mail domain can "
                "publish.", 0, "zone")
        return

    hosts = ", ".join(f"{m.preference} {m.host}" for m in zone.mx)
    out.add(Severity.INFO, f"{len(zone.mx)} MX record"
                           f"{'s' if len(zone.mx) > 1 else ''} published",
            f"Mail is delivered to {hosts}, lowest preference first. Edict "
            f"reads the names; it cannot check that they resolve or that they "
            f"are the servers you meant.", 0, "zone")


def _check_caa(zone: Zone, out: _Sink) -> None:
    if not zone.caa:
        untyped = _untyped_lines(zone)
        if untyped:
            out.add(Severity.NOTICE, "No CAA record recognised",
                    f"Nothing among these records could be read as a CAA "
                    f"record, so Edict cannot say which certificate "
                    f"authorities are allowed to issue for this name. "
                    f"{_untyped_tail(len(untyped))}", 0, "zone")
            return
        out.add(Severity.NOTICE, "No CAA record among the records given",
                "Without CAA, any certificate authority in the world may issue "
                "a certificate for this name, and a certificate for your mail "
                "host is what turns an intercepted connection into a silent "
                "one. Publish an issue property naming the CA you actually "
                "use.", 5, "zone")
        return

    issuers = [c.value for c in zone.caa if c.tag in ("issue", "issuewild")]
    if issuers and all(i.strip() == ";" for i in issuers):
        out.add(Severity.INFO, "CAA forbids all certificate issuance",
                "An issue value of \";\" tells every CA to refuse. That is "
                "correct for a name that should never hold a certificate, and "
                "an outage waiting to happen for one that should.", 0, "zone")
    elif issuers:
        out.add(Severity.GOOD, "CAA names the authorities allowed to issue",
                f"Only {', '.join(sorted(set(issuers)))} may issue certificates "
                f"for this name, so a mis-issued certificate takes a second "
                f"mistake rather than one.", 0, "zone")

    iodef = [c.value for c in zone.caa if c.tag == "iodef"]
    if iodef:
        out.add(Severity.INFO, "CAA asks to be told about refused issuance",
                f"An iodef property points at {', '.join(iodef)}, so a CA that "
                f"turns down a request can report it. Support is patchy, and "
                f"costs nothing to publish.", 0, "zone")


def _check_neighbours(zone: Zone, out: _Sink) -> None:
    from .records import NEIGHBOUR_TAGS

    seen: list[str] = []
    for rec in zone.other:
        if rec.kind is not RecordKind.TXT:
            continue
        label = NEIGHBOUR_TAGS.get(rec.tag.lower())
        if label and label not in seen:
            seen.append(label)
        if rec.value.lower().startswith("spf2.0/"):
            out.add(Severity.INFO, "A Sender ID record is published alongside SPF",
                    "spf2.0/ records belong to Sender ID, which was withdrawn "
                    "and is read by nothing today. Harmless, and safe to "
                    "delete once you have checked nothing internal parses it.",
                    0, "zone")

    if seen:
        out.add(Severity.INFO, f"{' and '.join(seen)} also published",
                "These are adjacent policies about how mail reaches you rather "
                "than who may send as you, so Edict reports them without "
                "grading them.", 0, "zone")


# --- the three pillars -------------------------------------------------------

def spf_stance(zone: Zone) -> tuple[Stance, str]:
    if not zone.spf:
        return Stance.ABSENT, "no v=spf1 record"
    if len(zone.spf) > 1:
        return Stance.BROKEN, f"{len(zone.spf)} records — permerror"
    policy = zone.spf[0]
    if policy.lookup_cost > SPF_LOOKUP_LIMIT:
        return Stance.BROKEN, f"{policy.lookup_cost} lookups — permerror"
    if any(spf_mod.covers_everything(m) for m in policy.mechanisms):
        return Stance.BROKEN, "a range covers the internet"
    qual = policy.all_qualifier
    if qual == "-":
        return Stance.ENFORCING, "-all"
    if qual == "~":
        return Stance.PARTIAL, "~all"
    if qual == "?":
        return Stance.PERMISSIVE, "?all"
    if qual == "+":
        return Stance.BROKEN, "+all"
    if "redirect" in policy.modifiers:
        return Stance.UNKNOWN, "redirect, not followed"
    return Stance.PERMISSIVE, "no all mechanism"


def dkim_stance(zone: Zone) -> tuple[Stance, str]:
    if not zone.dkim:
        return Stance.UNKNOWN, "no selector pasted"
    if any(k.strong for k in zone.dkim):
        best = max((k for k in zone.dkim if k.strong),
                   key=lambda k: k.bits or 0)
        return Stance.ENFORCING, dkim_mod.size_verdict(best)
    usable = [k for k in zone.dkim if k.usable and k.bits]
    if usable:
        best = max(usable, key=lambda k: k.bits or 0)
        if (best.bits or 0) >= dkim_mod.RSA_WEAK:
            return Stance.PERMISSIVE, dkim_mod.size_verdict(best)
        return Stance.BROKEN, dkim_mod.size_verdict(best)
    if any(k.revoked or k.testing for k in zone.dkim):
        revoked = [k for k in zone.dkim if k.revoked]
        return Stance.BROKEN, "revoked" if revoked else "flagged t=y"
    return Stance.UNKNOWN, "the key could not be read"


def dmarc_stance(zone: Zone) -> tuple[Stance, str]:
    if not zone.dmarc:
        return Stance.ABSENT, "no _dmarc record"
    if len(zone.dmarc) > 1:
        return Stance.BROKEN, f"{len(zone.dmarc)} records — all ignored"
    policy = zone.dmarc[0]
    if policy.at_dmarc is False:
        return Stance.BROKEN, "published away from _dmarc"
    rank = dmarc_mod.policy_rank(policy.p)
    if rank < 0 or not policy.version_ok or not policy.pct_valid:
        return Stance.BROKEN, "the record is not usable"
    if policy.p == "none":
        return Stance.PERMISSIVE, "p=none"
    if policy.p == "quarantine":
        return Stance.PARTIAL, "p=quarantine"
    if policy.pct < 100:
        return Stance.PARTIAL, f"p=reject at {policy.pct}%"
    if dmarc_mod.policy_rank(policy.effective_sp) < rank:
        return Stance.PARTIAL, f"p=reject, sp={policy.effective_sp}"
    return Stance.ENFORCING, "p=reject"


def build_pillars(zone: Zone) -> list[Pillar]:
    """The strength row: what each of the three actually commits to."""
    spf_state, spf_note = spf_stance(zone)
    dkim_state, dkim_note = dkim_stance(zone)
    dmarc_state, dmarc_note = dmarc_stance(zone)
    return [
        Pillar("spf", "SPF", spf_state, spf_note),
        Pillar("dkim", "DKIM", dkim_state, dkim_note),
        Pillar("dmarc", "DMARC", dmarc_state, dmarc_note),
    ]


# --- the letter --------------------------------------------------------------

def grade_zone(zone: Zone) -> Zone:
    """Populate ``zone.pillars``, ``zone.findings`` and ``zone.grade`` in place."""
    if zone.is_empty:
        zone.pillars = build_pillars(zone)
        zone.grade = Grade("F", 0, "No records to grade", _CEILING)
        return zone

    out = _Sink()
    check_spf(zone, out)
    check_dmarc(zone, out)
    check_dkim(zone, out)
    check_zone(zone, out)

    score = max(0, min(100, 100 - sum(f.points for f in out.findings)))
    letter = _letter_for_score(score)

    zone.pillars = build_pillars(zone)
    stances = {p.key: p.stance for p in zone.pillars}
    clean = not any(f.severity.rank >= Severity.NOTICE.rank for f in out.findings)
    all_enforcing = all(stances[k] is Stance.ENFORCING
                        for k in ("spf", "dkim", "dmarc"))

    if all_enforcing and clean and score >= 97:
        letter = "A+"
        headline = "Every edict this domain publishes holds"
    else:
        # A+ is reserved for a complete, clean policy — nothing else reaches it.
        letter = _cap(letter, "A")
        if score >= 90:
            headline = "A sound policy, with minor notes"
        elif score >= 70:
            headline = "Published, but it stops short of committing"
        elif score >= 60:
            headline = "Real gaps in what this domain declares"
        else:
            headline = "This policy would not stand in a forger's way"

    # Unknown beats a guess: without a selector, Edict has not seen a third of
    # the policy, so it does not hand out a high grade as though it had.
    if stances["dkim"] is Stance.UNKNOWN:
        capped = _cap(letter, "B-")
        if capped != letter:
            headline = "DKIM unknown — the grade is capped, not earned"
        letter = capped

    if stances["spf"] is Stance.ABSENT and stances["dmarc"] is Stance.ABSENT:
        letter = _cap(letter, "F")
        headline = "This domain declares nothing about its own mail"

    zone.findings = sorted(out.findings, key=lambda f: -f.severity.rank)
    zone.grade = Grade(letter, score, headline, _CEILING)
    return zone


def analyze(text: str) -> Zone:
    """Read then grade — the whole pipeline in one call."""
    from .records import read_zone

    return grade_zone(read_zone(text))
