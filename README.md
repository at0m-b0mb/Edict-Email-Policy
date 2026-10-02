<div align="center">

<img src="images/mark-180.png" width="88" alt="">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/banner-dark.png">
  <img src="images/banner.png" alt="Edict — what your domain declares" width="100%">
</picture>

<br>

**An offline grader for the SPF, DMARC, DKIM and CAA your domain publishes about
who may send as you — which resolves no DNS, follows no `include:` chain, and
says so on every number it prints.**

<br>

![Python](https://img.shields.io/badge/Python-3.10%2B-7A5D18?style=flat-square)
![PyQt6](https://img.shields.io/badge/UI-PyQt6-7A5D18?style=flat-square)
![Offline](https://img.shields.io/badge/network-never-2C6249?style=flat-square)
![Tests](https://img.shields.io/badge/tests-515%20passing-2C6249?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-6B6554?style=flat-square)

</div>

---

## Why

A few short lines in your DNS decide who the world believes may send mail as
you. Whoever set the domain up wrote them, and nothing has read them back since
— not you, and nothing that would complain.

Every receiving server reads them on every message and obeys exactly what is
published. An SPF record ending in `~all` says *probably not, deliver it
anyway*. DMARC at `p=none` says *tell me about the forgeries, then deliver
them*. A DKIM key generated in 2014 at 1024 bits still verifies, and no software
anywhere will mention its age. None of these is a failure. Each is working as
declared.

Edict reads the declaration back to you in plain words. Paste what you publish
and it shows how far each pillar commits, how much of your SPF budget is already
spent, the real size of your DKIM key decoded out of the base64 `p=`, and every
finding with something to do about it. Then it grades the whole thing, A+ to F.

One of those lines has a spending limit, and going over it quietly turns a
careful SPF record into no SPF record at all. RFC 7208 gives a receiver **ten
DNS lookups** to evaluate yours; at the eleventh it stops, returns `permerror`,
and most receivers treat that as though you published nothing. `include`, `a`,
`mx`, `ptr`, `exists` and `redirect` each spend one. Add a provider and a record
that worked yesterday is inert today with nothing changed on your side, because
the lookups they added are inside *their* record. Edict draws the ten as ten
cells, fills one for each mechanism that spent it, labels each cell with the
mechanism, and puts a hard line at the tenth.

It is the outbound half of a pair:
[Herald](https://github.com/at0m-b0mb/Herald-Email-Headers) judges a message that arrived,
Edict judges the rules you publish about who may send as you.

<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/screens-dark.png">
  <img src="images/screens.png" alt="A domain stuck at monitoring graded C, beside a hardened domain graded A+" width="100%">
</picture>
<br>
<sub>A domain still at <code>p=none</code> and <code>~all</code> (C, 73/100) beside one that finished the job (A+, 100/100).</sub>
</div>

## The honest part

Edict grades the records you pasted. That is the whole of what it knows, and it
is careful about the rest.

**It resolves no DNS.** No sockets, no queries, no `include:` followed. Each
`include:` costs the one lookup Edict can see, and the record it points at may
spend five more — so the count is a **floor**, never a total, and the line under
the gauge says so every time.

**It cannot confirm a key is in use.** A 2048-bit key in your zone is evidence
that a good key is *published*, not that your mail is signed with it, or signed
at all. Edict reads the names in your MX and SPF; it does not look behind them.

**Unknown beats a guess.** Paste no DKIM selector and that pillar reads
`UNKNOWN`, not absent — Edict was not told, which is not the same as the key
being missing. The grade is capped at **B-** and labelled as capped, rather than
scored as though the key were gone.

**A+ is reserved** for a policy that is complete *and* clean: one SPF record
ending in `-all` inside budget, DMARC at `p=reject` covering subdomains with
reports requested, a usable key of 2048 bits or better, and not one finding
above `info`.

A high grade means the published policy is sound — never that your domain cannot
be spoofed. That sentence is attached to every result, in the window and on the
command line, and the words "safe" and "secure" appear nowhere as a verdict.

## Install

```bash
git clone https://github.com/at0m-b0mb/Edict-Email-Policy.git
cd Edict-Email-Policy
python3 -m pip install -r requirements.txt   # just PyQt6, for the window
```

The engine and the command line need **no dependencies at all** — only the
standard library. PyQt6 is required solely for the graphical grader.

## Use

**The window:**

```bash
python3 -m edict          # or:  python3 run.py
```

Paste your records, open a file, or load one of the five bundled zones. Switch
between **Light**, **Dark** and **Auto** from the top right.

Shape does not matter. Zone-file lines, `dig` answer sections, `dig +short`
fragments and bare policy strings all work, mixed freely in one paste: quotes
come off, split TXT chunks are joined the way a resolver joins them (`"abc"
"def"` → `abcdef`), and parenthesised continuations are folded. A line with no
owner name is not an error — it is a record whose *location* is unknown, and
Edict says that rather than assume your DMARC record sits in the right place.

**The command line** — same engine, no Qt, pipe-friendly:

```bash
python3 -m edict samples/over-budget.dns          # a readable report
cat samples/wide-open.dns | python3 -m edict -    # from a pipe
python3 -m edict samples/hardened.dns --json      # machine-readable
```

```
  D-   Real gaps in what this domain declares  (61/100)
Edict grades only the records you pasted, and never resolves DNS… A high grade
means the published policy is sound — never that your domain cannot be spoofed.

Domain       budget.example
Records      4 read

What this domain declares
  SPF    BROKEN         11 lookups — permerror
  DKIM   ENFORCING      2048-bit
  DMARC  ENFORCING      p=reject

SPF lookup budget
  [##########|#]  Over budget: 11 of 10 used — at least, since include: chains
                  are not followed. A receiver stops at 10 and returns permerror.
     1. a
     2. mx
     3. include:_spf.crm.example
     …
    11. include:_spf.legacy.example

Findings (10)
  [ alert ] SPF needs 11 DNS lookups — the limit is 10 -26
  [notice ] SPF ends in ~all, not -all -8
  [notice ] No CAA record among the records given -5
  …
```

Exit status is `0` for a reading and `2` when there was nothing to read — an
empty input, or a file that would not open.

## What it checks

| Signal | What trips it |
|---|---|
| **SPF ending** | `+all` (anyone may send), `?all` (commits to nothing), `~all` (discourages only), or no `all` at all |
| **SPF budget** | over ten lookups and therefore `permerror`, or eight to ten and one provider from the cliff |
| **SPF mechanisms** | `ptr`, a range like `ip4:0.0.0.0/0`, terms stranded after `all`, malformed or unrecognised terms |
| **SPF records** | more than one published — a receiver then uses none of them |
| **DMARC policy** | `p=none`, `p=quarantine`, an unusable `p`, or `pct` below 100 |
| **DMARC subdomains** | `sp` weaker than `p` — the quietest gap in a deployment |
| **DMARC reporting** | no `rua`, or reports addressed to a domain that must authorise them |
| **DMARC location** | published anywhere but `_dmarc` — correct text that nothing will ever read |
| **DKIM key** | under 1024 bits, exactly 1024, revoked, unreadable, or no selector pasted |
| **DKIM flags** | `t=y` — receivers are told to ignore the signature |
| **Zone** | no MX, no CAA, SHA-1-only signing |

Findings are sorted most-severe first and carry the points they cost, so the
reasoning behind the letter is always on screen.

## Privacy

Edict never touches the network. It opens no sockets, resolves no names, and
sends nothing anywhere — the analysis is the standard library reading text you
already have, and `edict.core` imports nothing outside it. Records you paste
stay on your machine.

## Tests

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

515 tests cover the record reader (including the trap where `mx`, `a` and `ptr`
name both an SPF mechanism and a DNS record type), the budget arithmetic, the
DMARC tag reader, the DER walk that recovers a key's size from `p=`, the full
grading pipeline against the sample zones, the command line in both output
modes, and — as the house style demands — every text/background colour pairing
against WCAG AA in both themes.

## Layout

```
edict/
  core/            the engine — pure standard library, no Qt, no network
    model.py         the dataclasses everything speaks in
    records.py       the paste  ->  normalised, classified records
    spf.py           mechanisms, qualifiers and the ten-lookup budget
    dmarc.py         tags, location, and where the reports go
    dkim.py          tags, and the DER walk that reads the key size
    grade.py         pillars, findings and the letter, with the honesty ceiling
  ui/              the window
    theme.py         the design system: one place for every token
    budget.py        the lookup-budget gauge — Edict's signature element
    widgets.py       cards, chips, key/value rows
    main_window.py   the grader itself
  app.py           opens the window
  cli.py           the same engine on the command line
  __main__.py      what `python3 -m edict` lands on: window, or CLI if given a file
samples/           five synthetic zones spanning A+ to F
tests/             515 tests, including the contrast suite
tools/             brandkit.py (repository art), capture_screenshots.py
images/            marks, banners, screenshots, social card
run.py             opens the window
```

## Colophon

Set in **Iowan Old Style** for identity and figures, the system **sans** for
anything you read, and a **mono** for the raw records — a serif/sans/mono mix
that reads as authored rather than assembled. The palette is warm paper and two
golds: a deep brass legible as small text, and a brighter shine used only on
marks that carry no words. Dark mode is true black, with nothing in the ramp
that reads as blue. Every colour is declared as a light/dark pair, and a test
suite holds every pairing to WCAG AA so the theme can never quietly regress.

The screenshots above are real off-screen captures of the window, not mockups.
The banner and social card are drawn by `tools/brandkit.py`, which lays out
every piece of repository art deterministically and asserts the whole
composition clears GitHub's 80px safe border.

## License

MIT — see [LICENSE](LICENSE). For authorised, educational, and personal use:
Edict is a reader, not a resolver.
