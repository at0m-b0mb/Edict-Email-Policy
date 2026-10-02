# Changelog

All notable changes to Edict are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[semantic versioning](https://semver.org/).

## [1.0.0] — 2026-10-02

First release.

### The grader
- Reads a paste of DNS records in whatever shape it arrived: zone-file lines,
  `dig` answer sections, `dig +short` fragments and bare policy strings, mixed
  freely. Quotes come off, split TXT chunks are joined the way a resolver joins
  them, parenthesised continuations are folded across lines, and comment and
  blank lines are skipped.
- **SPF** — mechanisms parsed in evaluation order with their qualifiers, and the
  **ten-lookup budget counted**: `include`, `a`, `mx`, `ptr`, `exists` and
  `redirect` spend one each, `ip4`, `ip6` and `all` spend none. Flags `+all`,
  `?all`, `~all`, a missing `all`, `ptr`, ranges that cover the whole internet,
  terms stranded after `all`, malformed addresses, and more than one published
  record.
- **DMARC** — every tag read, including where the record *lives*: a policy
  published anywhere but `_dmarc` is correct text nothing will ever look at.
  Flags `p=none`, `p=quarantine`, `pct` below 100, an `sp` weaker than `p`, a
  missing `rua`, and report addresses on a domain that must authorise them.
- **DKIM** — tags read, and the **key size derived from the key material**: the
  base64 `p=` is decoded and the RSA modulus recovered by walking the DER
  `SubjectPublicKeyInfo` (a bare `RSAPublicKey` is accepted too, and `ed25519`
  is reported as 256 bits). Flags keys under 1024 bits, exactly 1024, revoked,
  unreadable, `t=y` testing, and SHA-1-only signing.
- **MX and CAA** — a null MX read as the deliberate declaration it is, and a
  missing CAA reported as any authority being free to issue for the name.
- **Pillars** — SPF, DKIM and DMARC each resolved to one of six stances:
  `ENFORCING`, `PARTIAL`, `PERMISSIVE`, `BROKEN`, `NOT PUBLISHED` or `UNKNOWN`.
- **Grade** — A+ to F, with an honesty ceiling: A+ is reserved for a complete and
  clean policy; a paste with no DKIM selector is capped at B- and labelled
  *unknown* rather than scored as though the key were missing; the lookup count
  is always stated as a floor because `include:` chains are never followed; and
  the words "safe" and "secure" never appear as a verdict.

### Interfaces
- A PyQt6 window in the house style — warm paper and gold, true-black dark mode,
  and an Auto theme that follows the OS.
- **The lookup-budget gauge**, painted: ten cells of budget, one filled per
  mechanism that spends a lookup and labelled with the mechanism that spent it,
  a hard red line at the tenth, any overflow hatched past it, and the floor
  caveat written underneath every time.
- A dependency-free command line sharing the same engine, with text and `--json`
  output, an ASCII gauge, and standard-input support.

### Engineering
- The engine (`edict.core`) is pure standard library — no third-party imports,
  no network, no sockets, no name resolution of any kind.
- 480 tests across the record reader, the SPF budget arithmetic, the DMARC tag
  reader, the DER key-size walk, the full grading pipeline, the command line in
  both output modes, and a WCAG-AA contrast suite covering every text/background
  pairing in both themes.
- Off-screen screenshot capture, and a repository-art generator that imports the
  engine and draws the card from a real graded sample, held inside GitHub's safe
  border by a registered-rectangle check.
