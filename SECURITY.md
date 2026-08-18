# Security Policy

This repository (`novachannel` and its sibling crates: `novachannel-rln`,
`novachannel-dp`, `novachannel-oram`, `novachannel-mpc`) is cryptographic
software. See `ENGINEERING-STANDARDS.md` for what correctness and testing
bar this workspace holds itself to, and each crate's own module docs
(`crates/*/src/lib.rs`) for what it does and does not claim to give you —
in particular `novachannel-rln`'s permutation (`crates/rln/src/permutation.rs`),
a hand-port of `p3-goldilocks`/`p3-poseidon2`'s Poseidon2-over-Goldilocks
construction (the hash underlying multiple independently audited
production STARK provers) rather than a from-scratch design, verified
against that reference's own test vector byte-for-byte. Porting the
*algorithm* closes the "invented, uncryptanalyzed construction" gap; it
does not by itself constitute an independent review of *this port* — a
transcription error in a constant would still be a real bug the test
vector happens to catch, not one guaranteed to be caught in general.

## Reporting a vulnerability

Please report suspected vulnerabilities privately, not in a public issue
or pull request — a public report on unfixed, exploitable cryptographic
code puts every current user at risk between disclosure and a fix.

Use GitHub's private vulnerability reporting for this repository:
[github.com/cameronaaron/novachannel/security/advisories/new](https://github.com/cameronaaron/novachannel/security/advisories/new).
This opens a private advisory visible only to the maintainer and you,
with its own discussion thread, until a fix is ready to publish.

Please include:
- The crate and file/function affected.
- A concrete scenario: what an attacker can do, under what
  preconditions (network position, prior message exchange, compromised
  material, etc.) — this workspace's own test suite is built around
  exactly this kind of "what breaks and how" framing (see
  `ENGINEERING-STANDARDS.md` §4), so a report in that shape is the
  fastest to act on.
- A proof-of-concept or failing test if you have one.

## Scope

In scope: any code under `crates/`, including its cryptographic design,
implementation, and the claims made in its doc comments and
`ENGINEERING-STANDARDS.md`. A doc comment asserting a security property
that the code doesn't actually provide is itself a valid report.

Out of scope: this is a research/engineering workspace, not a deployed
service — there is no running infrastructure, hosted API, or user data to
report against. That said, a mismatch between `novachannel-rln`'s ported
constants/round structure and the `p3-goldilocks`/`p3-poseidon2` reference
they're ported from is very much in scope and exactly the kind of report
this process wants — see its module docs for what's been checked (a
test-vector match) and what hasn't (independent review of the port
itself).

## Response

This is a personal project without a dedicated security team or a bug
bounty program. Reports will be read and acknowledged on a best-effort
basis — there is no guaranteed response-time SLA. Credit will be given
in the advisory and fix commit unless you ask to stay anonymous.

## Supply chain

Dependency vulnerabilities are checked with `cargo audit` on every pull
request and once daily via a scheduled workflow (see
`.github/workflows/scheduled-security.yml`) so a disclosure landing in
the RustSec advisory database after a dependency was already merged
still gets caught. If `cargo audit` flags one of this workspace's direct
or transitive dependencies, please still report it here rather than only
to the upstream crate — it may affect how this workspace uses that
dependency even before upstream ships a fix.
