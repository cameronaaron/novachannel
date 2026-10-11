# Security Policy

This workspace (`novachannel`, `novachannel-rln`, `novachannel-dp`,
`novachannel-oram`, `novachannel-mpc`) is unaudited research cryptography.
`ENGINEERING-STANDARDS.md` describes its testing bar, and each crate's module
docs (`crates/*/src/lib.rs`) state what it does and doesn't claim.

Note in particular `novachannel-rln`'s permutation
(`crates/rln/src/permutation.rs`): a port of `p3-goldilocks`/`p3-poseidon2`'s
Poseidon2-over-Goldilocks, checked against the reference's test vector and
against the published crate on random inputs. Porting an audited algorithm
removes the "invented construction" risk; it is not an independent review of
this port.

## Reporting a vulnerability

Report privately, not in a public issue or pull request, through GitHub's
private vulnerability reporting:
[github.com/cameronaaron/novachannel/security/advisories/new](https://github.com/cameronaaron/novachannel/security/advisories/new).

Please include:
- the crate and file or function affected;
- a concrete scenario: what an attacker can do and under what preconditions
  (network position, prior exchanges, compromised material), the same
  "what breaks and how" framing as `ENGINEERING-STANDARDS.md` §4;
- a proof of concept or failing test, if you have one.

## Scope

In scope: everything under `crates/`, its cryptographic design and
implementation, and the claims in its doc comments and
`ENGINEERING-STANDARDS.md`. A doc comment claiming a property the code
doesn't provide is a valid report, as is any mismatch between the Poseidon2
port and its reference.

Out of scope: there is no deployed service, hosted API or user data.

Known and documented, so not new reports: a malformed RLN proof can abort the
process calling `novachannel_rln::air::verify` (an upstream winterfell
allocation; see that function's docs), and positive-epsilon cover traffic is
not differentially private.

## Response

This is a personal project with no security team or bug bounty. Reports are
read and acknowledged on a best-effort basis, with no guaranteed response
time. Credit goes in the advisory and fix unless you prefer anonymity.

## Supply chain

`cargo audit` runs on every pull request and daily
(`.github/workflows/scheduled-security.yml`), so advisories published after a
dependency was merged are still caught. If it flags a dependency, a report
here is still welcome: how this workspace uses it may matter before upstream
ships a fix.
