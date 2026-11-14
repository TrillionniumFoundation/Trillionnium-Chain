# Read-only mapping of the seven open Dependabot alerts

The authenticated ProfHepta API observation found one complete page with seven open alerts, all for pip `cryptography` in `formal/pon-nakamoto-v1/requirements.txt`. The observed default branch is `main` at `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`. Its pin `41.0.7` is in all seven returned vulnerable ranges.

The already published candidate `dc42ce4df5cff79cc61c5addbaf01074b56b06ca` pins `50.0.2` at the same path, outside every returned vulnerable range. **No additional candidate dependency change is supported as necessary for these seven alerts.** This is a source-level remediation finding, not an installed-environment test or a claim that GitHub has closed the alerts.

| Alert | GHSA | Severity | Affected range | First patched version | Candidate 50.0.2 |
|---|---|---|---|---|---|
| #21 | GHSA-537c-gmf6-5ccf | high | >= 0.5.0, < 48.0.1 | 48.0.1 | outside range |
| #20 | GHSA-m959-cc7f-wv43 | low | < 46.0.6 | 46.0.6 | outside range |
| #19 | GHSA-r6ph-v2qm-q3c2 | high | <= 46.0.4 | 46.0.5 | outside range |
| #18 | GHSA-h4gh-qq45-vh27 | medium | >= 37.0.0, < 43.0.1 | 43.0.1 | outside range |
| #17 | GHSA-6vqw-3v5j-54x4 | high | >= 38.0.0, < 42.0.4 | 42.0.4 | outside range |
| #16 | GHSA-9v9h-cgj8-h64p | medium | < 42.0.2 | 42.0.2 | outside range |
| #15 | GHSA-3ww4-gg4f-jr7f | high | < 42.0.0 | 42.0.0 | outside range |

## Exact source identities

- Main requirement blob: `8529cb0ae36c10d37424b4573641f8cb4a5d4592`, 128 bytes, SHA256 `699b2a85292ac62587fbb32d0e207e709569d32540002ec0e8d206445d76cb6d`.
- Candidate requirement blob: `f505bfe105e824248803af99d2865a97dbf3cd8c`, 128 bytes, SHA256 `ae117e781e1420b46bfc2c4b9a550da3fe3f98ff9cbe868192036d34c342aed5`.
- Candidate portability inventory blob: `94b92f2a4877036ea3929a83f90ba3bbe8ca2ae3`, SHA256 `e766e17c0b85a79066f09ba609beca4439e91bc66b3039fa7b10f3b00fa0b390`.
- Candidate required workflow blob: `7837ff18f48b3cb9b0d38f161fc8f27a9fdbf919`, SHA256 `a93a36bf4a93f078b162403825ea45d92dc4a34989f678125bdbc928662da844`.

This is an active scientific/conformance requirement file, not a historical-only exception. Its first line and current formal README describe isolated development use rather than dynamic installation by a public node. The required workflow installs it at lines 271, 359, 461, 552 and 603. The current model-runtime CPU requirements also pin 50.0.2 with wheel hashes, and the PQ workflow explicitly selects 50.0.2. The portability inventory selects pon-nakamoto-v1 and preserves the named native Rust owners; its retired-package decisions do not retire this formal input.

The bounded manifest inventory found three Python requirement/lock files under .github, scripts, formal, config and trillionnium; the two declaring cryptography both pin 50.0.2. Original 41.0.7 strings in the current readiness tests are intentional rejection fixtures. This search does not cover every historical archive and does not convert the earlier RustSec result into a pip audit.

## Evidence and boundaries

The complete raw alerts response is `open-dependabot-alert-pages.stdout` (22,150 bytes; SHA256 `ee9ca2d6bc590138f7e5c75fa4fcc9c0d2c7416cfb0b529aa2802693e0e3b6b7`). Raw user, repository and default-branch reads, command results, fixed Git exports, hashes and source-before/after checks are retained separately. API reads were sequential rather than an atomic transaction.

All seven alerts remain open in the observed default-main namespace. No remote state was changed. A later normal integration and GitHub dependency scan can produce a new alert observation; this review does not predict that result. No tests, installations or Host workloads ran, and no source, history, Git refs, report or PR content was edited. The wheel-only qualifications on the relevant OpenSSL advisories are retained in the raw API response; no actual installed wheel/backend was inspected here.
