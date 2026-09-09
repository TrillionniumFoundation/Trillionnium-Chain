# Exact-source Rust CodeQL disposition candidate — `ded43a…`

## Exact binding

- Source commit: `ded43a0704b455cd4bef724cb3ca40fb6db9465d`
- Source tree: `c0791ffb57e05fde43f87bfed1a3b4656c09efc0`
- CodeQL run: `34311122905`
- CodeQL artifact: `10088713526` / `8eba327ccae6cfa4a9c0c618fe665de408b35c6129ccf27a5d168c8d8611f433`
- Triage run: `34312572616`
- Triage artifact: `10088892435` / `68042b2c487489cd3d5887768ab80158bdcf977eda5a6dc3c28c0cb1a3ab1843`
- Query: Rust, `build-mode:none`, `security-extended`, pinned action `d1ba80a13dd99fba24a470575428917156a28b43`

## Complete candidate classification

| Class | Count | Candidate resolution |
|---|---:|---|
| Test/fixture bounded non-production | 667 | `used in tests` |
| Query/dataflow false positive | 32 | `false positive` |
| Public deterministic protocol value | 3 | mixed: false positive / used in tests |
| Public deterministic policy limit | 1 | `false positive` |
| Unreviewed | 0 | blocking |
| Actionable production finding | 0 | source repair required |

The committed generator consumes the immutable exact-source SARIF and the prior conservative triage artifact. It deterministically emits a complete 703-row JSON/CSV packet in CI. Every row is bound to a stable primary fingerprint, full SARIF-result digest, source-line digest, source-context digest, scope proof or explicit semantic record, and a candidate GitHub resolution. The workflow also executes fail-closed mutants for a missing manual record, forged source binding, and missing finding.

## Previously over-broad “production review required” set

The v2 path-only classifier marked 44 findings for production review. Exact source review proves 23 of those are inside `#[test]`, `#[cfg(test)]`, file-level `#![cfg(test)]`, an explicit test-support feature, or an external file imported only under `#[cfg(test)]`. The remaining 21 are bound in `manual-semantic-review-v1.json`:

- 15 `cleartext-logging` results terminate at `Vec`, `VecDeque`, or `BTreeMap` `insert/remove/push` operations rather than a logging/file-output sink.
- 2 hard-coded-value results originate from an enum/boolean predicate and are over-tainted through simulator control flow into a variable named `nonce`.
- 2 results are business-consumption sequence defaults (`0`), not cryptographic nonce material.
- 1 result is a public anti-replay forward-jump policy bound (`1_000_000`).
- 1 result is a deterministic simulator block counter initialization.

## Authority boundary

This is a candidate disposition packet, not a self-approval. It does not dismiss alerts, change CodeQL queries, weaken branch protection, or grant release/activation credit. A non-author security specialist must review the exact packet and source. Only after that acceptance may a separately authorized administration actor apply per-alert resolutions and prove the official aggregate gate passes on the unchanged source.

Current flags remain:

```text
independent_specialist_acceptance=false
alert_dismissal_authorized=false
official_codeql_gate_success=false
all_gaps_closed=false
production_candidate=false
public_testnet_ready=false
release_ready=false
```
