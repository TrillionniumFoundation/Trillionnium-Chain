# A18 decoder registry regeneration audit — 2026-08-30

Status: **candidate evidence only; no Gate, release, production, or activation promotion**.

## Source-bound observation

The Native PoCO-BFT decoder registry checker rejected the committed generated
artifact because its recorded `rust_decoder` SHA-256 no longer matched the
canonical `trnm-consensus-types/src/cev0_decode.rs` bytes. The independently
maintained decoder taxonomy reference and all frozen wire/QC/TC/handoff vectors
passed before this generated-artifact comparison.

A one-shot GitHub-hosted workflow ran the sole canonical generator:

```text
python3 scripts/ci/check_poco_bft_v0_registry.py --emit
```

It then replayed the normal fail-closed checker, committed the exact generated
JSON, and deleted the temporary write-capable workflow in the same commit.

Regeneration commit:

```text
91183eaa41599b06c8e3d27661ed26a87f45c4d9
```

The generated change updates only the recorded source digest:

```text
rust_decoder = 0ade3799f7f62e6e8a7951bdb979af0012d98435fe33889eb1202cdca8ed1488
```

No decoder code, ordinal, scope, class, bound, schema partition, protocol
parameter, activation bit, or production claim was changed by the regeneration.

## Required replay

This audit record intentionally advances the candidate source commit so GitHub
Actions reruns under a repository maintainer identity rather than the temporary
`github-actions[bot]` author. Acceptance requires completed-success results on
this record's descendant exact head for:

- `repository-truth`;
- `protocol-contract`;
- `fuzz-smoke`;
- `external-evidence-contract`;
- `rust-baseline`.

The independent-review, branch-protection, real multi-host, HSM/KMS, physical
power-loss, external audit/red-team, wall-clock soak, governance, release, and
activation blockers remain open and must not be inferred from registry
synchronization.
