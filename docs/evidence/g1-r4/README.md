# G1-R4 A06 evidence directory

This directory contains the candidate-only evidence contract for
`G1_R4_FAULT_MATRIX_V1`. It is an index and schema, not a signed G1 exit.
The machine-readable contract is
[`fault-matrix-contract-v1.json`](fault-matrix-contract-v1.json).

## Reproduce a local process run

From a clean Linux checkout at the exact candidate source:

```sh
out_dir="$(mktemp -d "${TMPDIR:-/tmp}/trnm-g1-r4-evidence.XXXXXX")"
chmod 700 "$out_dir"
python3 scripts/faults/g1_r4_fault_matrix_v1.py \
  --output "$out_dir/evidence.json"
python3 scripts/faults/g1_r4_independent_replay_v1.py \
  "$out_dir/evidence.json"
```

`--output` must name a JSON **file**. Missing parent components are created
one-by-one as private `0700` directories; existing caller-owned directories
are never chmod'd. The report is atomically published as `0600`, and each
negative residue is copied to `retained/<case-id>.bin` before the private run
directory is removed. An existing file is safely replaced; an existing
directory is rejected. A run without `--output` prints a local report but
does not persist raw mutants and therefore is not reviewable evidence.

The producer launches a separate writer process for each filesystem cut and
the parent sends SIGKILL only after a phase-bound checkpoint line. The replay
checker is another process with an independent fixed-line decoder and digest
logic. It must agree on all bytes, roots, statuses, counts, and error classes.

The process gate is clean-snapshot only: it checks
`git status --porcelain --untracked-files=all` before execution and rejects
both tracked edits and untracked marker files. A dirty-worktree invocation is
therefore a negative test (`REJECTED`), not a candidate pass. The gate removes
only its own generated Python bytecode on exit; acceptance still requires a
fresh clean-clone replay.

## Current result vocabulary

The expected local result is:

```text
status=BLOCKED_UPSTREAM
scope=process
authority=candidate
classification=candidate-non-normative
positive_count=4
negative_count=9
retained_mutants=9
production_candidate=false
production_consensus_activation=false
g1_r4_exit=false
```

Injected `ENOSPC`, `EIO`, torn-write, rollback, skew, and losing-fork cases
are retained negative evidence. They do not claim physical disk exhaustion,
power loss, a host reboot, a SQLite WAL/SHM result, or a production
anti-rollback root. The three-block replay is a bounded ancestor-order
fixture, not the required 100,000-block real-node corpus.

## Interface request and invalidation

`G1-R4C-ICR-A06-LAB-WATERMARK-LIFECYCLE-MODE-V1` is a proposed A05-to-A06
interface request. This branch forwards the existing
`semantic_per_reservation_v0()` bit from `LabFileWatermark` and retains
unknown/restart/facts-mismatch negatives. The additive
`semantic_signer_journal_pair_v0()` trait method is absent from the exact 6e
base and is intentionally not added to A05-owned files here. Pair forwarding
therefore remains blocked until A05 publishes and accepts that interface.

The missing A02 Core acknowledgement, A03 ordinary Proposal permit, A04
application commit/readback, and A05 whole-node checkpoint/CAS interfaces
also remain blockers. When any of them changes, invalidate and rerun this
envelope plus A07 campaign, G1-S02/G1-S03, G1 exit, G2F, and release evidence.

The three A06 crypto forwarding/negative tests passed with the pinned
`1.95.0` toolchain in this worktree. The process gate intentionally executes
no Cargo command; workspace-wide format/clippy and clean-clone replay remain
pending. A passing Python gate is useful candidate evidence only and cannot
promote machine truth.
