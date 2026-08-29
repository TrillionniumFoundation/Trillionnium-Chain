# G1-R4 fault matrix and independent replay v1

Status: **BLOCKED_UPSTREAM / partial candidate slice**

Evidence classification: `candidate-non-normative` (scope `process`, authority
`candidate`).

This is the A06 package `G1_R4_FAULT_MATRIX_V1`.  It closes only the
independent, test-only process boundary that can be exercised without the
accepted A02--A05 interfaces.  It does not close G1-R4, G1-S03, or any
production/activation claim.

## Authority and exact source tuple

The implementation branch starts from the exact candidate required by the
agent control contract:

```text
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref   = refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829
base_commit = 6e0189e351015ef3230f217ca7ff86149baedcf0
base_tree   = efea864cb2fbc4835a59a089b3dbab8934e71231
source_branch = feature/chain-g1-r4-fault-matrix-v1-20260829
published_branch = feature/chain-g1-r4-fault-matrix-v2-20260829 (orchestrator handoff target)
```

The assessed plan tuple remains the one frozen in the registry
(`8198fea0307eb368df34ff77ffc272a6b0e655ec` /
`a1be71bba1b54c428493d186fafb656d081b31a9`).  The latest live plan was also
revalidated at `92449b8e101642f39d644d863db7bb60dea488f7` /
`cf8f1ab4f5065cb0551a30ec0e036cd44cb31766`.  A plan-tip change invalidates
the evidence envelope and requires replay; it is not silently folded into the
candidate source.

## Objective and boundary

The harness proves byte-stable process/reopen behavior for a small
candidate-only durable record.  A writer runs in a separate OS process,
emits a phase-bound checkpoint, and is stopped by the parent with signal 9.
Recovery classifies only the exact residue.  A separately implemented replay
process parses the evidence and independently checks bytes, digests, roots,
statuses, counts, and retained mutants.

The harness is an evidence producer, not a signer, SafetyRules owner, Core
receipt issuer, application/JMT owner, or whole-node checkpoint authority.  It
cannot mint production capability or alter `config/consensus-mainline.json`.

Owned changes are limited to:

```text
trillionnium/crates/trnm-poco-lab-validator/**       # test/lab adapter seam
trillionnium/crates/trnm-poco-node/tests/**          # reserved test surface
scripts/faults/**                                    # independent harness/replay
scripts/ci/*process_matrix*                          # local process gate
docs/evidence/g1-r4/**                               # evidence contract/index
this R4 fault-matrix package document and manifest
```

Production consensus semantics, production capability constructors, A05
Safety/Signer/Checkpoint modules, truth flags, release metadata, and network
campaign workflows are forbidden.

## Closed local slice

The following local interface gap is implemented on the exact 6e trait surface:

```text
ICR-A06-001
current interface: LabFileWatermark as ExternalMonotonicWatermarkV0
closed here: semantic_per_reservation_v0() is forwarded exactly from the
             wrapped authority; absent delegate remains false/unknown
deferred: semantic_signer_journal_pair_v0() requires the additive A05 trait
          method and is intentionally not added to an A05-owned file here
```

The lab wrapper does not infer lifecycle compatibility, switch to opaque CAS,
or turn an unknown bit into authority.  Candidate tests retain:

- explicit per-reservation forwarding and legacy-CAS rejection;
- unknown/false lifecycle mode and restart with a missing external head;
- altered semantic facts causing fail-closed poisoning;
- the future pair-attestation requirement as a typed upstream blocker.

The three new crypto tests were compiled and passed with the pinned
`1.95.0` toolchain available to this worktree.  The process gate itself does
not invoke Cargo.  The complete package suite was not claimed: a broader
unfiltered run was interrupted after compilation because unrelated long-lived
runtime tests exceed this lane's bounded handoff window.  Workspace-wide
format, clippy, and clean-clone replay remain follow-up checks.  The tests
must be replayed after A05's additive
`semantic_signer_journal_pair_v0` interface is accepted.

## Process fault/replay matrix

`scripts/faults/g1_r4_fault_matrix_v1.py` runs 13 deterministic cases:

| Cases | Required outcome |
| --- | --- |
| SIGKILL before publish; response loss before commit | exact temp recovery and idempotent retry |
| response loss after commit | exact target replay, no duplicate residue |
| disk full; I/O error; fsync error | injected error is retained; no fabricated target |
| directory-fsync error after publish | ambiguous target is retained for exact readback |
| torn write | malformed prefix is retained and rejected |
| database/namespace rollback | lower-than-external-watermark state is rejected |
| application/Safety skew | root mismatch is rejected before use |
| three-block ancestor order | independent replay accepts only contiguous 1,2,3 |
| losing fork | loser is retained; no automatic GC authority |

The current local run is 4 positive cases, 9 negative cases, and 9 retained
mutants.  `disk_full`, `io_error`, `fsync_error`, and
`directory_fsync_error` are deterministic injected errno classifications; they
are not physical disk-full or power-loss evidence.  Host reboot, SQLite
WAL/SHM/hot-journal behavior, and real Application/Safety/Signer/whole-node
CAS cuts remain open until the owning interfaces exist.

## Exact evidence contract and commands

The checked-in contract is
[`../../evidence/g1-r4/fault-matrix-contract-v1.json`](../../evidence/g1-r4/fault-matrix-contract-v1.json).
The producer and independent verifier are:

```sh
python3 scripts/faults/g1_r4_fault_matrix_v1.py \
  --output <new-or-replaceable-file>/evidence.json
python3 scripts/faults/g1_r4_independent_replay_v1.py \
  <new-or-replaceable-file>/evidence.json
bash scripts/ci/check_g1_r4_process_matrix_v1.sh
```

`--output` names a JSON **file**, not a directory.  Missing parent components
are created one-by-one with mode `0700`; existing caller-owned directories are
never chmod'd.  The file is atomically replaced with mode `0600` and the
`retained/` siblings contain raw negative residues.  Passing an existing
directory fails closed.  A stdout-only run hashes and indexes residues for a
local check but does not create a durable evidence bundle; use `--output` for
reviewable retention.

The gate records exact source/head/tree and worktree status, executes the
subprocess matrix and the independent replay in separate processes, checks all
required scope/authority flags, and executes no Cargo command.  The targeted
crypto test result is recorded above; workspace-wide format/clippy and
authorized clean-clone replay are still pending and are not inferred as
passes.  Its static permission checks cover recursively created `0700`
parents, preserve an existing non-private caller directory, and reject an
existing directory supplied as the output path.  The gate is also
clean-snapshot only: tracked edits and untracked marker files are rejected
before execution, while a clean-clone replay remains required for acceptance.

## Invariants, mutants, and open upstream gaps

The local assertions are:

```text
every named durable cut has a positive or negative result
SIGKILL checkpoints are parent-observed signal 9
independent replay agrees on bytes, roots, statuses, and error classes
all nine negative mutant kinds remain retained and indexed
production_authority_minted=false
g1_r4_exit=false
```

The package remains `BLOCKED_UPSTREAM` for:

1. A02 Core acknowledgement atomicity and generated Core receipt;
2. A03 ordinary Proposal permit/body/JMT authority;
3. A04 application commit/readback and SQLite fault hooks;
4. A05 whole-node Safety/Application/Signer checkpoint CAS and the additive
   pair-lifecycle attestation;
5. physical power-loss/host-reboot classification, clean-clone Cargo replay,
   100,000-block real-node corpus, and multi-host network replay.

No blocker is bypassed by the synthetic record.  Once an upstream interface
lands, the minimum invalidation set is A06 process evidence, A07 campaign,
G1-S02/G1-S03/G1 exit, G2F, and release evidence.

## Module-local outcome and rollback

Outcome: `BLOCKED_UPSTREAM`.  The local harness and wrapper-forwarding slice
are candidate-only and reviewable; module closure is not gate acceptance.

Rollback is one package-boundary revert of this branch's changed paths.  Raw
failed residues in a published evidence directory remain immutable and are
marked superseded/invalidated by a later envelope; they are not deleted to
make a rerun pass.  The final branch head/tree and changed-path list are bound
in the agent handoff, not self-referentially embedded in this document.
