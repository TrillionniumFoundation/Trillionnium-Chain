# Branch-bound work schedules: fixed-window C0 and anchored ASERT C1

## Status and authority

This is an additive, bounded research component under the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It changes no existing Node target, timestamp, packet, storage, activation,
fork-choice, or deployment rule. Production activation and cheapest-work
qualification remain false. It does not supply a mixed classical/quantum
consensus theorem.

The [native component](../../../../trillionnium/crates/trnm-pon-node/src/research_work_schedule.rs)
adds a checked branch-schedule API, full-W1 research checks for actual PNH1 and
PGH2 challenges, and a read-only adapter from the original Node's retained
parent path. The [native controls](../../../../trillionnium/crates/trnm-pon-node/tests/research_work_schedule.rs)
separate synthetic arithmetic histories from real complete-W1 packets.
Execution status belongs to the exact source evidence accompanying this
component, not to the presence of test functions in the source tree.

`CheckedBranchSchedule` deliberately does **not** say `ValidatedChain`.
`from_parent_first` checks the supplied schedule, but caller-provided header
identifiers are not independently authenticated by that constructor. The
native adapter obtains actual retained packets, checks their original IDs and
record heights, and completely replays their W1 relations before rebuilding
the schedule. Neither interface reexecutes application State, authorizes a
task, validates payments, or grants an atomic storage snapshot capability.
No new consensus or storage owner is introduced.

## Incremental continuation

The [incremental full-W1 context](INCREMENTAL_WORK_SCHEDULE_RESEARCH_V1.md)
can extend a checked research prefix by one complete PNH1 or PGH2 packet
without replaying prior proofs. It starts from this profile's genesis, has no
untrusted checkpoint constructor, publishes only after all verification and
cancellation checks, and retains the finite 4096-height scope. The original
retained-branch adapter below still replays its entire input history.

Candidate-only `clock_eligibility` and whole-branch
`branch_clock_eligibility` are separate queries. The latter retains the
maximum ancestor timestamp even when old-policy timestamps are nonmonotone.
Neither query changes historical target or credit. The
[time and credit continuation](TIME_CREDIT_CONTINUATION_V1.md) records the
existing native Growth clock integration, the rejected external quantum
source bound, and the remaining production qualification gates.

## Exact finite contract

The independent caller fixes a `Profile` before examining a candidate. Its
digest binds network, parameter identity, genesis ID/time, initial target,
pow limit, old retarget interval, spacing, future skew, actual PNH1/PGH2 wire
selection, policy, and the finite height bound of 4,096. The new hash domains
are `pon-branch-work-schedule-research-v1` and
`pon-research-schedule-statement-v1`.

These are **research result domains**, not changed header signing or work
domains. Existing native packet parameters do not thereby commit to ASERT.
Installing a policy in native consensus still requires an explicit new
parameter/wire/storage transition and its own admission/recovery validation.

The input path contains every non-genesis ancestor, parent first. Its last
link must reach this profile's genesis. Duplicate IDs, missing links, skipped
heights, a different expected parent, and wrong network/parameters refuse.
There is no supplied initial work, free-standing anchor, peer work, best-chain
anchor, or checkpoint that can shorten the required path or restart its credit.
The parent height must be below 4,096; the next candidate can be at height
4,096. A longer history is outside this research qualification and refuses.

| Property | C0: fixed target | C1: anchored integer ASERT |
| --- | --- | --- |
| Required target | Initial target throughout the entire research window | Old rule through activation height, then the branch anchor |
| Activation block | Not applicable | Still uses the original target and time rules |
| Anchor | None | Activation block, with its actual target and its parent's timestamp |
| New timestamp rule | From height one | Strictly after the activation block |
| Timestamp predicates | Child at least parent; child strictly above upper MTP11 | Same new predicates; old predicates retained for old history |
| Retarget resets | None | No periodic, restart, Cell-release, or profile-local phase reset |
| Credit | Existing exact required work, checked 512-bit accumulation | Same units and original old-history credit |

The profile fixes one policy for its complete bounded history. Results from
different policies do not obtain a new common work unit merely because both
use a `Work` type. The proposed fixed-probability/variable-work relation needs
its own qualified cost envelope; this component does not implement it by
multiplying W1 credit by nominal units.

## Pure target calculation and anchor binding

`CheckedBranchSchedule::required_target()` takes no candidate timestamp,
wall clock, advertised work, model quality, price, or miner-selected anchor.
The constructor has already computed it from this exact parent path.

For C1, let `a` be the activation-height ancestor and `p` the parent:

\[
T_{next}\approx T_a\,2^{(t_p-t_{parent(a)}-s(h_p-h_a+1))/\tau}.
\]

The implementation uses the BCH integer cubic approximation with truncation
toward zero for the signed fixed-point exponent, then Euclidean decomposition
into an integer shift and a nonnegative 16-bit fraction. It retains full
256-bit targets without `nBits` compression. Checked signed 128-bit
intermediates reject parameter overflow. The target product is represented
with the existing 512-bit type; oversized shifts have explicit clamp outcomes,
not platform-specific wrapping or overflow. Targets stay in `[1, pow_limit]`.

The [official BCHN specification](https://bitcoin-cash-node.gitlab.io/bchn-sw/bitcoincash-upgrade-specifications/2020-11-15-asert/)
defines the rounding and parent-of-anchor time convention. The
[fixed BCHN implementation](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/pow.cpp)
is the existing repository's upstream arithmetic reference. This implementation
does not import the BCH testnet delayed-block minimum-difficulty exception,
BCH's 600-second spacing, its two-day half-life, or its compressed target
encoding as PoN protocol requirements.

The [retained 18-vector fixture](../../../../formal/pon-nakamoto-v1/vectors/quantum-daa-asert-bchn-v1.json)
and existing [Python arbitrary-precision oracle](../../../../formal/pon-nakamoto-v1/quantum_daa_model.py)
are reused. Additional native controls cover negative fractional rounding,
full-width targets, overflow, and saturation. Eighteen upstream unit vectors
are not the complete external BCH ASERT vector corpus.

An anchor is derived from the continuous parent branch. Its private fields
bind profile digest, anchor block ID, height, target, and parent time. The
cache key is `(profile_digest, anchor_block_id)`. `check_anchor_hint` compares
the entire derived anchor; a hint cannot replace or select it. A fork with a
different activation ancestor fails that comparison even at equal heights.
Rebuilding the same branch after a cold reopen recomputes the same values.

## Historical validity versus current eligibility

New-rule historical checks enforce

\[
t_h\geq t_{h-1},\qquad t_h>\operatorname{upperMedian}(last\;\leq11\;ancestors).
\]

Equality with the parent is legal only when the separate MTP predicate also
passes. These predicates do not certify physical elapsed time. Monotone time
compression, catch-up, future dating, withholding, and long private forks
remain security obligations.

`HistoricalCheck` binds the complete encoded header and profile digest,
required target, per-block work, and accumulated work. A separate
`clock_eligibility(now)` returns `Eligible` or `DeferredUntil(timestamp-skew)`
with exact unsigned boundary behavior. Clock movement, including rollback,
changes only that eligibility. It cannot recalculate an old target or work.

The contribution is still

\[
W(T)=\left\lfloor 2^{256}/(T+1)\right\rfloor.
\]

The code recomputes every contribution and uses the original checked 512-bit
addition. A winning hash's luck, proof randomness, task price, or output quality
does not enter it. This establishes arithmetic consistency, not minimum cost.

## Actual full-proof controls and their interpretation

For each actual PNH1 and PGH2 backend, the test campaign is designed to:

1. Create and admit fresh original-policy packets with complete W1 proofs.
2. Reconstruct a candidate branch context by rereading that actual native path
   and replaying every complete proof in its correct challenge domain.
3. Recompute a complete candidate proof at a changed ASERT-required target and
   pass the research full-work verifier. The original Node's separate `TARGET`
   refusal is an isolation check showing the new policy was not installed.
4. Compute another **fresh**, correct-target proof for a timestamp that is
   above MTP but below its parent's timestamp. Independently verify complete
   W1 first, then require the research `SCHEDULE_TIME_NONDECREASING` refusal.
   Original-policy admission remains possible and is retained as a distinct
   observation. No old-proof/changed-target rejection is called a time fix.
5. Accept an equal-parent timestamp where MTP permits it; reject a wrong
   complete product; propagate a cancellation error without a successful
   receipt; refuse a cross-fork anchor hint.
6. Cold-reopen the original native database and reconstruct the same candidate
   context, target and accumulated work from its original retained packets.
   An old-policy nonmonotone branch remains rejected by the new research rule.

The adapter is application-level read-only over an **already-open** Node. Its
paths issue retained-packet/height SELECTs, metadata/namespace guards, and pure
proof replay; they do not call Node open, recovery, repair, block insertion, or
activation. This does not certify zero filesystem writes by SQLite locking or
WAL machinery, and a caller-provided progress callback has its own effects.
Opening, admitting, activating, and cold reopening in the test campaign are
separate mutating operations. Progress checkpoints are not measurements of
actual CPU budget.

## Optional retained packet evidence

Set `TRNM_WORK_SCHEDULE_RESEARCH_DIR` to a fresh evidence root during the native
test run. Each backend creates a new `pnh1-authenticated` or `pgh2-growth`
subdirectory and refuses an existing subdirectory. It retains exactly seven
complete packets: `first`, `fast`, `high`, `other_anchor`, `fresh_adjusted`,
`backwards`, and `equal`. The first four retain every required parent and the
alternate activation ancestor. Packet bytes, header/challenge identities,
proof trace and SHA-256, actual and required targets, branch ancestry, anchor,
exact work, research verdicts, and cold retained bytes accompany the report.
The report's settings scope is the actual schedule inputs and task-profile
name, not a proof of complete executable/source/configuration identity.

The [independent reader](../../../../scripts/pon_branch_work_schedule_reader.py)
reuses the #794 packet decoder and scalar full-W1 oracle. It does **not** reuse
the old 114-packet experiment's DAA or time conclusions. It reconstructs the
seven-packet graph, profile/anchor digests, integer ASERT targets, MTP and
nondecreasing time predicates, and checked-width work from raw packet bytes.
Every complete W1 transcript/product is replayed at its actual header target.
Advertised challenge, target, ancestry, work, and verdict are checked against
those independent results before a scoped reader pass is returned.

For `fresh_adjusted`, research acceptance and the original Node's `TARGET`
refusal remain distinct. For `backwards`, correct target and complete W1 must
pass, MTP must pass, and only the nondecreasing predicate must fail. The reader
does not reexecute native SQLite admission, cold reopening, account-state
transitions, or growth witness semantics; these remain external runner
observations, bound to the packet identities and an independently supplied
report digest. A digest pins bytes, not source or host provenance. Neither
export nor replay installs the proposed profile or qualifies useful work,
minimum cost, quantum cost, or joint consensus security.

## Native integration still required

A research full-W1 pass is not native admission under a new profile. The next
integration must bind the policy to actual parameters, apply the same rule at
PNH1 `target_from_recent`/header checks and PGH2
`growth_target_from_recent`/header checks, use the original owner's coherent
history/transaction boundary, and retain exact schema and recovery semantics.
It must also cover mining timestamp selection, duplicate admission, activation
clock handling, history import, cross-fork ancestry, equal-work ties, cancellation
and reorganization. No automatic fallback to the old target is permitted.

The [Garay–Shen analysis](https://eprint.iacr.org/2021/143)
is relevant prior theory for ASERT under its declared model. This component
does not instantiate its participation, timing, network, or security parameter
assumptions, and does not turn it into a quantum W1 theorem. Long private
chains, resource steps, multiple half-lives, selective publication, joint work
cost, and common-prefix/chain-quality/chain-growth bounds remain open.

## Reproduction

Run the repository preflight first, then on the same frozen source:

```sh
bash scripts/project-preflight.sh
cargo +1.95.0 test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --test research_work_schedule -- --test-threads=1
cargo +1.95.0 test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib consensus::tests -- --test-threads=1
cargo +1.95.0 fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo +1.95.0 clippy --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --all-targets -- -D warnings
```

For retained evidence, use a fresh path and retain the two digest lines from
the successful native run outside its evidence directory:

```sh
TRNM_WORK_SCHEDULE_RESEARCH_DIR=/absolute/fresh/evidence \
  cargo +1.95.0 test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --test research_work_schedule -- --test-threads=1 --nocapture
python3 scripts/pon_branch_work_schedule_reader.py \
  --raw-dir /absolute/fresh/evidence/pnh1-authenticated --report-sha256 EXTERNAL_PNH1_DIGEST
python3 scripts/pon_branch_work_schedule_reader.py \
  --raw-dir /absolute/fresh/evidence/pgh2-growth --report-sha256 EXTERNAL_PGH2_DIGEST
python3 -m unittest discover -s scripts/ci -p test_pon_branch_work_schedule_reader.py -v
```

The repository's complete source/graph/CI controls and affected retained suites
remain required by their existing gates. Neither these commands nor a scoped
pass erases any inherited failure or qualifies production activation.
