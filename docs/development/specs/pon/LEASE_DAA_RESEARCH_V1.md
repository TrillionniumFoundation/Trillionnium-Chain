# PoN lease continuity × DAA adversarial research v1

Status: non-activated engineering research for existing PN1/PN2/PN5 and M02/M06/M17.
Source base: Trillionnium-Chain PR #328 at `630f871293e48588e0a1ceae7ceb64973d3ec31d`.
This document is a subordinate test/engineering specification, **not** a second
architecture plan, accepted consensus revision, activation, or production certificate.

## Authority boundaries

- Q4 revision9 QDL2/QWA2 domains, tag22 atomic renewal, authenticated source
  sequence, retention and branch-relative rollback remain exact and unchanged.
- Revision12 explicit genesis maintenance is already implemented. It is selectable
  independently of optional sources, but never substituted for a named revoked,
  expired or missing task; its useful-output credit remains zero.
- The installed M02 `retarget` and `check_time` remain byte- and behavior-identical.
- Isolated `consensus::daa_research::asert_target` is not called by Node, CLI,
  mining, validation, persistence, expected-target determination or chainwork.
- No API signs for a source, reclassifies stored legacy history, accelerates a
  chosen proof by unverified shortcuts, or creates an implicit hash-only fallback.

## Work packages and acceptance (current evidence is scoped)

| Package | Implemented artifact | Still required for strict closure |
|---|---|---|
| P0-A | Original Revision12 real W1 maintenance/revocation, SQL recovery and reorg tests plus newly added `maintenance_recovers_signed_task_registration_and_policy_confirmation_after_revoke` native regression | Execute exact-head new test with current runtime, independent client/history re-execution, lost-material and multi-source cohorts; required-W threshold and no hidden fallback |
| P0-B | Q4 existing delayed tag22/atomically retained source tests; new independent negative-control state model for last block, too-late inclusion and retained slot | Real expiry at 1000, all 32 occupied slots, reclamation **after** `available_until`, signer absence, delayed ACK, reorg and source-owner handoff across independently governed operators |
| P0-C | Repository's original `pon_w1_budget_report`, fastest-observed structured/maintenance producers, false-trace and paid-CPU tests | Frozen longest reuse horizons, GPU/FPGA/ASIC/CPU miners, adaptive legal kernel selection, fastest complete work lower bounds, honest-peer ingress fairness and independent review; `work_profile_qualified` stays false |
| P1-A | Native isolated checked integer ASERT candidate plus independently coded Python oracle; common scalar vectors and errors | Exact-head native test runs, independent hidden vectors and a protocol review; no activation |
| P1-B | 80-header timestamp schedule with 5×4 clamps; synthetic steady, 16-block oscillation and sustained-shock targets; lease and fork-choice guard cases | Actual valid W1 packets, calibrated hashrate stochastic simulation, selfish mining strategy, network partition/heal, clock drift, peer service and confirmation risk under identical budgets |
| P1-C | Standalone Rust native **arithmetic candidate only**, old M02 unchanged | A distinct versioned consensus/genesis/parameter context, fork-aware ancestry/MTP anchor derivation, full native valid-proof admission/reorg/reopen, third-language oracle, client work confirmations and explicit reviewed activation |
| P2 | Documented pre-registration/fault matrix (below) | Three independent administering organizations, real WAN, 72h sustained measurements, paid materials, attacker budgets and externally signed receipts; no claimed qualification here |

A reference test pass does not close a native or independent acceptance gate. No
progress metric is inferred from counts of source files, documents or test rows.

## DAA candidate contract

The old algorithm remains a 16-block (15-interval) raw-endpoint retarget with
clamp factor 1/4..4, MTP11 lower bound and observed-clock +120s upper bound.
An independent test can construct 80 time-valid timestamps where five retargets
multiply the target by 4 each (until `pow_limit`). That is an **arithmetic/time
validity** counterexample, not 80 mined blocks or demonstrated profit.

The new *research* function uses the BCH aserti3-2d polynomial with truncation
toward zero to form a signed fixed-point exponent (radix 2^16). It returns a full
PoN integer target, **not** compact Bitcoin Cash nBits (so no nBits rounding).
The fixed anchor is a block with `anchor_height` and `anchor_target`; the supplied
`anchor_parent_time` is the parent's timestamp *before* that anchored block.
For candidate height `h` and parent observation `p_time`:

    deviation = p_time - anchor_parent_time - (h-anchor_height)*spacing
    exponent = trunc_toward_zero(deviation*65536 / half_life)
    shifts = floor(exponent/65536)
    frac = exponent - 65536*shifts
    factor = 65536 + ((195766423245049*frac + 971821376*frac^2
                      + 5127*frac^3 + 2^47) >> 48)
    candidate_target = clamp((anchor_target*factor*2^shifts)>>16, 1, pow_limit)

The negative shift in the final expression denotes right shifting; all operations
are checked and bounded in the native routine. Anchor-relative elapsed time and
height must come from **authenticated candidate-branch ancestry**, never a
header-supplied alternative anchor, local operator choice or DHT advertisement.

Two research selectors use identical integer arithmetic: raw parent timestamp or
MTP11 of its ancestors. They are competing rules, not simultaneous network
profiles. Median input may delay difficulty response to honest hashrate collapse;
raw input is more sensitive to endpoint manipulation. Half-lives 3600, 7200,
14400, 28800 seconds are comparison candidates only; nothing is selected.

The historical `retarget` and `check_time` functions must not be replaced in the
existing revision. Any future consensus switch requires a separately committed,
versioned protocol activation and exact branch/time/witness migration.

## Executable local research commands

    python3 -m unittest -v test_daa_lease_research.py
    python3 daa_lease_campaign.py --output NEW_NONEXISTENT_REPORT.json
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib daa_research_tests -- --test-threads=1
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib maintenance_recovers_signed_task_registration_and_policy_confirmation_after_revoke -- --test-threads=1

The Python suite does not execute Rust and does not assert source signatures or
proofs were generated. The native regression is a development-key/Node fixture:
it checks actual signed registration and local policy-confirmation readback, not
independent public identities. No source can relabel a synthetic pass as a native
or independent qualification. Record actual source tree, compiler, command,
stdout, stderr, and failed tests; do not repin old evidence to new code.

## P2 independent-operator acceptance freeze

A separate freeze record must name the exact candidate source, common genesis,
work relation, software hashes, observed hardware, CPU/RAM/GPU/disk limits, real
WAN topology, time offset tolerances, data-retention funding and failure domains.
At least three custodians/operators must prove independent control and live task
source authorization; three hosts sharing one administrator do **not** qualify.

Pre-register: full task revocation; author offline; 32 occupied lease slots;
late signed successor before/after expiry; storage-loss/repair; native-work and
cheap-invalid-proof floods; transient/final network partitions; timestamp warp;
oscillating effective hashrate; self-mining/withholding; restart and physical
power cuts; deep valid reorg and exact client membership/required-work checks.

Publish every attempted request, timestamp, resource budget, measured full
valid/invalid proof cost, honest confirmation latency/denominator, missing
samples, minimum storage recovery time, false state roots, and operator signing
receipts. Set p95/p99 sample counts and safety/availability thresholds before
starting. No favorable censoring, auto-resign, implicit fallback or
nonqualified relaxation of the activation flag is permitted.

## References

- Original candidate Q4: `docs/protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V4.md`.
- Original continuity: `docs/protocol/pon-nakamoto-v1/details/CONTINUITY_V1.md`.
- Prior real timestamp/valid-work evidence: `docs/protocol/pon-nakamoto-v1/details/WORK_COST_DAA_BOUNDARIES.md`.
- External numerical source: [BCH aserti3-2d specification](https://upgradespecs.bitcoincashnode.org/2020-11-15-asert/).
- External time-warp precedent: [Bitcoin BIP94](https://github.com/bitcoin/bips/blob/master/bip-0094.mediawiki).

## Source-bound 32-slot retention continuation (2026-10-25)

Research additions to the existing Q4/M06 and Revision12 native suites:

- `all_32_q4_slots_reject_early_reopen_and_allow_only_retention_safe_generation` constructs all 32 original QDL2 slots, refuses a 33rd distinct slot and early reuse (at and before `available_until`), then tests a new generation on the first legal height. Both stale ACTIVE and explicitly revoked records have the same retention bound. Pure M06 transition state is replayed; a cloned state is not a real fork.
- `native_32_slot_revocation_preserves_maintenance_confirmation_and_reopen` exercises actual signed 31 new opens, all 32 signed revocations, a rejected early replacement, explicit Genesis Maintenance W1 work, client policy-confirmation readback and SQLite reopen. The identities are all development fixtures and do not constitute independent operators.
- The Python Q4 model previously required `expired` or `revoked` status for slot reuse, while the native `open` checks only `previous.available_until < height`. The research model now follows the native rule and still validates diagnostic statuses. This does not change the original Q4 signed bytes, `open`, fee, nonce, eligibility or retention semantics.

The new Rust selectors are **NOT_RUN** in this isolated execution host (Rust toolchain and full project checkout are absent); no compile/Clippy/native proof success is claimed. The previous 11 Python research controls must be rerun on the final exact source. Do not promote P0-A, P0-B, P0-C, P1-C or P2 based on file presence or a test declaration. Production remains disabled.

## Deterministic Poisson feedback comparison (research v2 only)

The previously fixed 80-header time-warp schedule and equal-header half-life
curves are preserved. A separate `stochastic_mining_path` model now feeds each
legacy/raw-ASERT/MTP-ASERT target back into subsequent exponentially distributed
waiting times. Fixed seed 20261025 runs 160 simulated headers with four
effective-hashrate scenarios: steady; abrupt fivefold reduction; periodic
0.4x/2x oscillation; and a simulated loss of 80% of miners when lease
sources disappear while genesis maintenance remains available. An optional
30% timestamp-controller toy varies some endpoint timestamps within the original
MTP11 and future-skew constraints. Every produced time is checked; no valid W1
proof, independent miner, signed task, network fork, GPU cost or confirmation
security follows.

The report schema advances from `trnm-lease-daa-research-v1` to `v2` because
the stochastic distributions and their assumptions are additional fields.
Legacy reports remain bound to their original schema/source; do not rewrite
their bytes or infer superiority from single-seed p95. The added Python
selectors only test input denial, timestamp validity and seed repeatability.
P1-B adversarial and P2 independent operational acceptance remain open.

## Real native-ancestry shadow comparison (non-activated)

A further native selector, `isolated_asert_shadows_actual_native_w1_ancestry_without_activation`,
retains 48 actual mined/admitted W1 packets at a 10s declared logical timestamp
cadence, reads their original validated parent ancestry, and calculates both
raw-parent and MTP11 ASERT shadow targets without using either result in Node
admission. It checks steady-cadence raw equality, MTP lag, the unchanged
legacy expected target, native packet readback, full branch activation and cold
SQLite reopening. Fixed logical-clock fixtures are not physically paced public
mining. This test has NOT been compiled or executed in the current isolated host
and does not activate ASERT or satisfy P1-C/P2; it is an additional falsifiable
native qualification selector to run on a real Rust environment.

## Independent ASERT extreme-shift oracle repair (research-only)

The Python oracle previously attempted an unbounded left shift when a legal u64
parent timestamp and tiny half-life produced a very large positive exponent.
This can raise MemoryError before an expected research verdict. It now mirrors
the existing native ASERT saturation checks: shifts >= 256 return pow_limit,
and shifts <= -512 return target 1. No consensus target selector changed.

Both languages now declare a frozen 512-case xorshift64 input stream, including
maximum u64 parent times, floor/negative exponent semantics, 1-second
half-lives, and finite raw fixed-point values. The committed Python expected
SHA-256 over 512 concatenated 32-byte targets is:
`6be87e237c37aec8c50af8d4eaf9e14a0ca60e7dc69f18143ede1ef70c420c97`.
Python generated this digest locally, but the new exact-source Rust test is
NOT_RUN on the present host. This corrects a research verifier resource
bug; it does not prove public W1 hardness or activate a new DAA.

## Third-language numeric oracle and second native readback (2026-10-25 continuation)

A **standalone Go math/big** implementation has been added under
`formal/pon-nakamoto-v1/daa_reference_go`. This is a third source-language
numeric implementation: it independently computes the same exact 512-case
SHA-256 target stream as the existing Python and Rust candidates. Its local
Go unit tests and CLI were actually executed in the current research
container, including i128 overflow, negative floor shifts and huge-exponent
saturation. The frozen SHA-256 target-stream digest is
`6be87e237c37aec8c50af8d4eaf9e14a0ca60e7dc69f18143ede1ef70c420c97`.
See its own README for exact commands and nonclaims. This improves P1-A
arithmetical reproducibility, but does **not** provide a third independently
operated security reviewer, deployed consensus profile or W1 hardness proof.

The existing native `maintenance_recovers_signed_task_registration_and_policy_confirmation_after_revoke`
regression is strengthened to have a **second Node instance** with a separate
SQLite directory decode and admit each original W1 packet independently,
compare branch state and actual depth/work confirmations, reject a corrupted
registered-block proof without state mutation, and reopen both stores at the
same final tip. Those changes are test-only. The new Rust source has not been
compiled in the current Go/Python-only container and is not recorded as an
executed native receipt. Both Node instances have one developer/administrative
owner, not two independent WAN consensus operators.

P0-C work-hardness, hostile ingress, task-source independence, native long-term
Q4 reclaim and all P2 WAN/physical acceptance remain explicit blockers.
Production remains disabled and old Q4/Revision12/DAA rules are unchanged.

## Explicit long native expiration and retention exercise

An additional opt-in native test,
`long_native_retention_safe_sole_slot_reopen_after_1100_maintenance_blocks`,
is marked `#[ignore]` because it creates 1,108 actual W1 Maintenance blocks
and durable SQLite transitions. It observes the original sole lease expire
at block 1000 while maintenance continues, refuses that old task at 1001,
checks the retained slot at 1100, then includes a newly signed requester
OPEN and independently signed source REGISTER at block 1101 after the
retention boundary. Blocks through 1108 provide the existing depth/work
policy confirmation; a cold store reopen must reproduce the same state.

This is a *test to run*, not an executed result in the present environment:
the container has no Rust compiler or external source operators. A pass would
establish the named local lifecycle continuity only, not the economic
hardness of the fixed Maintenance relation, independent signers, long-term
artifact availability, or real WAN safety. It leaves old serialized
statements, consensus profiles and production activation untouched.

Run manually on a Rust-enabled controlled checkout:

    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib long_native_retention_safe_sole_slot_reopen_after_1100_maintenance_blocks -- --ignored --test-threads=1

## Executed Go–Python dynamic differential run

A new deterministic program `formal/pon-nakamoto-v1/daa_go_differential.py`
builds and runs the standalone Go source using a separate process on 128
individually selected full-width ASERT input tuples. All signed-range checks
are independently evaluated by the Python integer implementation. The local
run observed **111 identical full-width target values, 17 identical strict
ASERT_RESEARCH_RANGE refusals, zero mismatches**. Its SHA-256 commitment
over case-indexed outcomes is
`46c785d0954adf4ebc11b446768b4ab724b1e6892ffde9b2525121f21a62e132`.

Exact command from repository root:

    python3 formal/pon-nakamoto-v1/daa_go_differential.py --output NEW_NONEXISTENT_REPORT.json

The script does not execute Rust, authenticate PoN anchors or accept W1 blocks.
Passing two or three implementations from the same development effort remains
distinct from an independent protocol-security review.



## Native branch-specific ASERT and read-only Q4 forecast

The original installed target remains determined exclusively by legacy M02
arithmetic. The new native selector
shadow_asert_distinguishes_two_real_w1_forks_and_survives_cold_reopen creates
two real W1 branches sharing their first 15 blocks. Height 16..23 headers
have valid but distinct timestamps four seconds apart, and a height-24 packet
makes the second branch strictly heavier. Shadow ASERT distinguishes the
different validated parent timestamps without modifying either installed
expected target; both historical branches are checked again on cold reopen.

The additional native revision12 test
q4_presigned_overlap_survives_revocable_branch_and_maintenance_reorg signs
one Q4 tag22 successor and one matching source statement with public dev keys.
Identical raw signed bytes are admitted at distinct valid heights of two
competing real Maintenance W1 branches. It checks source sequence rollback,
heavy-fork replacement, new lease eligibility, zero useful-output credit,
and cold-state recovery. It neither re-signs automatically nor changes Q4
or revision12 historical byte semantics.

The public, read-only forecast_q4_renewal_window API receives old/new
canonical lease values, a prospective inclusion height and bounded assumed
queue-delay/margin. It reports timing advice only: AwaitSignedWindow, WindowOpenByTime,
AtRisk or Expired. It does not verify dual signatures, attest availability,
guarantee inclusion, read an authoritative Node generation or issue an
execution capability. The original owner must re-read every real parent,
verify rights and signatures, and submit the original signed tag22.
Malformed context, revision, source and window fail closed. Forecasts cannot
resurrect a revoked task or trigger an implicit Maintenance fallback.

Independent Go-Python subprocess arithmetic on the local research host was
expanded from 128 to 512 seeded cases: 444 exact matching numeric targets,
68 matching strict range refusals and zero mismatches. The locally executed
case-indexed JSON SHA-256 digest is
8f5f228087a17925956b61be1abb3bd0eecb6d60346ef613c7cffa3f7f098b18.
This is numeric research, not an independent security institution, native W1
execution or a source-complete rust/whole-network qualification. The local
Python oracle text is not byte-identical to the latest GitHub blob, so this
new expanded cohort is not labeled exact-head native source evidence.

Rust-only selectors to execute on a clean, compiler-enabled checkout:

    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test daa_adversarial_schedule shadow_asert_distinguishes_two_real_w1_forks_and_survives_cold_reopen -- --test-threads=1
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib q4_presigned_overlap_survives_revocable_branch_and_maintenance_reorg -- --test-threads=1
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib q4_renewal_window_is_advisory_and_never_resurrects_expired_source -- --test-threads=1

Those new Rust selectors remain NOT_RUN on this Go/Python-only host. P0-A/B
and P1-C therefore remain awaiting native evidence. Cheapest eligible W1 work
cost, public hostile-proof admission, independent operators, physical custody,
source/material liveness and P2 WAN acceptance remain separate open blockers.


## Joint Lease × DAA adversarial screening (synthetic, non-activated)

An additional bounded experiment lives in
[lease_daa_fault_matrix.py](../../../../formal/pon-nakamoto-v1/lease_daa_fault_matrix.py),
with independent negative controls in
[test_lease_daa_fault_matrix.py](../../../../formal/pon-nakamoto-v1/test_lease_daa_fault_matrix.py).
It *does not* implement or select an alternate consensus profile and cannot be
counted as a valid W1 packet, independent operator, source authorization or
accepted public-network claim.

This research combines three DAA algorithms (original 16-block, raw parent
ASERT and parent-MTP11 ASERT) with four **exogenously assumed** work-capacity
conditions (steady, abrupt drop, alternating hashrate and all outside leases
lapsed). For each scenario it compares honest timestamps, endpoint-push and
MTP-floor timestamps under the same seeded synthetic Poisson mining process.
All constructed timestamps must satisfy the existing MTP11/future-skew
predicate. The resulting target feeds back into subsequent simulated block
waiting time; cumulative *expected required work* is recorded separately
from observed height.

The attacker share is a conditional effective-work model, not an observed W1
advantage, and can be changed in the bounded configuration. Full-Maintenance
participation **is not assumed**: the lease-loss scenario explicitly assumes
only 40% of nominal mining capacity elects the existing genesis Maintenance
work after height 64. No signed task silently switches to that source; no
source signer, lease or material is fabricated. If all real miners leave, no
PoW DAA can manufacture a block or claim liveness.

The default frozen development screen uses seeds [0,1,20261025], 192 heights,
three algorithms, four capacity scenarios and three timestamp strategies:
108 deterministic run records. The local Go/Python-only development container
ran 7/7 new Python negative controls and the retained 14/14 research controls (21/21 total).
The case-indexed JSON digest over the 108 runs (no native W1 proofs) is:

    a914a8e593b3447293687b0db28813044914564ef9f4407f64b7e856d1a6090a

Generate a new evidence file without overwriting previous research:

    cd formal/pon-nakamoto-v1
    python3 -m unittest -v test_daa_lease_research.py test_lease_daa_fault_matrix.py
    python3 lease_daa_fault_matrix.py --output /absolute/new/fault-screen.json

The simulation is **not a calibrated selfish-mining game, real clock or
propagation model**. It does not connect a native Node, source operator, real
W1 producer or independent public verifier. Measured effective-work fractions,
real hardware costs, native full W1 fork tests, source-owner leases, negative
cost asymmetry and WAN chain-quality experiments remain the blocking P0-C,
P1-B, P1-C and P2 exits. The retained P0-A/P0-B Rust selectors still require
a current-source compiler-enabled native execution receipt.


## All-32-slot post-retention real-W1 native selector (opt-in, NOT_RUN)

The original native continuity_tests.rs owner now has an additional expensive,
explicitly ignored regression:
long_native_all_32_retained_slots_reopen_only_after_retention_boundary.

Unlike the earlier 32-slot short test or single-slot 1108-block test, this
selector opens 31 additional real QDL2 slots alongside the original bootstrap,
revokes all 32 using signed transactions, then executes normal Genesis
Maintenance W1 blocks through height 1100. It demands that the last retained
slot refuse an otherwise valid signed reopening at **height 1101** with no
requester nonce or State mutation, and only after that original retention
boundary opens all 32 new generations in a normal height-1102 Maintenance
block. The test advances through height 1110, demands depth/work transaction
confirmation, and cold-reopens the original SQLite Node.

    cargo test --locked --manifest-path trillionnium/Cargo.toml \
      -p trnm-pon-node --lib \
      long_native_all_32_retained_slots_reopen_only_after_retention_boundary \
      -- --ignored --test-threads=1

This is an additional test **definition only**. No installed Rust compiler,
actual test run, full state/archive growth measurement, independent signer or
public source credential is claimed by writing it. It must fail visibly if
the included terminal-retention rule or nonce accounting diverges, rather than
changing or silently replacing the old Q4/Revision12 agreement rules.

## Branch-pinned DAA observer continuation (2026-10-25)

Added a separate non-activated M02 observer named daa_branch_research.
It walks at most 4096 actual native packet ancestors and requires the
recomputed packet ID, exact network/parameters, strictly descending heights,
and a pinned genesis-adjacent anchor (height 1, block ID, target, genesis
parent). It applies either raw-parent or MTP11 time to the isolated ASERT
integer oracle without changing native expected_target or branch work.

The actual native test isolated_asert_context_rejects_wrong_anchor_and_uses_real_w1_branch_history
supplies packet IDs from Node::packet and Packet::id after real W1 admission.
It tests context substitution, malformed ancestry, absent anchor, overflow
of bounded history reads, unchanged legacy difficulty, and cold reopening.
The independent Python reference test has six negative/positive groups.
The short-history MTP control explicitly uses candidate height 2: with just
genesis and its first child, the upper median equals raw parent time.
For candidate height 3, MTP already differs from the raw clock; the previous
height-3 equality assertion was corrected before this source was promoted.

Limits: the public research observer's genesis_timestamp is caller-supplied
and not authenticated by the function. All trusted context, proof validation
and snapshot integrity remain the invoking Node's responsibility. This is
not a live consensus variant, a complete branch-index implementation,
reorg-safe activation, W1 hardness proof, or public confirmation result.
P1-C and every independent-operator acceptance remain open.

### Native Packet-bound shadow input hardening

The first research helper accepted a caller-supplied pair of claimed packet ID
and Header. Those two fields are independently mutable and are not a
cryptographic pair. The current helper now requires a complete stored Packet
and recomputes Packet::id internally before reading its Header. Negative
cases mutate actual proof bytes and Header.height; both must fail the exact
parent lookup without changing consensus or durable state.

The complete W1 relation is still verified by the original Node admission
owner, not by this ancestry observer. The independent Python model assumes
an already authenticated header mapping and therefore cannot establish
that native Packet identity binding passed on the current Rust source.
Exact-source native execution and all P1-C/P2 qualification remain OPEN.

## P1-B bounded fork / outage screening continuation

The standalone, non-activated research files
`formal/pon-nakamoto-v1/daa_fork_outage_research.py` and
`test_daa_fork_outage_research.py` add a branch-local Poisson-clock
fork competition to the existing scalar/timestamp research. This is not
an additional consensus implementation. Every discovered block is a
simulated opportunity, not a PNW1 witness; synthetic integer IDs do not
authenticate packets, source signatures, leases or account state.

The campaign preregisters 3 seeds, the three existing algorithm labels,
4 ASERT half-lives, and 2 timestamp policies (72 rows). It executes
24 shared-block opportunities, 64 partitioned opportunities, a
deterministic publication/heal at which the higher cumulative required
work wins, and 24 followup opportunities. After 40 simulated discovered
blocks, independently assumed miner participation changes from leased
work to explicit genesis-maintenance participation (35% of group A,
80% of group B). These numbers are **assumptions**, not sampled
real-worker shares or empirical W1 costs.

For each simulated candidate, target is recomputed from the actual
research parent branch. MTP11/future-window validity and accumulated
`floor(2^256/(target+1))` are checked again for all retained fork
headers; miner identity, chain height or claimed model utility cannot
override the heavier-work result. It reports overwritten blocks,
depth-six historical exposure, branch work, timestamp rejection and
outage liveness separately. Depth-six historical exposure does **not**
test the original policy's required-work threshold or signed business
membership, and must never be called an actual double-spend success.

A closed no-maintenance control drops both groups' assumed mining
capacity to zero when tasks expire and reports
`no_assumed_work_capacity`. A positive maintenance-capacity control
continues generating synthetic blocks. Neither proves W1 solvability,
cheapest legal computation cost, honest miner availability, peer
independence or public network liveness.

Local development results before commit: **9/9 Python unit tests
passed**, with 72 deterministic campaign rows and canonical rows SHA256
`097603b784410de74635d1689cfa533389bc2a5dea94279f04507ded917b34a2`.
This does not assert exact-GitHub-tree verification or native test
execution. The repository must retain current native W1 proof,
Q4/Maintenance, branch/undo and confirmed-transaction tests as separate
non-synthetic requirements.

Independent reproduction from `formal/pon-nakamoto-v1`:

```sh
python3 -m unittest -v test_daa_fork_outage_research.py
python3 daa_fork_outage_research.py --output /new/absolute/path/fork-outage.json
```

The output is create-only. A second write to the same path must fail,
rather than overwrite evidence. The fixed cohort does not optimize the
DAA, establish real attacker work fractions or activate ASERT. P0-C,
P1-C and P2 remain independently blocked; P1-B still requires
real-W1 authenticated forks, independently administered partition/heal
and withholding economics under frozen deployment assumptions.

## P0-C Go arithmetic, genuine W1 transcript, and same-target negative cost probe

A separate, experimental Go verifier at
`formal/pon-nakamoto-v1/work_go_probe.go` independently implements the
entire W1 64×64 matrix transcript, corrected AB output, canonical PNW1
certificate and ticket verification. The Python test
`test_w1_go_research.py` independently regenerates proofs for four public
matrix structures and seeds 0/1/9 and requires bit-for-bit digest
agreement for both one full proof and the first successful same-target
challenge search. Go itself checks canonical 49,188-byte length, direct
AB, transcript/product/task/length tampering and rejects a cheap forged
ticket after full verification; `Precheck` is never VerifiedWork.

The producer and forged-ticket negative use the **same target**
`7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`.
The honest producer recomputes one complete W1 attempt per fresh synthetic
challenge until winning, recording all failed attempts and their total
wall time; the false producer searches only claimed transcript digests,
never supplying a valid W1 relation. Both remain non-consensus probes:
challenges are local research hashes rather than real serialized block
headers, public task leases or miner identity contexts.

An actual local Go execution observed **4 passing Python test functions**
(including 12 signed-independent-bytes *arithmetical* comparison cases,
not independent participants) and **128 wall-clock cost samples**
(32 seeds for dense, zero, sparse and rank-one). The exact raw local
receipt, source/binary hash identities, limitations and reproduction
instructions are preserved in
`evidence/pon-w1-go-same-target-local-20261025/README.md` and its
`raw_32_per_shape.json`. The median full forged-rejection versus cheap
fake producer wall-time ratio was approximately 43–44 in this
development environment. A legal-winning producer's complete search was
measured separately; neither figure is an attacker's optimal cost
or an expected mainnet resource ratio.

The executed Go process is not the native Rust verifier. No GPU/ASIC,
worst-case honest/full-node ingress, Sybil attack, independent hardware
or operator qualification occurred. P0-C remains OPEN. This evidence
does not change W1, consensus revision, reward, task permissions, old
DAA, production flags or the source-sensitive historic evidence package.

## P0-C: full-W1 valid-producer output reuse across challenges (non-activated)

The additive Go selector `formal/pon-nakamoto-v1/work_go_reuse_test.go` examines
an independently selectable, fully legal producer optimization for the already
published `pon-matmul-transcript-64-v1` relation: when an eligible source fixes
A and B, the exact useful C=A*B can be computed **once** and reused across fresh
header challenges. Every new challenge still recomputes the four SHA256-derived
noise factors, the two noisy matrices, all prescribed per-tile accumulations and
the complete challenge-bound transcript hash. The proof remains the original
49,188-byte PNW1 statement. This is not a stored-ticket replay or free mining.

Run (requires Go, within `formal/pon-nakamoto-v1`):

```sh
GO111MODULE=off go test -count=1 -v work_go_probe.go work_go_reuse_test.go
GO111MODULE=off go test -run '^$' -bench '^BenchmarkW1Maintenance' -benchtime=40x work_go_probe.go work_go_reuse_test.go
```

The test compares full **bit-identical** proofs with the original Go producer for
12 public structure/seed cases and the exact Revision12 genesis Maintenance
matrix (52 distinct fresh challenge proofs), and validates actual W1 work at a
nonwinning-independent maximal threshold. It separately searches the SAME
half-range target with the generic and precomputed producers for five input
classes, comparing every loser and full verified winner. Negative controls
check stale challenge replay, changed input after task preparation, mutated
cached output, wrong TaskId, noncanonical fields and malformed sizes. The
amortization observations use identical challenge streams and horizon
1/4/16/64. The cached inclusive interval counts the one preparation; the
per-proof benchmark deliberately excludes setup and therefore must NOT be
reported as an all-in full search or fastest valid work cost.

**Local development evidence, 2026-10-25:** Go 1.23.2 on Linux ran all four
new named selectors against a locally reconstructed mathematical Go stand-in;
52 positive complete proofs, same-threshold winner tests, negative controls and
four bounded time horizons passed. The independently committed test blob is
`1cd5a2b441d0e07a2de4e6e92adc523bf4d82ee8`, matching the locally
executed additive test source exactly. The original checked-in
`work_go_probe.go` source was *not* available to the local compiler because the
container cannot download the repository, so these results are **not** an
exact-source test of the combined GitHub Go pair or a native Rust test. The
original W1 reference remains unchanged; the local stand-in was not checked in.
No timing from this development probe is a GPU/ASIC/minimum attacker-cost bound.

This new legitimate production strategy demonstrates why P0-C must compare
complete setup and amortized winning costs for an adaptive legal producer, not
only a generic prover against a cheap *invalid* ticket. It does not establish
that cached AB is the best possible producer. P0-C is still OPEN, as are P1-B,
P1-C and P2. No signed task, original Q4 bytes, Revision12 Maintenance rule,
DAA, lottery, admission priority, fork choice or activation bit is modified.

## P0-B: future-signed-window queue-risk priority (advisory only)

The original `forecast_q4_renewal_window` could return `AwaitSignedWindow`
for a legally pre-signed successor that starts so late that its old-lease
inclusion slack is already smaller than the operator-declared queue lag plus
safety margin. The phase looked merely pending, although the conservative
height budget was already exhausted. Now `Expired` retains highest priority,
`AtRisk` precedes `AwaitSignedWindow`, and the original `WindowOpenByTime`
classification remains only when the timing budget fits. Existing zero-lag
and height-100 final-boundary behavior are preserved. The negative control
fixes old expiry 100, successor start 95, observed height 50, lag 10, margin
10: earliest possible 95, slack 5, phase `AtRisk`, not a safe wait.

This returns only a time/risk **forecast**, never a signed Q4 source statement,
lease renewal, reserved block height, storage assurance, proof admission or
success token. Reorg, missing material, revocation, signature or signer absence
must still be rechecked against the original Node owners. Exact-head native
execution and WAN queue-lag measurement are still missing; P0-B remains OPEN.

## P0-C × P1-B: legal-prover cost × source-loss fork sensitivity

The additive, unactivated research files
`formal/pon-nakamoto-v1/daa_legal_cost_sensitivity.py` and
`test_daa_legal_cost_sensitivity.py` extend the existing fork-local
`ForkSimulator`, without rewriting the frozen original 72-case research
campaign. A single measured-or-hypothetical multiplier changes ONLY miner B's
Poisson rate of producing a complete *valid* work ticket. Required work for an
accepted header remains exactly `floor(2^256/(target+1))`; there is no score,
lease, identity, proof or model-quality chainwork multiplier. The study combines
legitimate prover cost advantage with independently selected task-outage
capacity and real branch-local DAA arithmetic in the synthetic model.

Frozen sensitivity dimensions: 3 seeds × 3 unchanged DAA choices × 2 B
timestamp policies × 4 legal-production speed factors (1, 1.5, 3, 8) = 72
finite cases. `speed=1` must produce the **entire unchanged base simulation
report** for the same seed; speed>1 may change which hypothetical miner wins
without changing the per-header required work. The original documented
`task_outage_at` remains an exogenous assumption, not an authorized lease
revocation. If both miners have zero available work, even an arbitrarily
faster legal miner cannot create a simulated block. Identity, rate, bounds,
NaN/Infinity, zero, time, and false-authority negative controls fail closed.

Run from `formal/pon-nakamoto-v1`:

```sh
python3 -m unittest -v test_daa_legal_cost_sensitivity.py
python3 daa_legal_cost_sensitivity.py --output /new/absolute/path/cost-sensitivity.json
```

The 72-row output is create-only, includes actual zero W1 proofs, zero real WAN
transmissions and zero independent operators, and exposes pre/post-outage
expected valid-ticket shares separately from realized finite-fork results. A
conditional output like 30% ordinary resource share becoming 56.25% after a
3× legitimate prover cost advantage is an *assumption sensitivity*, never a
measurement or a common-prefix theorem. It cannot qualify cheapest legal W1
production, source independence, real DAA economics or a new protocol revision.

**Executed local scope:** 6/6 Python tests and the 72-case campaign pass with
an explicitly reconstructed local version of the parent fork simulator and
its existing mathematical oracle. The new two Python files' exact Git blobs
match the locally executed source; the parent simulator was **not** fetched
as an executable checkout and this is not an exact complete-current-branch
Python run. No CI outcome is being used for closure. The full PR source pair,
real W1 valid-work/native fork source, full network service, independent
hardware and WAN tests remain open; P0-C, P1-B and P2 are not closed.

## P1-C activation-height branch anchor research — no consensus activation

The existing `daa_branch_context_oracle.py` is intentionally restricted to
a genesis-adjacent block-one anchor. A separate **non-activated** helper now
covers a future DAA transition at arbitrary, precommitted `activation_height`
without inventing an irreversible administrative block-hash checkpoint:

- `formal/pon-nakamoto-v1/daa_activation_branch_oracle.py` derives the ASERT
  anchor **target and parent time from the candidate branch's own previously
  verified ancestry**. The activation-height block keeps the old difficulty
  interpretation. Only its successor is eligible for the shadow new rule.
- A heavier valid fork crossing the activation height obtains its *own*
  branch-local anchor; a fork after that height shares the common anchor.
  A peer-supplied alternate anchor/nonce/height cannot select difficulty.
- For experimental MTP11-ASERT, calculate **both**
  `MTP11(candidate parent)` and `MTP11(anchor predecessor)` on their
  respective ancestor windows. MTP(current) minus raw(anchor predecessor)
  would bias a perfectly regular 10-second chain, so it is an explicit negative.
  The raw ASERT research arm continues to use raw timestamps on both ends.
- An immutable, already W1-verified/target-checked ancestry snapshot is an
  **assumption**, not something this Python helper authenticates. Context
  digests and a nonzero rule commitment are selectors, not signatures.
  The 4096-read bound refuses old anchors beyond its horizon rather than
  trusting an unauthenticated shortcut. A native authenticated ancestry index
  is still needed for unbounded long-lived operation.
- Reorg, missing/corrupt/cyclic ancestry, context substitution, short-genesis
  MTP windows, the exact first ASERT successor and 32-bit/64-bit numeric
  refusal boundaries are covered by
  `formal/pon-nakamoto-v1/test_daa_activation_branch.py`.
  The two newly committed Git blobs are `930808c28d9312d5505f6ddab761d2e438d7f9d6`
  (helper) and `b25abd50c9a41ecf727a953dd068be2b3a126d52` (tests).
  The existing upstream dependencies `daa_branch_context_oracle.py` and
  `daa_research_oracle.py` match the local exact Git blobs
  `cb33b0444d51b1a97bb409175c02a776f24c3131` and
  `5cce6222769f1ab2f968516f15fcdf330fb695bd`, respectively.

Local command from `formal/pon-nakamoto-v1`:

```sh
python3 -m unittest -v test_daa_activation_branch.py
```

**Actual observation**: 11/11 local Python tests pass against the exact
Git-blob-matched module and its exact two existing Python dependencies.
The tests' ancestry is an explicitly *synthetic assumed-validated mapping*;
no new Rust miner, native real W1 packets, signed lease, exact-head Cargo test,
production consensus revision, actual independent operator or 72-hour WAN
cohort was executed by this helper. The existing P1-C/P2 exit conditions
remain OPEN. Future protocol integration must commit its own signed context,
runtime activation rule, anti-rollback/reorg policy, persistent bounded
ancestry proofs and independent client confirmations, without changing any
historical revision.

## Executed, exact-source Go/Python arithmetic differential (2026-10-26)

A new **single local host** observation executed the original repository Go and
Python oracle blobs, and independently checked their Git blob identifiers
before running any arithmetic. The paired exact blob IDs at this observation:

- `formal/pon-nakamoto-v1/daa_reference_go/main.go`:
  `bf5142df7297a6f0dffa2d331785674061143c13`.
- `formal/pon-nakamoto-v1/daa_research_oracle.py`:
  `5cce6222769f1ab2f968516f15fcdf330fb695bd`.

The source-exact Go program compiled under Go 1.23.2 and produced its original
512-case fixed-input digest
`6be87e237c37aec8c50af8d4eaf9e14a0ca60e7dc69f18143ede1ef70c420c97`.
An additional local deterministically seeded 393-case process/Python differential
(`seed=20261026`) observed 147 exact matching 256-bit integer targets,
231 matched parameter refusals, 15 matched i128-range refusals and **zero
mismatches**. The local raw JSON evidence SHA-256 is
`7c43acf7e6f04ee0d677475348318b451e6e61de454f5ff54200cee5b172b84b`.
The raw 393-row file is supplied as a separate conversation artifact, not
committed to this repository; the checksum is provenance, not a hosted receipt.

**Scope is strictly scalar arithmetic** on one host with two languages authored
within this research lineage. None of these cases runs native Rust, produces
PNW1 valid work, admits a block, proves an independent validator, or qualifies
public-network difficulty/security. Local proof/admission tests and third-party
review remain explicit blockers. No legacy DAA or production flag changes.

## Q4 single-old-lease dispatch fencing (research continuation)

The Q4 lost-ACK research outbox refuses **two independently named dispatches
against the same immutable old lease**, even when signed transaction bytes and
operation identifiers differ. Preparing multiple un-dispatched proposals remains
allowed. The first durable `DISPATCH_UNKNOWN` fences the old lease; reorg, expiry,
unavailable observations or another child signature cannot replenish dispatch.
Distinct old leases remain independently dispatchable.

The fence is checked within one SQLite writer snapshot following a full-prefix
audit. Cold readback refuses a second, correctly rehashed `DISPATCH_UNKNOWN`
against the same old lease. Two competing SQLite writers cannot bypass it.
The research outbox does **not** verify real PNX1 signatures, reconcile external
effects, establish NotDispatched or grant a fresh submit authorization. Any
subsequent operation requires the original Hepta owner to resolve the original
effect identity, not rename it. No Q4 tag22 bytes, consensus revision, signer,
chain state, DAA, release or production authority is changed.

Research-only negative controls:
`python3 -m unittest -v test_q4_renewal_outbox_research.py` from
`formal/pon-nakamoto-v1`. P0-B/P2 strict acceptance remains OPEN.

### Cross-operation readback consistency

The same snapshot-backed `status()` now reports
`old_lease_dispatch_fenced`, computed across **all** original durable dispatch
events. `has_no_durable_dispatch_fence` is false for an un-dispatched alternate
operation whenever a distinct transaction has already fenced the same old lease.
A separate lease remains unfenced. These values are read-only diagnostics,
not authorization to send; only the original operation owner can decide
NotDispatched or reconcile an unknown external effect. Competing-writer and
cold-reopen controls test the exact cross-operation status.
### 2026-10-27 PN0/P0-A original native signed re-entry regression (source only)

The existing \`trnm-pon-node/tests/continuity_authenticated.rs\` now contains
\`maintenance_reentry_registers_signed_task_and_independent_client_confirms\`.
It uses the original Revision12 Genesis Maintenance for actual PNW1 blocks:
revokes the original only optional lease at height 1; carries an independently
signed new tag18 demand and tag21 source statement at height 2 (not a revoked
lease renewal); extends real Maintenance work through height 9; and checks
three actual signed transaction memberships against a separately reopened,
packet-replaying client, including the installed depth+required-work policy.
It requires the old task to remain ineligible, the new task to be eligible
from the next parent, equal checked native/reference state, and fresh cold
SQLite client readback. No production identity, W1/DAA byte, signature
domain, legacy rule or activation flag changes.

**Test execution on this exact source is NOT_RUN:** this local environment has
no Rust toolchain or full repository checkout. Source assertions do not make
independent administrators, real Hepta request ownership, W1 work-cost
qualification or 72-hour WAN acceptance true. P0-A remains OPEN pending
a real native exit plus a separately administered client/operator campaign.
### Active-branch Q4 advisory hardening (2026-10-27)

The native M07 Node adds read-only `forecast_q4_renewal_from_active`
for original Q4/Revision12 contexts. It uses the checked current active
state/root, actual parent generation, actual source-verified eligible old
lease, checked next-height arithmetic, unchanged pre-existing Q4 forecast
constraints and a final active-generation comparison. It returns only the
tip, generation and timing advice, not a verified successor signature, source
grant, dispatch or network-inclusion permission. On a real Maintenance
revocation it must refuse the old source instead of emitting a misleading
green advisory for an untrusted caller-supplied obsolete Lease.
The native test extends the existing signed Maintenance re-entry selector.

The original bounded status query remains advisory and may immediately be
stale. No operation/outbox may treat it as a NotDispatched certificate.
Exact-source Rust compilation and real independent network acceptance are
NOT_RUN here. P0-B and P2 remain strictly OPEN.


### Actual new-task work following zero-lease maintenance reentry

The existing `maintenance_reentry_registers_signed_task_and_independent_client_confirms` development regression now extends its nine original Maintenance blocks with an actual signed `make_with_task` PNW1 candidate for the registered new source/task at height 10. Both real SQLite-backed nodes must verify and activate identical bytes/state, the new task's output meter must become one, and a fresh independent Node must replay all ten blocks and confirm the originally signed revoke/open/registration operations before cold reopen. This closes a previously missing *test-path step*, not work hardness, independent administrators, signed production key custody or public release qualification. No historical Revision12/Q4/DAA bytes or activation flags change.
