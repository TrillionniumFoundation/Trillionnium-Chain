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
