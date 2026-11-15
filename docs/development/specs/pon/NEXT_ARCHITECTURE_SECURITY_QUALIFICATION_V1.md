# Trillionnium-Chain Next Architecture & Security Qualification

Program ID: `trnm-next-architecture-security-qualification`.
Started 2026-11-07 America/New_York; execution records use UTC.
Status: development in progress, **HOLD_NO_GO**.

This is the six-stream execution and qualification contract for the program
requested by the owner. The [existing development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
remains the sole plan and the existing integration candidate remains its source
lineage. The [program registry](../../../../config/pon/next-architecture-security-v1.json)
records work allocation; it is not a second consensus, release or activation owner.

## Objective and responsibility boundaries

The target is infrastructure through which independent Hepta nodes create,
evaluate, preserve, distribute and evolve neural capabilities. A consensus
receipt, a content hash, a model evaluation and permission to execute an external
effect answer different questions. Each must remain bound to its original owner.

| Plane | Existing owners | Required boundary |
| --- | --- | --- |
| Ordering and work | M01/M02, fully validated native Node | Only the selected, qualified work rule may determine chain weight; cached useful output, quality and price are not fresh work by declaration. |
| Durable state and recovery | M07/M08, original SQLite and operation journals | Querying evidence must not silently recover or activate a branch. Local effect/revocation history must survive chain reorganization. |
| Cell bytes | M04/M09 and existing Cell/TCR1 owners | External content IDs and peer discovery locate bytes. They cannot choose a release, install weights or grant FinalUse. |
| Learning and use | Learning Artifact Owner, Evaluation Owner, kernel.operations, Runtime FinalUse | A complete candidate, frozen evaluation, original operation, installed-parent readback and future use must agree. Rejected or no-update outcomes remain valid outcomes. |
| Payment and service | M12 funding/settlement and measured resource owners | Distinguish internal redistribution, protocol subsidy and independent external revenue. Failed work and storage/repair liabilities remain charged. |

The audited implementation base is `b5c655ebe9611b3d62cf739e61e6867decc053e3`
on the existing integration lineage. Its M00–M17 registry already records native
components for all 18 modules, including M02/M07/M08/M14. All 18 still record
`native_product_integrated=false` and `independent_accepted=false`. The
`runtime_implemented=false` top-level field means the complete qualified runtime
is unestablished; it does not mean these Rust components are absent.

## Six parallel streams and concrete next exits

| Stream | Current implementation in this program | Next required evidence |
| --- | --- | --- |
| Consensus Research | [Exact finite candidate-weight and sampling counterexamples](NEXT_CONSENSUS_PQ_RESEARCH_V1.md), with separate mathematical and physical-resource verdicts. Existing PoN remains unchanged. | Compare pure PoN and explicit hybrid candidates against every registered legal preparation/cache/delegation strategy. Freeze timed-resource units, admission, DAA and network assumptions before seeking a security reduction. |
| Native Runtime | [Repair the real `packet-status` opening path](NATIVE_PACKET_STATUS_OBSERVATION_V1.md) so a status read cannot activate an admitted packet. Use existing bounded readback and original namespace ownership. | Native Legacy/authenticated-state cases, dirty-recovery refusal, writer contention, unchanged source bytes and ordinary writer recovery, then the original complete service campaigns. |
| P2P Cell Commons | [Restricted BEP52/BTMH/CBP1 adapter](CELL_BEP52_BINDING_V1.md) and [fixed RS(6,4) chunk recovery](CELL_RS46_CHUNK_V1.md) over the existing TCM1 manifest/cache. Canonical descriptors, piece layers, internal context pins and original chunk hashes remain authoritative. | Wire reviewed discovery and erasure placement to bounded existing reservations/deadlines; test actual interoperable swarm, independent custody, repair and 72-hour PN5 campaign. |
| Hepta Integration | [Map actual receiver and owner interfaces](NEXT_HEPTA_OWNER_BINDINGS_V1.md), retain fresh artifact/PQ/accepted-task checks, and repair observation/recovery separation on the Chain boundary. | Freeze the paired consumer version and complete three real Learning Artifact → independent Evaluation → original kernel.operations → installed-parent readback → Runtime FinalUse cycles, including no-update, revocation, cancellation, restart and reorg. A Chain-only patch cannot certify those other owners. |
| PQ Security | Keep RISC0 join-v2 and Plonky3 W1 as different proof profiles. Preserve the 15 RISC0 obligations and expose the sampling-law counterexample without claiming an FRI attack. | Complete each profile's relation/compiler, PCS extraction, joint hash/Fiat–Shamir model, recursive composition and lifetime quantum-query accounting. No component security estimate becomes PQ128. |
| Performance & Economics | Native offline Cell adapter observation program, plus [strict campaign arithmetic](../../../../formal/next-architecture-security/performance_economics.py) that retains failures and missing costs. | Same-source, same-resource full campaigns for confirmation goodput, verification/rejection, complete model retrieval/device load, CPU/GPU/RSS/VRAM, bandwidth, byte-time storage and independently funded net revenue. |

All six can develop concurrently. Public activation still requires the existing
PN0–PN6 ordering. A completed microbenchmark, source check or symbolic counterexample
does not satisfy a predecessor's physical-service or cryptographic exit.

## Source-aware continuation, not retroactive qualification

The current W1 proof work in [PR #783](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/783)
already contains complete native AIR/STARK observations. Therefore the program
does not carry forward the obsolete claim that no complete backend exists.
Its actual end-to-end benefit, malicious rejection bound and complete NIZK/PQ
proof remain separate obligations. The research specification records the exact
observed profile rather than copying RISC0 recursion parameters into Plonky3.

[PR #778](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/778)
owns the RISC0 QROM mapping. [PR #782](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/782)
owns costly W1 task/runtime evidence, and [PR #785](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/785)
continues native query/current-funded-task evidence. Their existence and past
measurements are not claims that this program has merged, rerun or qualified all
of them. Future composition must retain each exact source, failed attempt,
original deadline and parent/operation identity.

The current packet observation wire is `pon-native-exact-packet-observation-v3`
with an optional `accepted_task` object whose nested `schema_version` is 1.
The later schema-4 requirement in the existing Hepta handoff document is not
implemented by relabeling this output. The paired external consumer version
and missing/unknown-field refusals must be frozen and tested before cross-owner
qualification. Only the local `packet-status` paths specified in this increment
gain the cold read-only opener; evaluation observation CLIs retain their
documented ordinary owner-open/recovery semantics.

## Performance and economics observation contract

The new reader accepts exactly one explicitly declared campaign with one
observer's monotonic clock. Every planned operation must have one outcome row,
including `not_started`, `unknown`, `timeout`, `cancelled` and `rejected`.
Missing or duplicate rows refuse the report. Separate metric groups are:

- `consensus_confirmation`, measured in `confirmed_transactions`: externally authenticated finality must be established
  by the native owner before interpreting successful units as real confirmations.
- `work_verification`, measured in `verified_statements`: valid and hostile work share the original denominator;
  the largest observed rejection remains a sample, never a universal bound.
- `cell_retrieval`, measured in `verified_payload_bytes`: complete validated byte availability, distinct from device load.
- `device_load`, measured in `execution_ready_models`: installation and execution-ready model state, distinct from download.

Each planned operation declares the fixed unit for its kind. Mixing Cell counts
with byte counts, or verified statements with transaction counts, is refused.

Deadlines use offsets from that same observer's start. A late success remains in
the cost and latency history but contributes no on-time goodput. CPU/GPU time,
ingress/egress bytes and storage byte-time are additive only within the supplied
nonoverlapping operation accounting. Any missing meter makes that total unknown.
Reported RSS/VRAM values are the maximum observed per-operation peaks, not the
simultaneous whole-system peak. Cross-host clocks and overlapping parent/child
meters need original-owner reconciliation before they can enter this format.

Finite successful-only latency order statistics always carry their sample count;
p50 is explicitly the nearest-rank order statistic, not the average of two
central observations in an even sample;
p95 is absent below 20 samples, p99 below 100. Even above those thresholds they
are empirical order statistics, not confidence bounds, independence evidence or
unconditional tail guarantees. Failures and censored attempts remain separately
visible in the complete denominator.

Every settlement binds a unique receipt identity and a planned operation. Mixed
unconverted monetary units, receipt replay and negative or noninteger amounts
are refused. The conditional external net is computed as:

\[
R_{\mathrm{external}}-R_{\mathrm{refund}}-C_{\mathrm{all\ outcomes}}.
\]

Protocol subsidies and internal transfers are reported separately and never
counted as external revenue. Unknown costs or refund/revenue amounts make this
net unknown. Observed-to-date cost and cashflow are separate from completed
declared-lifecycle cost and net. Any operation whose process/resource lifecycle
is not terminal makes the latter two unknown, even if a timeout returned or the
currently observed cashflow is positive. Future obligations are not certified.
Complete declared rows do not establish global coverage, truthful
meters, authentic settlement, independent customers or sustainable demand. The
reader explicitly leaves each of those qualifications false and always returns
`HOLD_NO_GO`; it is an arithmetic tool for reviewable measurements.

The BEP52 Cell example uses five deterministic synthetic payload sizes and three
repetitions each. It retains each chunk's valid/corrupt check, descriptor/proof
cost and complete cached verification. It measures local wall time only. Input
generation, cache opening, CPU, RSS, WAN, tensors, VRAM, energy and revenue are
not measured; no end-to-end model-load or economics claim follows. The RS46
example uses four size/chunk configurations with three repetitions each. It
omits two data shards, reconstructs each chunk from shards 2,3,4,5, writes a
separate destination cache, verifies the complete original TCM1 payload and
materializes byte-identical output. Its twelve local observations retain
encoding, wire roundtrip, recovery and corrupt-input refusal costs. Both
examples are finite synthetic observations, not full-service campaigns.

## Original acceptance conditions are preserved

The original Host contract remains 0.25 CPU, 2 GiB RAM, zero swap, 256 PIDs,
four seconds and sixteen hostile workers. Three complete 0/24/24 campaigns,
complete History, capacity/churn and independent WAN evidence remain their own
exits. The required root-owned cgroup and the original experiment's process
ownership cannot be replaced by a faster unconstrained development machine.

PN5 retains at least three independently administered failure domains and the
preregistered at-least-72-hour WAN experiment. No script can manufacture those
administrators or elapsed time. Storage replication and a DHT advertisement are
not independent custody, permanent availability or economic sustainability.

Research and fixes are published as a reviewable continuation. No deployed data,
keys, services, protected branch policy, current work rule or production switch
is changed by this program's registry, tests or report.
