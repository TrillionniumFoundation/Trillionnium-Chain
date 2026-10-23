# Native development node, bounded confirmation and empirical model claims

Measured implementation: `b34561d1ade376512a34fed3fd78938ed2431ecd`; tree `5a91b1ecc696b8a0c468ee8ba2a3dd0fe9e8d3d8`.
Recovered native composition/confirmation parent: `74bc8b0a61d5a38dd46e74388436bd71117ef9cf` remains in the same lineage and in its untouched qualification checkout.
Canonical PR #204 / `fix/chain-pon-contract-authority-20260929`; no parallel node candidate.
Native binary SHA256: `903ce1cabb510fbde70ca21cd15a49be88f012ae021f5ef7f8d99bfe5691d7ff`.

## Delivered behavior and unchanged authority

The M15 `trnm-pon-node` composes the existing codecs, strict work verifier and twelve-
command execution engine with native M02 target/work arithmetic and a native M07/M08
SQLite branch/delta/recovery owner. Ordinary development commands mine, submit, recover,
export, synchronize and confirm. Python remains a separate conformance oracle, not the
binary's runtime or fallback. The native namespace is fresh and separate from the
reference/session namespace; no deployed database is migrated in place.

The continuation adds 1..256 distinct-query native batches to the ordinary CLI and
loopback socket. Membership is verified per requested body, ancestry/current clock once
per batch, and all results share one generation. Cancellation, future ancestors, missing
memberships and reorg return no partial successful batch. Duplicate work admission cannot
reuse an old caller clock. Read traversal is cooperatively interruptible; not every
SQLite call, root computation, admission or reorg step is preemptible.

The work producer's explicit fixed-task preprocessing retains the same exact challenged
transcript/proof. Two target levels and four task structures are measured with setup
included. A faster implemented producer falsifies treating one honest implementation
as the fastest-adversary cost bound; it does not qualify a public work profile.

The existing model worker emits reduced rational fixed-dataset/control/marginal values
and a checkable empirical accuracy upper bound of 1. Zero gap means only optimum for
that fixed labelled accuracy objective, NOT general circuit, future-task or minimum-cost
optimality. Settlement recomputes the claim and compares canonical bytes in both report
copies; changed bounds, fabricated authority and Boolean aliases reject.


## Admission concurrency and native historical access

The native socket Submit path drops the only durable-owner mutex before full work
verification, then reacquires it and rechecks packet context/clock before state and
commit. Opaque checked packets cannot become changed-header or stale-clock authority.
Six deterministic counterexamples cover a read during work, cancellation after actual
verification, exact duplicates, wrong destination/clock, cancellable owner waiting and
an intervening heavier branch. This is not public Sybil or sustained-service acceptance.

Native metadata reads no longer materialize packet BLOBs. Ancestry time/target checks
read block-ID-bound header/trace projections; requested transaction bodies still check
roots and membership. Projection width is not a measured SQLite disk-I/O claim. A real
12-block, 3,072-signed-transaction test validates multipage socket history in a separate
native store and after reopen. Header/trace/body mutations retain rejection tests.

Actual signed Python/native evaluation permutations reproduce the revision3 first-pair
score difference (10 or 100), including third-attestation rejection. Exact artifact
copy across authors rejects; functional copies/splits and an order-independent successor
remain unimplemented. Neither a passing counterexample test nor unchanged consensus
bytes means that the economic vulnerability was repaired.

## Clean-source runtime receipt

`qualification.json`, `logs/` and the original **`runtime-manifest.json`** are the
collector's unchanged outputs. The enclosing `manifest.json` additionally inventories
this publication and separately executed supplementary collections without repinning the source.
Rust 1.95.0, locked/offline Cargo, two compiler jobs, one native harness thread and disk
SQLite were used; exact commands, filesystem/environment, raw logs and binaries are bound.

- Full workspace: **1842 native tests** and **15 documentation tests** passed.
- Native node: **22 distinct integration cases**, also contained in the workspace run;
  repeated invocations are not extra distinct cases. Thirteen actual exit-86 initialization/
  admission/reorg cuts are observed. Process exits are not physical power loss.
- Strict workspace Clippy and formatting, the existing Python/native/session matrices,
  historical evidence checks, paired session costs and genuine work/receiver pipeline
  are recorded separately. The two default-ignored entries are helpers: the native child
  is invoked by the crash tests, and the research helper is run explicitly.
- Actual loopback ingress rejects 32 distinct ticket-passing false transcripts while
  serving 16 four-query batches. This is bounded same-host mixed load, not a public attack
  rate, operator independence or a Sybil-fairness qualification.

The qualification's `model_experiments_rerun=false` describes that runtime collector.
The separately executed model supplement below is not concealed behind that flag and
does not retroactively modify historical E3 observations.

## Ordinary native CLI replay and query cost

`native-batch-replay/` retains its portable driver, exact input hashes, commands, stdout,
stderr and measured process intervals. It replays 44 retained work blocks through two
native stores per scenario (88 admission executions across the two scenarios) and checks
96 application confirmation targets. Repeating read queries three times in both modes
is NOT 576 new transactions or additional included work. Total actual CLI invocations:
**386**. Every single and batched result is compared exactly.

| Scenario | Retained paired samples | 48 separate CLI queries, median ms | One 48-query CLI batch, median ms |
|---|---:|---:|---:|
| independent | 3 | 2069.195 | 43.622 |
| hot-sender | 3 | 1711.850 | 35.356 |

Each batch checks the 22-block ancestry once and the distinct included bodies once.
These measurements include process startup, store reopening/recovery and query checking.
They demonstrate request amortization, not a pure executor speedup, WAN latency, p95/p99,
isolated-host capacity or public TPS. Other controlled qualification activity may share
the host. All slower samples remain. The clock is explicitly logical and blocks are not
wall-paced to ten seconds. `measurement-summary.json` is derived from the retained samples.

## Current model producer, not invented independent acceptance

`model-current/` executes the existing real local training, frozen integer evaluation,
settlement replay and three actual optimization attempts using the recorded public
repository source. Its driver takes explicit checkout/output/source arguments. Earlier producer trials on
74bc8b0a6 remain in the owned work directory as historical observations; they are not
counted as executions of this source, future experiments or improving generations.

The current candidate fails its preregistered statistical gate: **not adopted; reward 0**.
The three retrospective attempts do not establish independent chronological generations.
The exact actual claims, controls, datasets, calibration, model bytes, predictions, logs
and zero-reward result are retained. Public code routing is still a small model family;
no LLM-scale efficacy, ordinary Hepta request, private-data authority, paid provider call,
funded public GPU serving or independent evaluator is manufactured.

`check_native_node_supplements.py` replays the retained block work/signatures/state with
an independent implementation, reconstructs all native confirmation results, validates
query accounting, and recomputes the frozen model claims and zero-gain settlement.
Its mutation tests reject substituted work, Boolean success aliases, missing observations,
fabricated costs and public/independence flags. This is evidence consistency and actual
replay, not proof that one operator is independent of itself.

## Same-binary owned physical hosts

`owned-host-smoke/` retains 27 actual SSH/copy/native invocations on ROG, Pocket4
and X230 with identical binary and packet hashes. Each independently stored native
instance admits the signed golden block, reopens the same root, rejects duplicate
state advancement and checks transaction inclusion at depth zero. These are three
executions of one historical vector, not three new mined blocks, independent
operators, public P2P or wall-clock confirmation. No service was installed and only
new private temporary namespaces were used. The checker validates the raw outputs
and exact source/binary/vector; it does not reexecute the physical-host experiment.

## Preservation and open work

Historical v1/v3/v4/E3/client/session packages and their failures are unchanged. New costs
live in `work-cost/`; old costs are historical, never repinned to this binary. Initial
missing-cache preparation output remains in `failures/`. The separate earlier qualification checkout remains clean at its recorded commit.
The existing delivery branch was intentionally fast-forwarded through that commit
before the new implementation commit; no live services, keys or user databases were modified. Root README remains blank by the existing owner decision.

Still incomplete: fastest-adversary/work admission qualification; authenticated public
P2P and durable continuous mining/mempool scheduling; incremental persistent native state
and full bounded long-history service; revision3 first-two evaluation arrival economics,
public disputes and functional copy/split attribution; ordinary Hepta consent/effect and
resource ownership; independently administered future model benefit; funded long-term DA
and inference; physical power-loss and sustained public client-confirmed throughput.
These are both implementation and external-acceptance work, not all external blockers.

`runtime_implemented`, `work_profile_qualified`, `production_candidate`,
`production_consensus_activation`, `public_testnet_ready` and `release_ready` remain false.
The development binary is not a wallet, public testnet release or deterministic finality.
