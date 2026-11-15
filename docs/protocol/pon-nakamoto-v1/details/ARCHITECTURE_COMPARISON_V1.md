# Architecture comparison on the native business contract

Status: explicit research experiment; no protocol activation. The
[sole plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
retains `pon-nakamoto-v1`. This contract measures signed batch dissemination
through the current native application, work, storage and client-confirmation
owners. It does not restore PoCO-BFT or implement a Conflux, Bullshark or
Mysticeti consensus runtime.

## The frozen common contract

The callable experiment is
[`architecture_delivery_compare.rs`](../../../../trillionnium/crates/trnm-pon-node/tests/architecture_delivery_compare.rs).
Its source-bound execution owner is
[`architecture_compare.py`](../../../../formal/pon-nakamoto-v1/experiments/architecture_compare.py).
Neither creates an installed profile, public protocol command or readiness flag.

All three measured arms use the same network, parameters, genesis, public
development keys, signed transactions, native packet bytes, useful-work task,
parent-derived target, complete W1 verifier, application rules and SQLite writer.
There are four proposers, two rounds and four signed transfers per proposer per
round: 32 transactions in the first native block, followed by six actual native
blocks. The two workloads use either separate recipient accounts or one hot
recipient. Source nonces retain their actual native meaning.

Each arm reacquires every complete work proof on a fresh native producer before
starting its receivers. The seven byte streams must equal the frozen workload.
The measured acquisition includes actual losing target attempts, application
execution, state commitments and persistence. Preparing the signed workload
once remains an explicit separate acquisition scope. This is not the fastest
possible mining implementation or a work-cost lower bound.

Signed dissemination cells bind the native network and parameter context,
proposer, round, ordered parent references and exact body commitment under a
fresh research-only domain. All arms send the same cell bytes through real
framed loopback TCP, sync actual copies to disk and read them back. Frames have
a 64 KiB bound and one two-second absolute frame budget across connect, header,
body and acknowledgment. The eight-cell campaign shares a 15-second absolute
deadline. Every socket retry and final material readback observes that original
deadline; a failed sender/receiver cancels its peers and all threads are joined.
Cancellation is polled during read/write, while a pending connect may take its
remaining frame budget. Filesystem/kernel stalls are not preempted: an overrun
must be rejected after the operation returns, so this is a cooperative budget,
not a guarantee that the process returns within 15 seconds. An already durable
copy is not erased when its acknowledgment is refused. All cell metadata bytes
and storage remain in measured
cost; a digest is not treated as a free available body.

| Measured arm | Actual change | Retained consensus owner |
| --- | --- | --- |
| Serial signed batches | One sender serially delivers the eight cells and submits their native pool bundles | Full native PoN admission and independent client confirmation |
| Concurrent proposer batches | Four real proposer threads deliver cells and co-offer one native bundle per proposer per round | The same PoN rules, resource policy and single durable writer |
| Signed reference DAG | The same four threads send later vertices before their parents; the receiver resolves complete signed causal history before the same native bundle calls | The same PoN rules; the DAG adds no fork weight, vote, committee or finality |

After material checks, every arm uses the existing public V3 pool owner. Actual
native signature, nonce, capacity and application checks must queue all eight
bundles. The same seven native packets are then submitted through the existing
protected service. An independent local Node obtains their actual History pages,
fully validates them and checks all 32 transaction memberships. A success needs
both depth six and the installed required-work threshold; `finalized` and
`execution_authority` remain false. Local acknowledgment, stored cells, pool
admission, a passing work ticket and a server Head response do not substitute
for that confirmation.

The experiment cold-reopens the actual receiver and compares its state with
the independent client. Sender, relay, receiver, writer, client and cold reopen
costs enter the whole-trial process CPU observation. That interval includes all
trial threads and diagnostics through cold reopen; final report construction and
serialization and the separately measured source-workload preparation are outside
it. It is not allocated among actors or called a kernel measurement. Missing
platform clocks remain unknown. Service CPU partitions
retain their own existing scope, including their exclusions. Application frame
bytes are actual framed bytes; physical link bytes, power and per-actor energy
remain unmeasured.

The order is balanced cyclically over three samples per workload and arm.
Fresh stores prevent a previous arm's accepted-block cache from supplying free
verification. The output retains every pool call, block submission, History
response, native confirmation, error, resource measurement and failed target.
The reader refuses a finite success if any required native step is absent,
cost accounting is unknown or a later authority flag is promoted. A test-harness
exit zero alone cannot qualify the business target.

## What the measured DAG does and does not establish

The receiver authenticates complete cell material before storage, binds exact
body bytes and requires complete parent history before ordered use. Separate
negative controls reject a signed header with an unavailable body, a changed
signed parent list, an incomplete history and two authenticated values at the
same proposer/round slot. These controls exercise the experimental material
boundary; they are not a Byzantine consensus theorem.

There is one correctly administered local material store. Its response explicitly
means **stored, not confirmed**. It has no quorum certificate, independent replica
custody, committee admission or rotation, Byzantine node bound, global common
prefix proof, epoch recovery or distributed agreement on garbage collection.
The fully available local DAG has a deterministic order; agreement between
independently partitioned Byzantine views has not been implemented. The negative
controls run separately from the timed no-attacker trials. These trials do not
inherit the separate public hostile-service qualification campaign.

Measured burst completion rate uses 32 actually client-confirmed transactions
and full cold business latency. It is labeled a finite cold burst, never saturated
confirmed TPS. The small workload, loopback topology and known public development
keys do not describe a WAN, independent operators, arbitrary State size, long-run
retention or simultaneous public attack load. A slower arm, a failed call or a
missing body remains visible. No architecture winner is hard-coded.

## Comparability before a full successor

The external protocols below are primary-source references, not names assigned
to the local arms. Their source code, safety rules, cryptography, payload custody
and complete native business paths would need their own implementation and
measurements. Their reported paper throughput is not used as a measurement here.

| Architecture | Participation and security premise | What must be implemented before fair native comparison |
| --- | --- | --- |
| Current PoN Nakamoto | Qualified effective-work share, work/lottery relation, delay and validation assumptions; confirmations are probabilistic and their public risk is unqualified | Complete unchanged work, branch selection, reorganization, depth/work confirmation, payload availability and actual application cost |
| Bitcoin-NG family | Work-based key blocks elect an epoch leader; that leader signs transaction-carrying microblocks, with separate fork/incentive and confirmation assumptions | Key-block work and epoch transitions, current PQ leader signatures, microblock equivocation/censorship, complete payload replay, leader loss and reorganization; a signed microblock receipt is not the independent client's confirmation |
| Conflux Tree-Graph / GHAST | Permissionless computational competition with its own delay/work assumptions; adaptive weighted pivot selection and probabilistic confirmation | Parent/reference graph validation, adaptive weights, pivot/epoch total order, conflict execution, deep recovery, complete graph custody and a PoN-compatible work argument |
| Narwhal with Bullshark | A fixed authenticated committee with `n >= 3f+1`; reliable data dissemination plus a separately defined BFT ordering rule | Actual quorum-certified custody, author/round equivocation rules, leader support/commit/skip logic, synchrony model, membership/rotation, recovery and application execution |
| Mysticeti | Authenticated Byzantine committee assumptions; signed uncertified DAG vertices interpreted by its specific commit rule | Exact equivocation handling and commit/skip/support relationships, custody, membership, persistent recovery and the application-specific fast-path rules |
| Prism family | Permissionless work assumptions with separate proposing, voting and transaction-carrying roles | Separate work lotteries, vote chains, leader-order/confirmation rules, payload custody and their actual combined resource and proof costs |
| OHIE family | Parallel work chains with post-work chain assignment and a global confirmation frontier; variable mining power requires its specified pivot/work-coordinate construction | Complete all-chain parent commitments, post-work sortition, pivot-dependent target and nondecreasing referenced pivot work, partial-confirmation frontiers for every chain, strict rank-below-frontier ordering, recovery and native transaction execution |
| GHOSTDAG family | A greedy blue-set rule retains a k-cluster and derives an order from a complete block DAG under specified mining/delay assumptions | Exact selected-parent and anticone rules, complete past availability, all-block deterministic ordering, work/difficulty semantics, bounded metadata, reordering/recovery and conflict execution; a topological transport DAG is insufficient |

A committee cardinality bound is not a mining-work fraction. A BFT commit is not
six Nakamoto successors. The comparison must name each security assumption and
its acceptance state; it cannot assign an invented equal-risk label to the two
families. If committee admission is controlled by one operator, it must be
reported as such. Availability certificates are not model quality or Hepta
FinalUse authority. Neither model voting nor an LLM recommendation activates
new consensus rules.

### Common full-business comparison requirements

The current 32-transfer dissemination experiment does not satisfy the user's
full successor comparison. An NG, Prism or DAG successor must run an explicit
implementation of its own consensus and recovery rules against the following
common inputs. This is the comparison contract, not a claim that those
implementations or measurements already exist.

| Dimension held common | Required observation and refusal condition |
| --- | --- |
| Transaction semantics | Identical canonical signed transactions, ordered nonce requirements, application/state commitments and initial balances; both disjoint recipients and actual conflicting writes. No missing or rejected transaction disappears from the denominator. |
| PQ and current authority | The same selected current PQ ownership/trust rules and full verification, including rotation, revocation, retry, conflict and recovery. Signatures on microblocks, votes, certificates and custody add to each architecture's measured costs. |
| Work and preparation | The same legal W1 relation/task/target accounting where applicable, with unsuccessful attempts, structured strategies, setup, cache lifetime and amortization recorded. A changed work/lottery relation needs a new security argument and cannot borrow PoN's assumption. |
| State and durable execution | Identical declared state cardinalities and touched keys, complete applicable validation, durable writer commits, proof construction, cold reopen, rollback detection and all effect journals. Delivery-only or in-memory timings cannot replace this interval. |
| Resources and faults | The original CPU/memory/network/storage budgets and deadline, with no-attack baseline, valid-work pressure, late-product/fabricated inputs, withheld payload, equivocation, leader/provider loss, partition and crash recovery under the same schedule. |
| Business outcome | An independent client verifies the actual application result and that architecture's stated confirmation rule. Report the rule and its unqualified assumptions; do not label six Nakamoto successors and a committee certificate as equal risk without an argument. |
| Complete costs | Producer, dissemination, PQ verification, consensus/vote/certificate, state execution/proof, persistence, client verification, recovery and repair costs; include all bytes and attributable resources, with unavailable observations marked unknown. |
| Decision | Publish all planned successes, failures and unobserved rounds on each exact source/profile. No architectural winner or protocol activation follows from a faster delivery arm or from paper throughput. |

The engineering expectation is conditional: separating leader election,
transaction propagation or ordering could reduce one stage while increasing PQ
signature traffic, stored history and recovery work. Which tradeoff improves
this application requires the complete measurements above. The present native
experiment remains labeled dissemination under the existing PoN consensus.

### Four-candidate continuation and current implementation scope

The 2026-11-05 continuation stays on the existing #688 integration lineage. Its
[source and execution record](../../../../evidence/pon-architecture-continuation-20261105/README.md)
separates implemented components from a complete successor:

| Candidate | Executable scope in this checkout | Remaining protocol work |
| --- | --- | --- |
| Bitcoin-NG | The common signed dissemination experiment and absolute frame-deadline controls | Work-elected key epochs, current PQ leader authority, microblock ancestry/equivocation, leader loss/censorship, key-work-only fork weight and complete recovery are not implemented as an NG backend |
| Prism | The same common dissemination/resource baseline; no separate proposer/voter-chain backend | Post-work role assignment, vote-chain reorganization, full dependency closure, confirmation rules and measured metadata/vote costs remain required |
| OHIE | The existing [bounded 2021 text-profile model](../../../../formal/pon-nakamoto-v1/parallel_variable_ohie.py), including a reorganization-safe executable mempool selection repair | Synthetic token execution and truncated SHA-256 queries do not implement native W1/PQ, WAN bandwidth, long-lived pool reclamation or mixed classical/quantum security; the source's stated text/appendix discrepancies remain explicit |
| GHOSTDAG | A new [uniform-work paper ordering reference](../../../../formal/pon-nakamoto-v1/ghostdag_order_reference.py), differentially checked against an independent set-based Algorithm 1 oracle | No native W1/PQ validity, weighted/variable-difficulty protocol, transaction execution, pruning/recovery, networking or security qualification is inferred from the ordering kernel |

The OHIE repair selects executable transactions from the current ledger's
unspent view in stable mempool order. After each selection it rescans, so a child
that arrived before its parent can follow that parent within the same template.
Invalid conflicting prefixes no longer occupy every available proposal slot.
The scan is bounded by the configured block and mempool capacities. It never
deletes a transaction merely because it is currently unusable: dependency
arrival and reorganization can make it usable later. Explicit caller-supplied
transactions, admission, target, rank and ledger rules retain their old meaning.

The GHOSTDAG reference uses the paper's greedy rule rather than solving maximum
k-cluster. A proposed blue block must preserve the anticone bound for **every**
current blue block as well as itself. Red blocks still appear in the complete
order. Missing dependencies, cycles, duplicate identities, unsupported work
semantics and exhausted model budgets cannot return a successful partial order.
Its deterministic profile and finite operation/cache limits are explicit in the
source. Equal final inputs must yield equal order regardless of input arrival
order; this is not a claim that independent incomplete network views agree or
that a finite suffix never reorganizes.

The common report reader now checks a lower bound on the measured sequential
wall interval: proof acquisition, dissemination, pool rounds, block calls and
History calls must fit within the complete business clock. For concurrent pool
rounds, it uses the maximum call duration per round, never the sum of overlapping
waiter durations. Identical workloads must retain positive identical frame-byte
counts, and the reported transaction payload must equal the bound signed bytes.
These are observation-consistency checks; a synthetic consistent report does
not authenticate a native execution or qualify a protocol.

### Congestion and late predecessors are part of the comparison

The NDSS 2024 [congestion/dependency study](https://www.ndss-symposium.org/wp-content/uploads/2024-685-paper.pdf)
analyzes Prism and OHIE when concurrent traffic increases propagation delay and
a block cannot be processed before its predecessors arrive. Consequently the
common fault schedule must include delayed predecessors, withheld bodies,
partial-frame trickle, overloaded priority queues and recovery after the missing
dependency arrives. Header arrival, complete dependency availability, full
validation, ordering, durable commit and independent confirmation are different
events. Priority for a small vote/header does not make its large dependencies
available for free. The new socket controls exercise their local I/O boundary;
they do not reproduce the paper's full network attack or establish WAN safety.

For NG, count work only under its declared key-block rule; microblock count is
not new PoN work or a replacement for independent confirmation. Test old-leader
suffixes, equivocation, withholding and leader failure. For Prism, measure vote
and proposal dependencies and voter-chain reorganization. For OHIE, every chain
must contribute its actual frontier and `rank == confirmBar` is not fully
confirmed. For GHOSTDAG, include wide anticones, duplicate transactions, missing
past and reordering with nonce, reward and supply conflicts.

The original native PoN no-attack and four-second/16-hostile-W1 gates, installed
depth plus required-work confirmation, and 4,105-block History gate remain
unchanged. Successor-specific confirmation must disclose its own security
assumptions; it cannot be called equal risk merely by matching a block count.
The 2021 variable-difficulty OHIE profile and the CRYPTO 2026 Fast DAA protocol
are separate constructions. A standalone target-recalculation component cannot
establish the latter's approximate-agreement, epoch or global-security rules.

The engineering inference motivating this experiment is limited: multiple
proposers and reference-based dissemination may improve the delivery stage,
while a shared writer, full W1 replay, conflicting account writes and independent
confirmation can still dominate the completed business path. Conflux's use of
concurrent blocks cannot remove those costs. Narwhal's separation of reliable
dissemination from ordering is a useful boundary to examine before changing
consensus. Whether either helps this application remains an observed question.

## Initial native component observation

An isolated local execution on 2026-10-13 ran both exact selectors. The 18 fresh
trials confirmed all 32 transactions per trial through the independent client,
retained all 396 native calls and zero errors, and passed the cold-reopen and
finite business criteria. Each mode transmitted 19,539 application frame bytes
for the disjoint workload. The complete proof acquisitions retained 11 and 12
attempts per seven-block workload respectively, including losing attempts.
The full comparison selector took 7.99 seconds; this is a component source tuple
observation before the final clean-source execution, not release qualification.
The actual native report SHA-256 was
`ee18a76028b05701002c9d9f9039f7ea1ed3972b5c3ae1009fd2dc8e6bb580c5`.

| Workload | Arm | Dissemination median, ms | Full cold business median, ms | Whole trial process CPU median, ms |
| --- | --- | ---: | ---: | ---: |
| Disjoint recipients | Serial | 9.20 | 465.10 | 273.09 |
| Disjoint recipients | Concurrent proposers | 2.68 | 411.50 | 274.12 |
| Disjoint recipients | Signed reference DAG | 2.49 | 404.14 | 268.83 |
| Hot recipient | Serial | 10.32 | 458.77 | 267.75 |
| Hot recipient | Concurrent proposers | 2.75 | 396.02 | 258.48 |
| Hot recipient | Signed reference DAG | 2.46 | 410.83 | 279.05 |

These three samples per cell show a local concurrency effect. The DAG arm does
not consistently beat concurrent proposers across the two workloads, and the
whole business path remains much longer than dissemination. This does not
establish a consensus architecture winner, a sustained throughput increase,
equivalent adversarial risk or improved Hepta model quality. The active protocol
therefore remains unchanged; a full successor still needs the comparability
obligations above and independently administered measurements.

## Primary references

- Eyal et al., [Bitcoin-NG: A Scalable Blockchain Protocol](https://arxiv.org/html/1510.02037v2), sections 4.1–4.5. Key blocks elect leaders and microblocks serialize transactions; their confirmation and fork rules require their own implementation rather than relabeling concurrent batch delivery.
- Li et al., [Scaling Nakamoto Consensus to Thousands of Transactions per Second](https://arxiv.org/abs/1805.03870v4). Conflux derives a transaction order from concurrent block relationships; its native node processing can become the bottleneck.
- Li, Long and Yang, [GHAST](https://arxiv.org/abs/2006.01072v1). Adaptive weights and a Tree-Graph supply the protocol's own liveness and confirmation argument; adding references alone does not implement it.
- Danezis et al., [Narwhal and Tusk](https://arxiv.org/abs/2105.11827v4), sections 2–4. Reliable dissemination and causal storage are separated from ordering; a `2f+1` availability certificate relies on checked storage by honest committee members.
- Spiegelman et al., [Bullshark](https://arxiv.org/abs/2201.05677), and [the partially synchronous description](https://arxiv.org/abs/2209.05633v1). The ordering rules interpret DAG support; a topological sort is not their complete commit algorithm.
- Babel et al., [Mysticeti](https://arxiv.org/abs/2310.14821v6). Avoiding explicit vertex certification depends on the stated commit and fast-path rules, not on removing signatures or custody requirements.
- Bagaria et al., [Prism](https://arxiv.org/abs/1810.08092). Separating roles is another permissionless design reference; its confirmation proof is not inherited by useful neural work.
- Yu et al., [OHIE](https://arxiv.org/abs/1811.12628), and Wang et al., [Securing Parallel-chain Protocols under Variable Mining Power](https://arxiv.org/html/2105.02927v2). Parallel-chain aggregation and the pivot/difficulty-coordinate conditions require their complete stated protocol.
- Sompolinsky, Wyborski and Zohar, [PHANTOM/GHOSTDAG](https://www.avivz.net/pubs/2021/phantom_ghostdag.pdf), Algorithm 1. This continuation implements a bounded uniform-work ordering reference, not Kaspa's production protocol.
- Wu et al., [Security-Performance Tradeoff in DAG-based Proof-of-Work Blockchain Protocols](https://www.ndss-symposium.org/wp-content/uploads/2024-685-paper.pdf), NDSS 2024. Its congestion/dependency model motivates the additional common fault obligations above.
- Garay, Kiayias and Shen, [Fast Difficulty Adjustment in Proof-of-Work Consensus](https://eprint.iacr.org/2026/1116), revised 2026-09-10. Its parallel-chain and approximate-agreement construction is not supplied by the current arithmetic component.

## Reproduction

Run the project preflight first. A clean committed source is required by the
execution owner; its existing source verifier checks tracked bytes rather than
trusting cached Git status. The output must be a new directory outside the checkout.

```sh
python3 formal/pon-nakamoto-v1/experiments/architecture_compare.py --out /absolute/new/output
```

The owner builds the exact native test binary, executes both named selectors,
checks the bounded actual report, binds its hashes and repeats raw source identity
verification after execution. Failed compilation, missing measurements and native
business failures remain in the manifest. It introduces no Actions lane or
activation setting. The actual selected source, environment and result belong to
the newly produced receipt, not to this document.
