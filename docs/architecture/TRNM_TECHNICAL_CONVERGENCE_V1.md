# Trillionnium Chain technical convergence contract v1

Status: **active implementation-boundary supplement; no production, public-testnet, release, or activation authority**

This document supplements the sole Plan v2 development plan. It does not create
a second roadmap. Its purpose is to reduce simultaneous invention, make the
smallest native PoCO-BFT node independently reviewable, and keep every
unverified claim fail closed.

## 1. Convergence objective

The first accepted node is a deterministic, recoverable state-machine replica,
not a complete AI economy. Its production-candidate closure contains M00-M08,
M13, M15 and M17. M09-M12 remain candidate application packages until the node
path is stable. M14 and M16 remain non-authoritative services.

Resolve `docs/architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md` before using
this supplement. The two authority paths are intentionally separate:

```text
authenticated ingress -> bounded admission -> ordered proposal
  -> deterministic full-payload validation into a prepared overlay
  -> authorized Safety decision and exact intent durable
  -> exact signature recorded -> vote published

complete three-chain finality verified against the expected oldest target
  -> exact commit intent durable -> idempotent canonical application apply
  -> commit result durable -> checkpoint confirmed -> finalized receipt published
```

A prepared overlay never becomes canonical state merely because a proposal was
valid or a vote was sent. A vote MUST NOT wait for its own block's finality.
The old `Prepared` through `OutboundPublished` labels describe candidate journal
observations, not authority to collapse these paths. Interleaving and recovery
must preserve both sets of invariants, including exact intent replay and fresh
authoritative readback after uncertain completion.

No remote planner, indexer, RPC response, benchmark harness, fixture, legacy
runtime, or candidate application package may become an implicit authority in
these paths. The module partition is a delivery constraint, not production
acceptance; documenting the partition does not close semantic design gaps.

## 2. Consensus and economic separation

PoCO-derived capacity remains `shadow`. It may produce diagnostics and
counterfactual validator sets, but it must not change active membership, quorum
weight, leader selection, signing authority, rewards, jail, or slashing.
Leaving shadow requires a new, independently reviewed activation package that
binds finalized state provenance, anti-collusion policy, identity independence,
mainnet economic constants, slash policy, multi-operator observations and a
signed epoch-boundary governance decision.

PoCO consensus or another mature engine may be retained only as an offline
differential oracle. It is not a production dependency, fallback authority or
alternate source of finality.

## 3. Reviewable delivery units

A convergence change must be scoped to one authority boundary or one
machine-verifiable cross-boundary contract. A pull request should identify:

1. exact source, base and prospective-merge identities;
2. modules and capability edges changed;
3. protocol, persistence and recovery states affected;
4. resource limits and negative cases;
5. evidence invalidated by the change;
6. the commands and retained artifacts that qualify the exact source.

A large integration successor remains a composition target, not the review unit.
Subsystem changes enter it through bounded child pull requests.

## 4. Supply-chain boundary

Candidate-controlled code must never execute in the same trust domain that
holds a repository-write credential. In particular, candidate build scripts,
procedural macros, tests, shell scripts and generated binaries may not run
before a token-bearing publication step on a persistent runner.

An automated repair flow must use:

```text
protected controller
  -> ephemeral read-only, tokenless builder
  -> content-addressed bounded patch
  -> independent verifier
  -> publisher that executes no candidate code
  -> expected-head compare-and-swap
```

The final product tree must not retain one-shot writers. A queued, skipped,
cancelled, `action_required`, empty or different-head run has zero acceptance
credit.

## 5. Performance claim boundary

Only finalized and replay-verified committed goodput is a chain throughput
claim. Every result binds source, binary, configuration, workload bytes,
conflict distribution, process/host/operator/region/custody topology, RTT/loss,
fault schedule, duration, repetitions and raw traces.

The minimum matrix includes 4/7/31/100 validators, multi-host execution,
20/80/180 ms RTT, 0/1/5 percent loss, 0/10/50/90 percent conflict, leader loss,
partition/heal, disk pressure, restart, state-sync rejoin and migration
rehearsal. Ingress or submission TPS is not substituted for committed goodput.

## 6. Closure classes

A repository commit may close source, documentation, schema, test and packaging
gaps. It cannot self-create independent review, HSM custody, a physically
independent monotonic anchor, physical power-loss evidence, multi-operator
campaigns, external audit/red-team results, wall-clock soak time or signed
governance activation.

`config/technical-convergence-v1.toml` records these classes. Its
`all_gaps_closed`, production, public-testnet, release and activation flags
remain false until the canonical machine authorities are changed through
protected review with matching evidence.

## 7. Required module supplements

The stable M00-M17 reference remains the module authority index. Implementation
details that were previously too compact are frozen in the following
supplements:

- M04 authenticated P2P and dissemination;
- M05 transaction lifecycle and mempool recovery;
- M08 finality, Node Commit Ledger and restart convergence;
- M14 RPC, indexer, SDK and CLI consistency;
- M15 node composition, packaging and release supply chain;
- M16 guarded, out-of-band control plane;
- M17 observability, benchmark, security and evidence.

Each supplement defines authority, typed interfaces, state machine, persistence,
resource bounds, security, SLOs, verification evidence and activation boundary.
