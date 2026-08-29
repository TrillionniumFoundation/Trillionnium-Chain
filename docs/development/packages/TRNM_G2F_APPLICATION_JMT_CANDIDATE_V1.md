# G2F versioned sparse application-tree candidate v1

Status: **repository-local implementation candidate closed; canonical application JMT authority remains blocked**

Owner: A16  
Package: `G2F_WHOLE_NODE_LIGHT_CLIENT_V1`  
Evidence head: `b879dcff8cf1f162faf70d1277f3517ae78c0d3e`  
Exact-head run: `33278500374` (`completed/success`).

## Candidate implementation

`conformance/g2f/application_jmt_v1.rs` is a dependency-free Rust implementation of the candidate Protocol-09 sparse application-tree shape. It provides:

- 256-bit LSB-first state-key paths;
- domain-separated SHA-256 state-key, leaf, node and empty-node commitments;
- versioned immutable snapshots;
- exact parent/new-version sequencing;
- sorted unique `Put`/`Delete` write sets;
- write-version equality;
- membership and non-membership proofs;
- prior-version isolation;
- rejection of stale parents, noncontiguous versions, duplicate keys, wrong write versions, proof sibling/value/root tampering and non-membership claims for present keys.

Fixed vectors bind:

```text
empty_root=e7973f7b9e655388bbab7edf097ba7fbf16befe699b1be1530fa7b46ed19d49c
three_record_root=6e6e92f5eebb5d58a405e0158bffbe38816dbf3d77f9342b89d02f49f2d0770a
```

The exact-head package gate compiles the source with `rustc --test -D warnings`, runs four focused test groups, then executes the existing G2F Python campaign, feature-gated Node tests, strict Clippy, workspace rustfmt and clean-worktree assertion.

## Authority boundary

This candidate does **not** establish that the resulting root is the chain's canonical application root. Commissioning still requires all of the following:

1. accepted A11–A15 source-plane interfaces and exact content digests;
2. accepted finalized Order/header authority and application-commit sequencing;
3. whole-node predecessor-bound CAS and externally anchored rollback protection;
4. independent second implementation and cross-language fixed-vector replay;
5. process crash, power-loss, state-sync and multi-host evidence;
6. independent P0 review and a separate Gate/truth decision.

## Closed candidate gaps

```text
A16-RUST-VERSIONED-SPARSE-APPLICATION-TREE-CANDIDATE
A16-MEMBERSHIP-NONMEMBERSHIP-PROOF-CANDIDATE
A16-PRIOR-VERSION-ISOLATION-CANDIDATE
A16-PROTOCOL09-FIXED-VECTOR-CANDIDATE
```

## Remaining blockers

```text
G2F-CANONICAL-APPLICATION-JMT-AUTHORITY
G2F-INDEPENDENT-APPLICATION-TREE-IMPLEMENTATION-REPLAY
G2F-ACCEPTED-A11-A15-INTERFACES
G2F-FINALIZED-ORDER-APPLICATION-COMMIT-AUTHORITY
G2F-WHOLE-NODE-CAS-AND-EXTERNAL-ANCHOR
G2F-POWER-LOSS-MULTI-HOST-EVIDENCE
G2F-INDEPENDENT-P0-ACCEPTANCE
```

## Non-claims

```text
versioned_sparse_application_tree_candidate=true
canonical_application_jmt=false
order_finality_authority=false
production_external_anchor=false
production_hsm_authority=false
g2f_exit=false
node_support=false
production_candidate=false
production_consensus_activation=false
```
