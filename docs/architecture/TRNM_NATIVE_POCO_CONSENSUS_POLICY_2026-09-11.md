# TRNM Native PoCO Consensus Policy

Date: 2026-09-11  
Status: **binding architecture direction**

## Decision

TRNM block consensus, task validity, consumption settlement, rewards, challenges, and finality evidence remain self-developed and protocol-native.

The canonical implementation path is:

```text
trnm-mempool
  -> trnm-chain-node proposal
  -> trnm-chain-validator independent execution and vote
  -> native quorum and commit
  -> trnm-state / trnm-pouw
  -> state root and finality receipt
```

A third-party block-consensus engine or application bridge is not part of the production candidate.

## Required properties

The native protocol must provide and test:

- authenticated peer and validator identity;
- deterministic proposal ordering and execution;
- durable anti-equivocating votes;
- proposer rotation and round change;
- quorum of at least `2/3 + 1` voting power;
- unique finality per height;
- commit propagation and crash recovery;
- validator-set changes bound to committed state;
- replay-safe commands, nonces, votes, receipts, and proofs;
- deterministic state roots and finality receipts;
- bounded resource use and fail-closed input validation;
- PoCO value conservation, challenge, resolve, expiry, refund, and slashing semantics.

## Module boundary

- `trnm-node` owns native consensus networking, proposal, vote, recovery, and finality orchestration.
- `trnm-pouw` owns PoCO validity and settlement rules.
- `trnm-state` owns committed state and roots.
- `trnm-finality-types` and `trnm-finality-verifier` own portable finality evidence.
- `trnm-mempool`, `trnm-executor`, and `trnm-rpc` must not bypass consensus validity or mutate committed state independently.

## Acceptance rule

A feature is implemented only when the native node and validator path executes it on every validator and produces identical committed roots and receipts. Isolated library tests, simulator output, or documentation-only claims are insufficient.

## Release rule

Public-network readiness remains false until authenticated multi-host topology, validator lifecycle, secure signer custody, staking/slashing policy, state synchronization, observability, indexing, multi-host performance, long-duration fault testing, and independent security review are complete.
