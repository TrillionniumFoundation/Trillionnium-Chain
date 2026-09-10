# PoCO v1 — Proof of Consumption Protocol Draft

Status: development draft  
Consensus family: self-developed native PoCO

## Purpose

PoCO coordinates useful-compute tasks, verifiable result commitments,
consumption receipts, challenges and value-conserving settlement while the
native validator network orders and finalizes state transitions.

## Actors

- Client: funds a task and defines bounded acceptance conditions.
- Worker: accepts assignment, posts stake and commits/reveals a result.
- Consumer: pays for an accepted consumption receipt when applicable.
- Challenger: posts a bond and supplies a bounded challenge.
- Resolution authority: resolves only through governed, auditable commands.
- Validator: authenticates, orders, executes and votes on deterministic blocks.

## Lifecycle

`Create -> WorkerAccept -> ResultCommit -> ResultReveal -> Consume -> Challenge/Resolve or Settle`

Every pre-terminal state must have deterministic timeout, refund, settlement or
slashing behavior.

## Consensus binding

Native proposals and votes bind chain ID, height, round, prior block hash,
transaction root, state root and validator-set identity. A finality receipt
contains the committed header, quorum evidence and inclusion proof material.

A validator independently authenticates and executes every command before
voting. A quorum requires at least two-thirds plus one of configured voting
power. Partitions without quorum must halt.

## Determinism and replay protection

- consensus-visible values have canonical encodings;
- command IDs and signer nonces are replay protected;
- expiries use consensus height/time rules defined by the protocol;
- failed commands cannot mutate state;
- every value transfer names its payer, escrow, receiver and terminal outcome;
- state roots and finality receipts are reproducible from ordered inputs.

## Security and economic invariants

1. Total value is conserved except for explicitly governed issuance or burn.
2. Worker assignment requires worker authorization.
3. Commit/reveal material is domain separated and salt bound.
4. Challenges require a bond and have bounded windows.
5. Resolution authority cannot silently rewrite signed evidence.
6. Validator equivocation evidence must be durable and actionable.
7. Resource limits and fees must make sustained abuse uneconomic.

## Status

The repository contains substantial native implementation and local evidence,
but multi-host networking, secure signing, staking/slashing, public anti-spam
parameters and long-duration performance evidence remain release blockers.
