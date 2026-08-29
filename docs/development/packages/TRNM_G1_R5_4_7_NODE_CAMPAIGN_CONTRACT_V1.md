# G1-R5 4/7-node campaign contract v1

Status: **candidate harness contract; no validator run**.

## Identity

Every campaign binds repository, source commit/tree, Plan, protocol manifest, binary, SBOM and genesis digests. A rebuilt or changed artifact creates a new campaign identity.

## Validator sets

### Four-validator baseline

- exactly four unique validators;
- equal positive weights;
- strict public keys and proof of possession;
- quorum `floor(2W/3)+1 = 3`.

### Seven-validator baseline

- exactly seven unique validators;
- unequal positive weights;
- example candidate weights `[4,3,3,2,2,1,1]`;
- total 16, quorum 11.

## Topology

Each validator maps to one process, host, operator and custody domain. The campaign reports all cardinalities separately and requires at least three hosts. Process count is never operator/decentralization count.

## Required scenarios

Common:

- normal finality;
- offline minority and rejoin;
- leader crash and timeout certificate;
- validator restart and catch-up;
- state sync from a finalized checkpoint;
- epoch/key rotation;
- signer fault;
- disk-full/I/O fault.

Four-node-specific:

- 3–1 progress;
- 2–2 safe stall and heal.

Seven-node-specific:

- 5–2 progress;
- a weight-selected 4–3 safe stall and heal.

Every progress scenario names an active set whose weight reaches quorum. Every stall scenario names an active set below quorum.

## Result authority

Transport connectivity, authenticated handshakes or material exchange are not validator-run evidence. A completed campaign requires signed per-validator consensus reports, raw process journals, one finality/root tuple, zero double-sign and exact recovery/fault outcomes.
