# Security Policy

Status: **reporting process requires operational verification before public release**

## Supported scope

Security reports are accepted for the native PoCO chain path, including:

- `trnm-node` node and validator protocol;
- `trnm-pouw` PoCO validity, challenge, and settlement logic;
- `trnm-state` balances, governance, replay protection, persistence, and state roots;
- `trnm-mempool`, `trnm-executor`, and `trnm-rpc` resource and concurrency boundaries;
- finality types, quorum verification, proofs, receipts, worker-agent, CLI, bridge, oracle, contracts, and frontend integrations.

## Reporting

Do not open a public issue containing details of an unpatched vulnerability.

GitHub private vulnerability reporting is the intended channel. Repository owners must enable it, submit a private test report, verify notification delivery, and record the triage owner before describing this policy as operational.

Until that verification is recorded, maintainers who already have an established private channel may use it. Do not invent or publish an unmonitored security address.

A useful report includes:

- affected commit and component;
- minimal reproduction;
- expected and observed behavior;
- impact and required access level;
- whether exploitation requires validator, operator, worker, consumer, authorized signer, peer, RPC, or unauthenticated access;
- suggested containment where known.

## Priority classes

Highest priority includes conflicting finality, unauthorized state transition, forged vote or receipt, supply or escrow violation, replay bypass, remote code execution, key disclosure, validator equivocation, state-root divergence, persistence corruption, and remotely triggerable resource exhaustion.

No bounty, disclosure deadline, or release status should be inferred from this file. Coordinated disclosure timing is agreed after triage.
