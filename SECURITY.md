# Security Policy

Status: **reporting route not yet operationally verified**.

## Supported scope

Security reports are accepted for the native Trillionnium Chain path, including:

- `trnm-chain-node`, `trnm-chain-validator`, `trnm-chain-cli`, and `trnm-sim`;
- native proposal, vote, quorum, round-change, commit, replay, and recovery logic;
- validator keys, anti-equivocation state, peer authentication, and validator lifecycle;
- `trnm-runtime`, `trnm-state`, `trnm-executor`, `trnm-mempool`, `trnm-rpc`, proof/finality crates, and canonical protocol types;
- bridge, oracle, worker-agent, contract, frontend, release, and supply-chain boundaries where they can affect chain safety or assets.

External consensus engines are not supported project components and must not be introduced as dependencies or runtime authorities.

## Reporting

Do not open a public issue containing details of an unpatched vulnerability.
GitHub private vulnerability reporting is the intended route, but repository owners must enable it, submit a private test report, and record the triage owner before treating it as operational.

A report should include:

- affected commit and component;
- minimal reproduction;
- safety, liveness, confidentiality, integrity, availability, or economic impact;
- required attacker access;
- whether the issue can cause double signing, conflicting finality, state-root divergence, unauthorized state transition, key compromise, replay, denial of service, or fund loss.

## Release blockers

Public release remains blocked until the project has:

- a verified private reporting route and triage rotation;
- independent review of consensus, cryptography, state persistence, networking, and economic logic;
- long-running fuzz and adversarial network campaigns;
- reproducible SBOM and build provenance;
- HSM/KMS or remote-signer operations;
- incident, key-compromise, chain-halt, rollback, and state-recovery drills.

No bounty, disclosure deadline, or deployment status should be inferred from this draft.
