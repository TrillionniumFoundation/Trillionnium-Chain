# Trillionnium Chain project boundary

The canonical repository is `TrillionniumFoundation/Trillionnium-Chain`. Its
active consensus lane is **native PoCO-BFT v0**. CometBFT code is retained only
for one-way migration and historical differential replay; it cannot authorize a
release, validator deployment, or production-readiness claim.

## Owned surfaces

This repository owns consensus protocol and safety rules, native application and
state execution, mempool/RPC/node interfaces, genesis and validator tooling,
migration/state-sync/light-client proofs, and the release/SBOM/evidence chain.

## Excluded surfaces

World gameplay, campaign and economy logic, Hepta services, Nakama authoritative
match state, sibling-repository Cargo paths, and cross-repository orchestration
are outside this boundary.

## Governance boundary

`main` is the default integration branch and is required to be protected by pull
requests, two approvals, a code-owner review, last-push approval, and stable
required checks. `PROJECT_BOUNDARY.json` is the machine-readable policy; GitHub
settings are independently verified and may not be inferred from this document.

Production candidacy and consensus activation remain false until signed,
source-bound evidence satisfies every gate in the canonical development plan.
