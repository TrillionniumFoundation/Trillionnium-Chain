# Security policy

Status: **native PoCO-BFT candidate; no production or mainnet claim**.

## Supported scope

Security reports are accepted for the active native path and every component
that can affect its safety, liveness, custody, availability, or release chain:

`authenticated ingress / state sync -> trnm-poco-node -> trnm-consensus-core
-> trnm-consensus-safety-rules / safety-store / signer journal -> native
application / execution / state root -> finality and light-client proofs`

Reports involving wire decoders, validator-set or epoch transitions, QC/TC
verification, pacemaker behavior, persistence, rollback protection, remote
signing, HSM/KMS policy, migration/export tooling, build provenance, CI, SBOMs,
operator configuration, RPC admission, or denial of service are in scope.

CometBFT, `trnm-consensus-app`, and `trnm-node` are migration residue and
historical differential inputs. A vulnerability in those surfaces remains
reportable, but it is not evidence that the native path is affected unless the
behavior is reachable through an active migration, build, or runtime boundary.

## Reporting

Do not publish an unpatched vulnerability in a public issue, discussion, pull
request, or commit message. Use GitHub private vulnerability reporting after the
repository owner has verified that the route is enabled. Until that verification
is recorded, use an already-established private maintainer channel and disclose
only enough publicly to request contact.

Include the exact commit/tree, affected configuration and validator role, a
minimal reproduction, expected impact, prerequisites, and whether exploitation
requires unauthenticated network access, validator/operator access, signer
authority, filesystem access, or supply-chain control.

## Handling and disclosure

Security fixes must retain a private source-bound reproduction, add a negative
regression or mutant, identify downstream evidence invalidated by the change,
and receive independent review. Critical and High findings block public-testnet,
release, production-candidate, migration-cutover, and activation claims until
remediation is independently replayed and accepted.

No bounty, response deadline, supported mainnet version, or deployment should be
inferred from this policy.
