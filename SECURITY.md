# Security Policy

Status: **unverified reporting-policy draft**. Repository owners must enable and
test a private reporting route before treating this file as an operational
security contact.

## Supported Scope

Security reports are accepted for the production-candidate path:

`CometBFT -> trnm-consensus-app -> trnm-runtime -> committed state/AppHash`

The bespoke `trnm-chain-node`, `trnm-chain-validator`, `trnm-chain-cli`, and
`trnm-sim` binaries are legacy harnesses. Reports affecting those paths are still
useful, but they do not establish impact on the production candidate unless the
same behavior is reachable through the canonical path.

## Reporting

Do not open a public issue containing details of an unpatched vulnerability.
GitHub private vulnerability reporting is the intended route, but its enablement
has not been verified by this repository state. Before release, repository owners
must enable it, submit a private test report, and record the triage owner.

Until that verification exists, this document does not claim a public security
contact or invent an unmonitored email address. Reporters who already have an
established private channel with the maintainers may use it without placing
vulnerability details in a public issue.

A report should include the affected commit, a minimal reproduction, expected
impact, and whether exploitation requires validator, operator, authorized signer,
or unauthenticated network access.

No bounty, disclosure deadline, or mainnet deployment should be inferred from this
policy. Coordinated disclosure timing is agreed per report after triage.
