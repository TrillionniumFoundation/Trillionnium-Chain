# Security Policy

Status: **reporting route not yet operationally verified**.

## Supported scope

Security reports are accepted for the native PoCO chain:

- `trnm-node`, validator voting, quorum, recovery and finality;
- `trnm-pouw`, task proofs, challenges and settlement;
- `trnm-state`, checkpoints, balances and committed roots;
- `trnm-executor`, `trnm-mempool`, `trnm-rpc`, worker and CLI surfaces;
- finality receipt types and verification.

## Reporting

Do not publish unpatched vulnerability details in a public issue.

Repository owners intend to use GitHub private vulnerability reporting, but
must enable it, submit a private test report and record the triage owner before
this file is treated as an operational security contact. Existing trusted
private channels may be used meanwhile.

Include the affected commit, minimal reproduction, expected impact and required
access level. State whether exploitation requires validator, operator,
authorized signer or unauthenticated network access.

No bounty, disclosure deadline or release readiness should be inferred from
this policy.
