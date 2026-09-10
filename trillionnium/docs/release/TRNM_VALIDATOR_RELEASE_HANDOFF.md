# TRNM Native PoCO Validator Release Handoff

Status: development handoff template; not release approval.

Required fields:

- branch, commit and clean-tree state;
- native node/validator binary hashes;
- chain ID, validator identity, voting power and key fingerprints;
- configuration and genesis/checkpoint hashes;
- test and fault-injection commands;
- final height, block hash, state root and quorum evidence;
- replay, restart, rotation and rollback results;
- unresolved blockers from `../../../RELEASE_READINESS.md`.

A handoff is NO-GO when any identity, hash, signer-safety or state-convergence
field is missing or inconsistent.
