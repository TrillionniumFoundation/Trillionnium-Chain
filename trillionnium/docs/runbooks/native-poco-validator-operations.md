# Native PoCO Validator Operations

Status: development runbook.

## Bootstrap

1. Build from a clean, recorded commit with the pinned toolchain and reviewed
   dependency lock.
2. Generate validator and operator keys separately; never use packaged fixture
   keys.
3. Record chain ID, validator set, voting power, genesis/state root and all
   configuration hashes.
4. Start as a non-voting observer, authenticate peers and verify checkpoint
   convergence.
5. Enable voting only after local height, block hash and state root agree with
   a quorum.

## Rotation

A rotation packet must identify old and new keys, validator identity, voting
power, activation height, approvals and rollback conditions. New keys prove
possession before activation. Old keys remain protected until the transition
is final and reviewed.

## Compromise

Immediately isolate the signer, preserve anti-equivocation state and logs,
freeze automated restarts, compare signed votes, initiate governed rotation and
publish a commit-bound incident record. Never copy a possibly compromised key
to a replacement node.

## Recovery

Restore only from an authenticated checkpoint and verified write-ahead history.
A recovered node rejoins as non-voting until state convergence and signer safety
are demonstrated.

## Evidence

Every rehearsal records branch, commit, clean-tree status, binary hash,
configuration hashes, validator identities, commands, timestamps, state roots,
quorum evidence, failure injections and rollback results.
