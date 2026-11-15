# Fixed W1 v2 guest reproduced without changing the pin

This follows the earlier [image mismatch](../pon-w1-rebuild-preflight-20261105/README.md).
A new locked build reproduced the original guest **byte for byte**: SHA-256
`25718312ec3c6f5219d832e3516adfb5f82983156f669c5e7daa15bd22d1798f`,
375,928 bytes. The original independent verifier's image/profile and all proof
limits remain unchanged. No guest source or Cargo.lock was edited.

The real checkout directory had to match the historical absolute source root
`/workspace/scratch/79360d3567d1/chain`. A recorded Cargo wrapper appends only
`--remap-path-prefix=/workspace/shared/w1-home/.cargo=/root/.cargo` to the
SDK's existing encoded guest flags. Rust compiler, sysroot, dependency versions
and normal SDK flags are unchanged. Merely remapping both source and cache
paths from another physical checkout produced a different image; that failed
reproduction and its build log are retained. The successful recipe is specific
to this historical image, not a general location-independent build guarantee.

[reproduction.json](reproduction.json) records the exact command, environment,
source/tree identities, wrapper digest and frozen binary hashes. The executed
local source commit is `2810f7c2b1b5e549302b3fdb2cf41b2a6ee19bff`, whose tree
is identical to published `a635200956843f0d2f335f929977d602b48b36ec`.
Do not claim that the published commit itself was the executed commit.

The original full v2 proof has now started using these frozen binaries, the
original input, external A/B commitments, 7,200-second total budget,
300-second segment budget, 1-GiB free-space floor and 256-MiB checkpoint cap.
At this evidence checkpoint the full run and 58 saved-receipt controls remain
pending. This successful build closes only the fixed-guest reproduction
prerequisite. It does not qualify proof security, performance, Node admission,
PQ-128 or production.
