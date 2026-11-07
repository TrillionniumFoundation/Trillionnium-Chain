# Throughput continuation — original acceptance remains HOLD

This continuation starts from PR #688 source
`e70f13448aad715286fb8eb56fc802b09db643a3`, tree
`1fc19c44ab2d4b35672b25d0f4e4039b769cadea`. It preserves the existing integration
candidate, all original resource limits and the earlier failed observations.
The source changes are component improvements; this record grants no production
activation, higher confirmed TPS, complete authenticated-state migration or
successor-consensus qualification.

## Implemented scope

| Priority | Concrete change | Boundary retained |
| --- | --- | --- |
| Inbound work | After checking the exact packet envelope, length and every lowercase-hex byte, construct the same request directly. Read sockets into the already reserved initialized buffer. | Original framing, canonical bytes, ticket, signatures, complete work/state validation, live Host checks, queue/byte ceilings, read quantum and deadlines. |
| State/history work | Reuse the existing bounded full-input sparse-root arithmetic only during classical Legacy reorganization. | Read all actual SQL rows, compare the current stored root and preserve continuity, untouched-corruption checks, cursor/owner fences, cancellation and atomic publication. PQ, Growth and Authenticated profiles keep their original validation paths. |
| Parallel preparation | Skip speculative state work for a repeated classical sender whose nonce must depend on an earlier command. | Every preparation/signature and ordered state effect still executes. Original full-speculation and serial references remain differential test oracles. PQ/Growth state ownership is unchanged. |
| Bulk data and batching | Preserve the existing separate Cell data plane; integrate reviewed actual accept-loop readiness for its test fixture. | No weight/training payload is moved into the block hot path; the original request timeout starts at actual use and is not increased. |
| Acceptance | Retain all available hostile attempts, errors, late returns, repeated indices, missing observations and CPU nesting in the failed-confirmation summary. | The original v1 report, 4-second/16-worker test and 4,105-block History requirements retain their identities and failure status. |

Independent review found that the draft root-arithmetic selector did not
explicitly preserve PQ's profile-specific State relation. The normal Legacy
constructor already refuses PQ, so this is not evidence of a deployed public
exploit. The final selector explicitly excludes PQ; its regression checks that
defensive selector invariant, then supplies malformed PQ authority leaves with
an attacker-consistent plain root to the actual PQ owner. Original PQ validation
must still refuse them. A matching generic root never replaces profile validation.

This Legacy optimization remains **O(N)** in current State. The separately
selected `PermanentAccountGrowthV2` already implements authenticated touched
accounts, bounded working state and SQLite COW. Composing that path with PQ,
complete mandatory ranges, migration, recovery anchors, retention and
unaccessed-data audit obligations in
[STATE_RECOVERY](../../docs/protocol/pon-nakamoto-v1/details/STATE_RECOVERY.md)
remain separate work. The 64-command/10-second PQ parameter ceiling is unchanged
and does not establish observed confirmation throughput.

## Original evidence and source repairs

The [acceptance record](acceptance/README.md) independently reads the exact
original Actions artifacts. Its all-event denominator is 20 terminal runs:
11 success and nine failure. Retained-packet baseline confirmation is 1/1 in
3.098539910 seconds; its 16-worker pressure result is 0/1. The separate
fresh-challenge stream also remains 0/1 under pressure. Current History is
2,362/4,105 returning imports on x64 and 4,104/4,105 on ARM. ARM stores all
4,105 non-genesis rows but retains active genesis and cancelled cursor 3,404.
These current records are distinct from earlier 3,322/3,407 observations.

The reviewed source corrections are the exact SQLite script pin from PR #768,
the two actual accept-loop readiness files from PR #772, and PR #760's local
CodeQL SARIF ownership correction. The latter retains exact-source analysis and
parseable artifacts while the already enabled repository default setup remains
the server-side upload owner. No branch protection or repository security
setting is changed. Sibling-branch results do not qualify this composition.

## Qualification rules

Record the exact committed source, compiler/profile, locked dependencies and
all raw command outcomes. Keep component and extracted-function timing separate
from whole-Node release observations, and keep both separate from original Host,
WAN, sustained malicious traffic, independent confirmation and p95/p99 service
acceptance. Charge fixture construction, unsuccessful work and all retained
attempts. Missing physical or global costs remain unknown.

The original service, long History and same-hardware successor-architecture
comparisons must be rerun on the final source; neither an exit-zero harness nor
a faster local component closes those gates. No consensus-architecture choice
or increased protocol quota follows from this continuation.
