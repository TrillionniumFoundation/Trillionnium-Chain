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

This Legacy optimization still traverses every current State row and its bytes,
and sorts the complete leaf set. It is not touched-set O(k) processing. The separately
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

The reviewed source corrections are the exact SQLite script pin from PR #768
and the two actual accept-loop readiness files from PR #772. During this work,
PR #688 advanced independently through `271a87f831aa7e08f3c2024f738504c1422122dd`
to `3d1b6507671ec694ce58e86d4063a125c8deeb66`.
Its SQLite correction is identical; its complete CodeQL workflow is preserved,
including before/after source identity, explicit `upload: never` and failed-run
SARIF retention. The earlier PR #760 `upload: false` setting is superseded:
the pinned action interprets it as `failure-only`, not a complete upload disable.
The already enabled repository default setup remains the server-side upload
owner. The later diagnostics identified one generated, untracked historical
crypto harness lock, with no tracked diff. [Scan preparation](codeql-lock/README.md)
adds its independently validated 12-package lock while retaining all original
historical bytes and the strict source guard. All concurrent diagnostics and
historical F0/campaign/History evidence are preserved. The failed scans retain
their status; the final scan must pass on its own source. No branch protection
or repository security setting is changed. Sibling-branch results do not
qualify this composition.

## Measured local results

The [eight complete native observations](reorg-abba/README.md) use the same
512-block real PNW1 fixture and the original release profile. All eight complete
State and cold-reopen comparisons passed. Activation wall median fell from
1.227694237 s to 0.916976377 s (about 25.3%); activation CPU fell about 26.7%.
However, whole-process wall stayed at about 71.6 s, whole-process CPU at about
70.0 s and maximum RSS at 23,580 KiB. Complete preparation dominates this
fixture: the stage improvement does not establish overall throughput gain.

[Repeated-sender observations](repeated-sender/README.md) retain all 84 rows
and every signature/state comparison. For 256 transactions with two senders,
reexecution fell from 255 to one; with 64 senders, from 255 to 63. Wall-clock
comparisons vary and do not establish a consistent whole-executor speedup.
The [inbound extracted-function observations](inbound/README.md) show lower
decode/read overhead under their explicitly mixed compiler/dependency profile;
they are not whole-Node release or original Host measurements.

[Frozen-source validation](validation/README.md) records M06 141 passing tests,
Cell 353, SQLite 13, strict workspace Clippy, the full locked graph, formatting,
149 acceptance-reader controls and all source-integrity controls. Node records
1,150 passed, three failed and 31 ignored. The three independent-witness tests
fail during Unix-listener startup, before the business path; independent probes
reproduce AF_UNIX socket-creation EPERM. Their failures are retained. All nine
new Node regressions passed. No combined
whole-product or original-resource gate is promoted by these component checks.

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
