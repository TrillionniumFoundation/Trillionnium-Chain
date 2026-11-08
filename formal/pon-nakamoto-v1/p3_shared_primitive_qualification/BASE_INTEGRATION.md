# Integration with the advanced research baseline

Status: **HOLD_NO_GO**. This is an integration and measurement continuation,
not a new cryptographic qualification or a change to the tagged profile.

## Preserve both source histories

The first P3 candidate, `cfef87ff6e09f998cb8fc5d3165fce8ac9eb2da1`, passed its
complete focused exact-commit checks and independent proof replay, and was
pushed normally. Before opening the stacked PR, the target PR #783 had
advanced by ten commits from `cc836dfc13ef0006eb0878abd8cb5eca9a76bec0` to
`09fbc0f45151a68a1bf205641171840fbf309882` through parallel research work.

The candidate integrates that exact incoming head without rewriting either
history. Two append-only conflicts were resolved: the sole development plan
retains both sets of entries, and `src/lib.rs` retains `sha_schedule_air`
alongside both new tagged modules. The incoming runtime, configuration and
qualification directories are unchanged from the original baseline.

The existing SHA AIR, SHA plan, public statement, both original arithmetic
AIR files, packed backend example and Cargo manifest/lock are byte-identical
between those two baseline commits. The
[two-file integration review](independent_review/base_integration_review.md)
checks the actual `proof_config.rs` and `proof_wire.rs` differences: the new
legacy scheduled-SHA component 5 leaves components 1/4 intact. The tagged
profile keeps its own closed component enum, configuration, magic and scanner;
it does not inherit the added legacy selector. This review is internal source
analysis, not an external cryptographic audit.

The first candidate's exact checks remain archived in
[the original gate index](evidence/integration-v1/exact-cfef87ff6-v1-index.json)
and its neighboring compressed archive. They cover 50 repository negatives,
43 source-integrity negatives, ten historical hash checks, 40 budget checks,
six path-extraction checks, 56 Rust tests, and a complete 71-control structural
plus 11-process receiver replay. All 11,585 tracked entries, totaling
1,047,317,375 bytes, were verified against the exact commit before/after and
after replay. Those receipts are not relabelled as later-merge execution.

## Fresh experiment on the integrated code

The new [native-v2-base-sync evidence](evidence/native-v2-base-sync/README.md)
records its measurement state explicitly: HEAD was the first P3 candidate,
MERGE_HEAD was the incoming head above, and the resolved index tree was
`26785a22b3118c718f71c1774dc1c1961db410e9`. This was a resolved, uncommitted
merge snapshot. Actual crate source hashes, the tracked diff, merge/index
identities, binaries and inputs match before and after the frozen experiment.
Later commit identity is established by its own post-commit checks.

The campaign rebuilt with Rust 1.95.0 and no added RUSTFLAGS, used CPUs 0..7
and Rayon 8, and ran the same two fixed inputs in ABBA order. Every execution
freshly prepared the public statement, generated both complete STARK proof
components, and launched an independent verifier. The compared AIRs remain
the same SHA component 1 and packed carry component 4, isolating the hash
replacement from the separate scheduled-SHA optimization.

| Fixture and median measurement | Legacy Poseidon2 | Tagged SHA3-512 |
|---|---:|---:|
| Retained: complete pipeline | 19.158297 s | 8.386623 s |
| Retained: prove process | 17.813407 s | 7.793349 s |
| Retained: independent verifier | 1.270538 s | 0.544260 s |
| Retained: statement + proof bytes | 5,187,252 | 5,435,252 |
| Retained: peak process RSS | 2,036,224 KiB | 2,039,712 KiB |
| Dense: complete pipeline | 19.481059 s | 9.607534 s |
| Dense: prove process | 18.296750 s | 8.299337 s |
| Dense: independent verifier | 1.093916 s | 0.616325 s |
| Dense: statement + proof bytes | 5,186,804 | 5,444,148 |
| Dense: peak process RSS | 2,037,182 KiB | 2,040,994 KiB |

There are two samples per arm per fixture. All eight planned executions passed.
Across the four executions per arm, the observed pipeline medians are
19.378426 and 8.786902 seconds; independent-verifier medians are 1.094783 and
0.544260 seconds. Per-phase medians need not sum to the pipeline median.
The host is shared and all samples remain included. These figures are not
confidence intervals, a worst-case bound or a production/native comparison.

The two campaigns together contain 16 fresh complete W1 executions, each
with two real STARK components. The initial eight and the integrated eight
have separate source/resource records and are not pooled to claim statistical
significance. The input fixtures are preconstructed; mining/search, production
queues, WAN, energy, recursive verification and global hostile costs remain
outside these measurements.

## Integrated validation and executable identities

The merged-source native campaign passed 68 release Rust tests, strict release
Clippy over all targets/features, 71 full-proof structural controls and 11
independent receiver controls. The latter consist of two positives and nine
negative outcomes; their replay generated no additional proofs. The 31
independent role vectors remain part of one of the Rust tests. The original
profile code, frame descriptor, wire limits and vectors are unchanged.

Measured integrated executable SHA-256 identities are:

- Legacy packed backend:
  `e6528d4a10e7f6585f23994c0d4d4bb17653c893114bfd57bfea9afb5147904f`.
- Tagged backend:
  `ddc5b9d20e9c2463690e0b3a1aff2ed781b685efa687501096340b85ded58fe5`.

The final committed candidate must run the focused exact-commit checks again
and compare rebuilt executable hashes with these integrated measurements.
The post-commit receiver replay uses the unchanged native-v1 receiver-control
driver against the materialized v2 proofs and v2 binary identities. The
historical v2 ABBA driver deliberately records MERGE_HEAD and therefore belongs
to the measured merge state; it must not be silently rewritten for replay.

Actual P3 pruned/mixed-height binding, concrete shared-primitive analysis,
Fiat-Shamir knowledge soundness, quantum/advice/lifecycle composition,
recursive AIR cost and production admission remain open as described in the
[security contract](SECURITY_CONTRACT.md).

## Evidence closure correction

A final commit-content check found that the first candidate and the merge
candidate retained native logs on disk while Git ignore rules omitted 32 v1
and 14 v2 indexed log files from their commits. The original failed
[closure observation](evidence/integration-v1/evidence-git-closure-initial-failure.json)
is retained. Earlier source receipts correctly checked tracked bytes; they did
not establish that every indexed evidence file was tracked. Local evidence
materialization therefore did not, by itself, establish published Git closure.

The exact missing original logs are now explicitly tracked. The focused runner
also invokes [the Git closure gate](verify_evidence_git_closure.py): it reads the
index and all storage directly from the requested commit, disables replacement
objects, requires ordinary blobs, checks compressed and original lengths/hashes,
and verifies aggregate counts. Nine focused regression tests cover the actual
ignored-file failure and relevant integrity boundaries. The gate checks both
historical stores without rewriting their observations or source identities.

Four immutable stdout logs contain terminal blank lines. Their original bytes
are preserved; the [cosmetic whitespace observation](evidence/integration-v1/immutable-log-whitespace-observation.json)
records that check failure. The staged diff check excludes only those four raw
log paths, while the Git closure gate verifies every indexed log byte.
