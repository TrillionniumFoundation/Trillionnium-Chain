# M15 cold replay and full native follow-through

## Source and result

The tested source is `1c14fab4cca9c2ad1a48c502f51eb89edeb7df50`, tree
`cd446a4dc02d94f446134e9fd441bab04a672a2c`. This evidence-only successor
does not imply a new execution. The actual source bodies, original frozen
inputs, compiler and OpenSSL provider were checked before and after each phase.

Publication preserves concurrent parent `83bb1c4e` and its
[separate admitted-source and checkpoint evidence](../pq-migration-recovery-20261107-e1dee/README.md).
Those selected native results bind `2c51e15e`. They are not combined with this
`1c14fab4` complete run to claim a complete test of the later composition.

| Observation on this exact source | Actual result |
| --- | --- |
| Targeted M15 root and sealed-object controls | 14 passed; 14 original execution readers accepted |
| Complete Node library, all features | 1,249 passed; 0 failed; 33 ignored; 1,282 registered; 991.36 seconds |
| Subsequent original ignored cost cases | 3 Node cases and 1 MVCC case passed individually |
| Original continuation command records | 29 commands exited zero across cost, CPQ1, C and SDK phases |
| NPQ6 migration integration binary, default features | 3 passed; all 3 original execution readers accepted; 13 command records exited zero |
| Strict Clippy | Library and tests passed with all features on the native host; default features passed locally |
| Local source controls | Workspace format, 690 exact blob pins, 38 negative controls and clean repository integrity passed |

The complete-command aggregate remains 33 ignored. Its three subsequently
executed Node cost cases are separate observations, not additions to the 1,249
count. Nested subprocess summaries are not counted as outer library tests.
The original 14,400-second outer allowance was retained for the continuation.
The complete-library phase used a **new, stricter 1,500-second outer cap**;
that cap was not the original complete-run allowance. No retry or per-command
timeout was added, and no profile, concurrency or original load was relaxed.

## Repairs and controls

The original frozen `840522d` complete run failed: **1,242 passed, two failed,
33 ignored**, in 1,128.94 seconds. Its complete log and command records remain
in the archive as a failed observation.

The production repair decodes the existing root role strings through serde's
internally tagged proof representation. Only decoded role keys 1 through 4
are accepted; duplicate, unknown and aliased keys are refused before insertion.
The signed serialization, role/quorum checks and exact record re-encoding
requirements are unchanged. Three new controls cover every tagged proof
boundary, malformed maps and root/canonical-record requirements.

The other repair is test-only. A denied memfd write can advance mtime/ctime
while retaining identical content and seals. The positive source-replacement
check now runs before denied writes. Separate real-kernel tests verify unchanged
bytes/seals and rejection of changed metadata at read, copy, descriptor and
executable handoff. Production sealed-object identity checks were not weakened.

The local pre-fix build received SIGKILL before running a test; its raw failure
is retained without asserting an OOM cause. The first remote source packaging
attempt refused a borrowed Git object store before any Rust command. A fresh
independent clone passed the unchanged guard. Neither failure is a passing test.

## Evidence and executable identity

`receipt.json` binds the observations and archive hashes. Each archive contains
its own per-file SHA-256 inventory. `targeted-and-complete-native.tar.gz`
contains 89 raw records, including original failures, actual Cargo JSON build
identity, registry, native logs, command records and independent reader outputs.
`local-quality-and-failed-build.tar.gz` retains local quality and failed-build
records plus the local diagnostic. Large retained executables remain on the
native host; their hashes and file identities are in the raw command evidence.

`original-continuation.tar.gz` holds 71 further records for the original cost,
CPQ1, C and SDK commands. CPQ1's reader recomputed 22,528 raw sample values
across 352 measurement rows and 32 cases, each with 64 samples. Reservations
are not mathematical signature-verification counts, and its reader is not an
independent hardware execution attestation. The C and SDK results are bounded
primitive/metadata interoperability, not full deployed updater qualification.

`hosted-gate-failures.tar.gz` preserves 400 hosted job/report records from the
four failed lanes, including their actual measured outcomes and source bindings.
Its inventory binds the original four GitHub ZIPs and the thirteen ELF copies
excluded from this smaller evidence archive; their complete hashes remain.
No failing report has been converted into a passing observation.

`migration-and-exporter-native.tar.gz` contains 61 sealed records. The three
migration cases ran on the exact `1c14fab4` source with their unchanged CI
commands and default features. Their independent integration-test ELF is
204,623,560 bytes, SHA-256
`6505b61a0a252a599147cdbf120f63f5d0af7ac44477c39fd9558b02315efa55`.
The archive also retains the exact `840522d` exporter build and registry,
two zero-native preparation refusals and retained CLI loader observations.
This is **build-only exporter evidence**: no fresh export or paired Hepta
consumer ran in that phase, and the original 300-second freshness was unchanged.

The all-feature executable here is the **library test harness**, not an ordinary
CLI: target kind `lib`, source `src/lib.rs`, 458,139,952 bytes, SHA-256
`69fac051c35677c9acddbbf83df28d71f53fc6dfd0a4822d653bd89adf5ce295`.
Independent external-CLI and Hepta compositions require their own exact source,
actual `bin` artifact and execution evidence.

## Remaining release gates

The separate [hosted baseline run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42323049446)
does not pass as a whole. Its protocol and both architecture cost lanes reached
the actual original from-zero confirmation test: named invariants passed, but
the four-second, sixteen-worker pressure window did not finish independent
business confirmation. Seven submit ACKs are not an independently confirmed
transaction. The strict `CONFIRMATION_TARGET` refusal is retained.

The hosted runtime shard separately reported 352 data-availability tests passed
and one failed: `fixture_setup_wait_preserves_original_tcp_announcement_budget`.
After setup completed, its first announcement returned WouldBlock after about
205 milliseconds. This is not covered by the passing Node library command.
These hosted failures do not alter any earlier raw result or qualify production.

The original lineage still has its previously recorded signoff exception:
`b1e7904bcec97688dcb21d681d79a27f728a5ee6` has only the Codex trailer, without
the required Franksudoman trailer. This receipt does not certify DCO across the
concurrently imported history. The history has not been rewritten. GitHub
also continues to report the PR dirty even though its actual base is an ancestor.
No protected-main bypass, self-approval, force push or activation is authorized.

Deployed legacy balance/nonce/liability/ownership migration, independently
operated custody and freshness, whole-directory rollback protection, public
WAN confidentiality, complete quantum work/DAA/fork/proof qualification and
release acceptance remain open. The result is **HOLD / NO-GO**.
