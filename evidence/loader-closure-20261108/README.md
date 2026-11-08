# Actual material reader and static execution closure, 2026-11-08

Status: **RESEARCH / HOLD / NO-GO**. The [V2 contract](../../docs/security/M15_STATIC_EXECUTION_CLOSURE_V2.md)
states the supported native closure and the capabilities that remain unsupported.

## Retained original failure

The base is `8d8f05566b2a1612a3bf4a6c6c71635df454d397`. The
[test-only patch](baseline-test-additions.patch) adds one real-reader regression
to each continuous/mining policy module. The
[baseline source hashes](baseline-source.sha256) identify the two original
implementation files and the two test files as executed. Two newly written
environment modules had not yet been declared as modules and were not compiled
in this baseline.

The offline attempt did not execute tests: the cache lacked `nix`. The online
attempt completed compilation and executed both regressions. Both failed:
the old reader returned SHA-256
`02c9a68f567b8ec215d893cde67ae2da41ba3c9b838d0ba4d3d04ab3cdc58da6`
instead of
`1566ccd537d00b47da815ef976d5fcefaa69cc45ec562c2ef99f9b3404d05e43`.
Only the shared file cursor was changed; file bytes, path identity, length and
the retained identity metadata stayed unchanged. This is a component counterexample, not a complete
authenticated production launch.

Retained outputs:

- [Offline stdout](baseline-cursor.stdout) and [stderr](baseline-cursor.stderr).
- [Executed baseline stdout](baseline-cursor-online.stdout) and
  [stderr](baseline-cursor-online.stderr).
- [Machine-readable terminal outcomes](baseline-outcomes.json).

The baseline also retained the actual SQLite build warning that `RUSTC` was
not absolute. That warning is not reclassified as SQLite qualification. The
reader regression does not open a SQLite store. Final checks use the actual
absolute Rust compiler and its toolchain library directory; they do not
disable the SQLite fence or alter its original build contract.

## Verification scope

The source repair keeps the original resource checks and adds positional reads
plus a streaming comparison to the authenticated material digest. Static
execution profile V2 adds explicit provider controls before authority access,
secure-execution refusal, one non-executable stack declaration, no text
relocations and fully file-backed executable segments. V1 stored records retain
their original validation/digest interpretation, while new/current execution
requires V2 and a new signed configuration through the existing authority.

## Frozen source and terminal results

The source published for review is
[`059e149ccf683a69e6dad4e7f5a21fdd76b671fc`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/059e149ccf683a69e6dad4e7f5a21fdd76b671fc),
tree `c9ea28106d0dfc33f9edb04d396e6e3c6f8783ba`. Its full tree is identical to
the original local source commit `0bc39741809c8987018523ce3b2827604403a2f1`.
The [alignment record](source-alignment.json) retains that check and the guarded
reference update. Tests were recorded again against the published source SHA;
the earlier local observations are retained separately.

The existing `record_pq_native_command.py` verifies every tracked raw byte
before and after every command. Each source set contains 15 complete command
receipts. All 30 observations bind the same full tree and retain
11,094 tracked entries / 1,115,140,162 bytes. The containing evidence publication
adds observations and prose; it does not relabel these executions with a later
commit identity.

| Published-source observation | Terminal result |
| --- | --- |
| Original continuous/mining policy and complete non-ignored M15 library groups | **67 passed, 8 failed, 1 ignored; Cargo exit 101** |
| New reader, environment, legacy-digest and ELF regressions | **12 passed**, included in the 67 above |
| Thirteen source/static commands | **13 passed** |
| Negative/source/recorder Python cases | **155 passed**: 56 + 37 + 15 + 43 + 4 |
| Exact corpus / repository / embedded inventory | **721 pins**, 3,668 local links; inventory current |
| Locked Cargo graphs | Default **176**, all features **181** packages; **26** workspace members each |
| Whole-workspace, all-target, all-feature Clippy with `-D warnings` | **Exit 0**, with the corrected explicit toolchain environment |
| Full isolated ordinary M15 consumer | **Ignored / not executed** in this observed suite |

The 12 new regressions include actual positional material consumption with a
shared cursor changed between chunks, digest/limit/cancellation/path-replacement
refusal, the exact six-entry process environment, secure-execution parsing,
old signed configuration digest preservation, V1 current-execution refusal,
one non-executable stack and both text-relocation encodings. The known legacy
configuration is still 1,845 canonical bytes and retains digest
`4eda981573772152dffe3b3066f1c4d3a8793bffe6946a0e6a9e12eface8cf1a`.

### Eight service failures remain failures

All eight `release_owner::service_tests` fail inside the unchanged
`service_test_fixture.rs` at `UnixListener::bind`, before the fixture starts its
clock service. The [actual socket diagnostics](socket-probes.json) narrow the
boundary: `socket(AF_UNIX, SOCK_STREAM)` itself returns `EPERM`, before binding
any pathname. Fresh 0700 directories owned by the current UID under `/tmp`,
the working area and `/dev/shm`, plus the abstract Unix namespace, have the same
result. An ordinary loopback TCP socket can bind and listen. Changing the
temporary directory therefore does not repair the missing Unix-socket ability.

The process reports `NoNewPrivs=1` and `Seccomp=2`; the particular policy rule is
not identified by those facts. A [trace attempt](service-socket-trace.stderr)
was itself refused at `PTRACE_TRACEME`; no syscall trace of the test is claimed.
No permission or test semantics were weakened, and TCP was not substituted for
the Unix transport. These eight tests need their original environment with
`AF_UNIX` support before service qualification can pass.

The [hosted coverage readback](hosted-coverage.json) binds the existing workflow
and recipe bytes. `trnm-required-baseline.yml` runs the retained full workspace
test command in its runtime shard; `pon-pq-system-continuation.yml` also runs
the complete original Node library. Both commands cover these eight ordinary,
non-ignored tests. This is source-level coverage, not an observed hosted pass.

### Toolchain warning is retained separately

The initial local strict Clippy command returned 0 but emitted a real SQLite
`UNQUALIFIED` warning: the Cargo-home Clippy shim selected a different sysroot
from the explicit compiler. The [direct shim diagnostic](clippy-sysroot-diagnostic.json)
records both actual sysroot results. The final published-source Clippy command
sets `RUSTUP_HOME` and `RUSTUP_TOOLCHAIN` explicitly in its recorded argv, aligning
the shim, compiler and loader library directories. It returned 0 with no warning
or `UNQUALIFIED` line. The original warning is retained in the local-source
archive; the checker and source were not changed to obtain the corrected run.
The [execution environment](execution-environment.json) retains compiler/tool
hashes and the exact relevant overrides. Original optimization settings and
resource limits were unchanged; this is not a new resource qualification.

### Raw records and readback

- [Verification summary](verification.json) preserves each command outcome,
  all eight failed identities, the ignored identity and all 12 new passing tests.
- [Local-source archive](local-source-observations.tar.gz) preserves all 15
  original receipts and logs, including the first strict-Clippy warning.
- [Published-source archive](remote-source-observations.tar.gz) preserves all 15
  final receipts and logs, including the failed native suite.
- [Archive and per-file hashes](observations-index.json) bind every original
  receipt/log byte; the summary was recomputed from these archive contents.
- [Initial fixed-source stdout](initial-fixed-native.stdout) and
  [stderr](initial-fixed-native.stderr) retain the preceding actual compilation
  and native probe, separately from both official recorded suites.

Full model/runtime closure, public WAN, full-state rollback, independent
operators and production activation remain unqualified. Passing components do
not turn the failed full selected suite or the unexecuted isolated consumer into
acceptance.
