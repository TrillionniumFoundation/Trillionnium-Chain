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
metadata stayed unchanged. This is a component counterexample, not a complete
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

The corrected native and source checks will be recorded against the final
source. Baseline failure, correction checks and any unexecuted isolated-native
qualification are separate observations. No prior run is transferred to the
changed source. Full model/runtime closure, public WAN, full-state rollback,
independent operators and production activation remain unqualified.
