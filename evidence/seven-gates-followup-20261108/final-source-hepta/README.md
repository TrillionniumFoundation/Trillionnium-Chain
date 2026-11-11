# Hepta 36d5 / Chain bb026: fresh original 39 + 3 native controls

## Result and scope

The second native attempt executed the original 39 learning controls and the
original 3 direct-owner controls successfully on Hepta
`36d5eff44f4071bb1f250b1c7706dc690cf0a875`, tree
`077347454d7517f8f5e16cd2dfc0f6a1c502109d`.

The fixed paired Chain input is
`bb026697a972521009bc133ae6ed2b653e18e931`. This Hepta wrapper verifies the
Hepta worktree. The paired Chain SHA is an input label; Chain's own source and
native execution require their separate records.

**Component result: PASSED_ENGINEERING_CONTROLS. Overall qualification: HOLD_NO_GO.**
No result from Hepta `4a93aaf` or `ed1ea569` was accepted as a pass for this source.
The old checkout and target were read as preparation inputs; a separate checkout
and target were used for this attempt. Cached build products are not provenance.

| Fresh native step | Exact cases | Native exit | Nextest run UUID |
| --- | ---: | ---: | --- |
| learning39 | 39 | 0 | `41002e4d-1303-453a-8a3c-dd2dbd4e4ca1` |
| direct3 | 3 | 0 | `4b997023-0fb3-448f-bfc5-7c51565146aa` |

Both retained JUnit files match their original name rosters exactly, contain no
failure, error or skipped case, and match the fresh UUID recorded in their native
stdout. The collector exited 0. The source was verified before execution, after
each native step, and at the end: 11,191 tracked entries, 150,824,608 tracked bytes,
and 20 discovered lockfiles. The full raw tracked-manifest commitment is identical
across those observations. No ignored or untracked files remained in the source.

The observed native test executable candidates and their hashes are retained.
They are not an independently observed exec or library/provider load closure;
`complete_build_load_closure_verified` remains false.

## Retained failures and recovery

The failed observations are included unchanged, before the successful attempt:

1. **build-01 exited 2, with no native test execution.** The build-only preparation
   added `--no-run`; the original `just test` recipe adds `--no-fail-fast`, and
   installed Nextest 0.9.103 rejects that combination. Full source observations
   before and after were unchanged. The preparation was not counted as a test.
2. **native-01 exited 99.** Its learning39 command exited 0, but Nextest wrote
   `codex-rs/target/nextest/local/junit.xml` into the source. The strict collector
   rejected that untracked output. All tracked source bytes still matched. The
   direct3 step was not executed, and this attempt remains BLOCKED_OR_FAILED.

The first JUnit, its identity, the mismatch observation and the relocation
manifests were retained before the generated file was moved out of this task's
source directory. No tracked source, source pin, test list or collector policy
was changed. A new complete 39 + 3 attempt was then executed.

## Configuration and resource contract

The repository's original `nextest.toml` is retained separately as
`hepta-nextest.toml`; its SHA256 is
`63f832eabf890a5f3cd7c0e4ee1856b1ca99d4db8952de71b81282265668dc8c`.
Profile `local` inherits the original ordinary watchdog of 30 seconds multiplied
by `terminate-after = 2`, and the original `retries = 1`. No timeout was extended.

The second attempt added only the supported `--tool-config-file` option. Its
external TOML contains only `[store].dir`, pointing into `native-02/nextest-store`.
The original repository configuration has higher priority. The actual generated
JUnit files were observed at that external location and retained stably before
being parsed. The config contents, hash, command delta and fresh artifacts are
in the archive. This option selects the original `run-nextest.py` full-metadata
branch; that behavior is recorded rather than hidden.

Installed help and upstream configuration implementation for the installed
Nextest commit `d2e7b879fb79975e8b47a8e3ce569b651e6381c0` support this output
setting. The exact upstream source files and URL/hash manifest are retained in
`nextest-version-source/` inside the archive. No newer Nextest behavior was assumed.

The actual cgroup and systemd readbacks, both before and after the native steps,
show 8,589,934,592 bytes of memory limit, `cpu.max = 200000 100000`, and Nice 10.
Rust/Cargo 1.96.0, just 1.51.0 and Nextest 0.9.103 were used, with their binary
hashes retained. The runtime job requested a 5,400-second supervisor timeout;
systemd itself reported `RuntimeMaxUSec=infinity`. Full equivalence to the old
outer service watchdog is therefore not claimed.

The successful second attempt used the target built during the first native
attempt. Its command wall times and memory peaks are observations for a warm
target, not a goodput, tail-latency or performance qualification.

## Files and integrity

- `hepta-36d5-bb026-native-controls.tar.xz`: 1,020,840 bytes, containing 80 files.
- Archive SHA256:
  `df4cbe229cc78a06435dda2824fcdaea93cec40c3f39308e996ee955ef562d4a`.
- Internal `raw-evidence-index.json` SHA256:
  `0f818a2a0de03eccf96ebb6cd56be91485042d7115c596bf293d89764029aa3f`.
- `summary.json`: machine-readable result, exact cases/UUIDs, source/lock pins,
  resource observations, configuration delta, failure history and limitations.
- `tool-receipts/`: retained launch and terminal-status observations for both
  failures, the successful attempt, and the archive transfer.
- `SHA256SUMS`: hashes for the publishable files alongside this README.

The archive contains original runners and rosters, all wrapper versions including
the review-before v1, original stdout, fresh JUnit, full tracked-source manifests,
configuration, failed results and recovery records. Its SHA256 and all 79 file
entries in its internal manifest were independently verified after transfer.
The fresh JUnit IDs, names, failure/error/skip absence, source commitments and
memory/CPU limits were also checked from the transferred bytes. These are
artifact-integrity checks, not another native test execution.

Real training, independent evaluation, real payment, installation and subsequent
adoption, WAN cold recovery, complete executable/provider loading, the consensus
joint model, and whole-chain PQ composition/independent review remain outside
these component controls. All qualification and actual-model/final-use claims
remain false.
