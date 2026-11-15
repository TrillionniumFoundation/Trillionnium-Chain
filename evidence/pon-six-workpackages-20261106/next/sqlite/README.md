# SQLite build-fence cache recovery

The original `0ca272d09d1522b0ffd740e441b6d3de1ed81de6` build script could
return from loader-path qualification before registering its `RUSTC` environment
watch. A relative compiler path correctly refused qualification, but the same
Cargo cache retained that refusal after the caller supplied the real absolute
compiler path. Both commands returned Cargo success because an unqualified
optional boundary is deliberately supported; Cargo success alone was not the
qualification verdict.

The repair registers common environment inputs before any fallible check. It
does not relax loader paths, source/ABI pins, symbol verification or the build
fence, and it does not certify dependency build provenance. A previously refused
environment must run the complete qualification again before emitting the cfg.

## Actual observations

| Control | Result | Scope |
|---|---|---|
| Original source: relative then absolute `RUSTC`, same target | Both unqualified; build output and timestamp unchanged | Reproduces stale refusal on the original source. |
| Repaired source: relative then absolute, same target | Refused, then qualified | All original qualification checks remain. |
| Fresh target, four real Cargo invocations | Refused → qualified → refused → qualified; four expected outcomes | No source edit, cache clean or target replacement between phases. |
| Existing SQLite transaction-scope library tests | 13 passed, zero failed/ignored | Actual writes, prepared statements, ABA, rollback and sticky refusal controls. |
| Existing finite public-API process controller | Failed | All ten child attempts retained; the child cannot resolve its actual PID identity through this environment's `/proc/<pid>`. |
| First held-directory invocation | Failed | Original AS/FSIZE were not set, and an unscoped selector also invoked the child harness without its environment. This is a retained invocation error. |
| Corrected exact held-directory controller | Failed | Original hard/soft AS=3 GiB and FSIZE=16 MiB applied; all four child attempts still refused missing kernel start identity. |

The independent environment probe observed `getpid() = 5`, while
`/proc/self/stat` identified PID 29386 and `/proc/5/stat` did not exist. The
original controller checks were not changed to accommodate this mismatch.
None of these attempts qualifies public-service process ownership or recovery.
The enclosing local cgroup has 8 CPUs and 8 GiB, separate from the original
quarter-CPU/2-GiB service profile.

## Reproduction and retained bytes

[The archive](raw.tar.gz) retains every original build output, stdout/stderr,
command/cost record, failed child directory and environment probe, plus the two
initial observation drivers. [The index](index.json) lists every member's exact
byte count and SHA256. The archive was decoded and checked against that index.

The permanent [native cache control](../../../../scripts/ci/check_sqlite_build_requalification.py)
requires fresh absolute output and target paths and real pinned compiler paths:

```sh
python3 scripts/ci/check_sqlite_build_requalification.py \
  --output /absolute/fresh-records --target /absolute/fresh-target \
  --rustc /absolute/pinned-toolchain/bin/rustc \
  --cargo /absolute/pinned-toolchain/bin/cargo
```

The locked dependency graph must already be available: the control uses offline
Cargo. Other build environment values are retained, so a separate invalid input
continues to fail rather than being silently stripped. The CI step preserves
the original native selectors and records the new cache control separately.
Its output does not count as a SQLite operation, complete Cell proof or original
resource acceptance.
