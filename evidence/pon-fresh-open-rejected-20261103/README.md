# Rejected fresh-open component candidate

**Research only; no production patch adopted.** This checkpoint preserves a real
small experiment that did not justify further production testing. It does not
qualify the fixed public Host, a complete Node build or any service gate.

The existing production `host_kernel_parent.rs` had SHA-256
`6f4cf524831e8af8e23c954764e388d6d167f125c3de0dd19ce235630ce7df7d`
before and after this experiment. That source is present in owner
`12171edc890df1611bf68503038bfad3d66a5a88` and the earlier observed
`116a3caf6046dd0db3caf1d0797e636c35c877b8`. The candidate only prepares
CString pathnames and uses a fresh `rustix::fs::open` for each observation,
then invokes the original complete-read functions. It retains no descriptor,
content or Host verdict. No production source was modified.

## Actual experiment

The original file-open path and candidate ran in 16 paired ABBA groups, four
slots per group, 128 repetitions and seven paths per repetition: **57,344
actual fresh reads**. The paths are the current container's boot ID, actual
calling thread's cgroup membership and five current cgroup limit files.
All compared bytes matched. These container cgroups are not the approved
public Host parent; this is a component experiment only.

Rust 1.95 compiled the preserved component source with the exact existing
dependency rlibs recorded in `RECEIPT.json`. Compilation and execution exited
zero. The complete command, compiler/dependency/source/binary hashes and raw
output are retained. The harness uses boxed errors in place of the Node's full
error type; it does not run the complete native semantic regression suite.

| Decision input | Observed value |
| --- | --- |
| Median paired candidate/original calling-thread CPU | 0.984894554063932 |
| Empirical p95 paired ratio | 1.4616457572731536 |
| Median threshold used for further testing | At most 0.95 |
| p95 threshold used for further testing | At most 1.0 |
| Selected for production testing | **False** |

All pairs remain in `DECISION.json`; no outlier was removed and no rerun was
selected to replace this result. Total measured calling-thread CPU was
107,811,045 ns and measured wall time was 111,818,201 ns. This observation
does not demonstrate a service speedup or a complete-path regression.

## Reproduction and limits

`build_and_run.py` is the exact executed script. Its absolute scratch paths and
preexisting dependency rlibs describe that actual environment. Recreating it
elsewhere requires the same pinned source and compiler/dependency artifacts,
then explicit path relocation; this checkpoint does not claim a portable,
self-contained Cargo build. `observed_production_reader.rs` retains the exact
compiled generated source, including the original complete-read implementation
and the additional component probe. `main.rs` and `probe_addition.rs` retain
the independent handwritten inputs. The executable itself is reproducible and
omitted; its actual SHA-256 is preserved.

The separate original CPU matrix remains bound to its own `116a3caf` source.
Four-second/16-hostile, F0 and 30-second campaign failures remain failures;
none is replaced by this tiny probe. All activation and acceptance flags stay
**DRAFT / SHADOW_ONLY / DENY_ALL / HOLD_NO_GO**.
