# ArithmeticFactCache local implementation comparison

This is a selected-source, single-host diagnostic. It is not a whole-workspace
build, the original fixed-Host service campaign, an attacker-cost estimate, a
work-hardness lower bound, or production qualification.

The baseline restores `pon_work.rs` and every tracked child module from
`7c5caf5bce1396976808a0f504c4163fbc1aed44`. The candidate snapshots the current
working source. `build-manifest.json` identifies every source byte, compiler,
manifest, lockfile and executable; only `arithmetic_facts.rs` and its new
test-only FullLimb controls differ between these source sets.

Both standalone harnesses use exactly the same `main.rs`, four exact direct
dependencies and identical resolved lockfile. Every registry version and
checksum matches the original workspace lock. Each harness has its own checkout
and target directory. Builds use Rust 1.95.0 with the unmodified Cargo default
release profile, `--locked --offline`, and no compiler/profile overrides.

The executable runs three fixed dense-material seeds, eight cases, and 128
measured calls per seed/case. Three fresh-process rounds use the recorded order
baseline/candidate, candidate/baseline, baseline/candidate. Repeated rounds are
not additional independent material samples. The capacity-one eviction case
alternates two distinct challenges: every entry misses, but the challenges are
not globally unique.

The fixture target is all `ff`, so no ticket search is being measured. Valid
proof construction and independent reference checks have separate fixture CPU
and wall intervals. Cache allocation and prefill have separate case setup
intervals. Prefill costs are not silently added to or excluded from an attacker
denominator: **there is no attacker-cost measurement here**.

The timed region contains native `verify_with_observation`, the fixed loop and
preallocated outcome retention. Every complete result is subsequently checked
against the reference challenge, task, ticket and full product; invalid results
must have exactly the expected error. Cache observations must match the intended
cold, warm, trace-only upgrade or eviction path. These checks and JSON output
occur after call timing. `ClockId::ThreadCPUTime` measures the actual calling
thread; wall time includes scheduling. No subtraction of a guessed clock or
loop overhead is performed.

`summary.json` retains all paired per-round and per-seed ratios. For each cold
path, the candidate/baseline CPU ratio is below one when the three seeds are
aggregated within each of the three paired rounds. This does not mean every
individual seed pair improved: `cold_false_trace` has 1 of 9 seed pairs above
one (maximum **1.046793744458546**, round 3, seed 7), and `cold_valid` has 2 of 9
above one (maximum **1.1639442552585306**, round 1, seed 43). The warm-valid
three-seed aggregate ratios, in round order, are **1.21806147142079**,
**1.0848743876577889**, and **0.9114152591545132**; these do not establish a
stable speedup. Other warm observations also vary and include regressions.
There is no uniformly-faster or public-service completion claim. All six raw
JSONL streams, stderr files, exact commands and pre/post source readbacks remain.

`selected-source-and-executables.tar.xz` contains both complete selected source
trees, manifests, lockfiles and the actual measured executables. To reproduce
from that archive, extract it in a new writable directory, build each package
with its own target directory using Rust 1.95.0 and `cargo build --release --locked
--offline`, then run each executable with arguments `baseline 1` or `candidate 1`
and continue the recorded round order. Registry sources must already be present
at the exact locked versions. Absolute paths in the preparation scripts describe
the captured execution environment, not portable workspace identity.
