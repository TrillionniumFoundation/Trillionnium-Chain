# W1 rejection-cost v2: four kernels and twelve balanced positions

This is a new diagnostic experiment, declared before its native execution. It
repairs the observation contract after the native driver acquired a fourth
kernel. It does not promote an old observation, adopt a production mechanism,
or change any public-service acceptance budget.

## Retained failure and source boundary

At source `85fdf7233510d6913956a36fa98a9e0a1f2194d3`, the v1 native
driver emitted four kernels and twelve invocations per cohort, but retained nine
samples per group. Its Python validator still expected three kernels and nine
invocations. Native execution succeeding did not make that observation valid.
GitHub run `41750153462`, x64 artifact `13285217854`, retains this failure.
The artifact ZIP SHA256 is
`28fe005dfe5de248da29f7e394b4254ce61fd1094b243789128b95348688c857`;
the original `work-rejection/native.stdout` SHA256 is
`1a879b615d1e3e6c13ea0a7249da3ee641d110f59ae6b26f32063674aeb21a6c`.
Keep those bytes, original build/native costs, and failed validation unchanged.
The same applies to the original ARM and other-source records.

V2 uses distinct raw, summary, execution, and comparison schema versions. Its
validator rejects v1 bytes. Merely changing a v1 schema label cannot satisfy the
fixed twelve-sample and complete balanced-order requirements. The earlier
`pon-structured-cost-v3` collector remains separately versioned.

## Fixed experiment

The work profile remains `pon-matmul-transcript-64-v1`, with the same complete
proof, field, task binding, full transcript, progress callbacks, and error
semantics. There are four matrix classes, two existing target values, and twelve
samples per class/target group: 96 cohorts in total.

| Kernel index | Observed kernel | Role |
|---|---|---|
| 0 | `retained-transposed` | Retained earlier implementation |
| 1 | `scalar-reference` | Full reference implementation |
| 2 | `limb-transcript` | Limb transcript with original correction path |
| 3 | `production-full-limb` | Actual production verifier and ratio denominator |

Each cohort measures the same three complete proof variants through all four
kernels: legal, same-target transcript rejection, and final-cell product
rejection. For position `p` and sample `s`, the arm is `(p + s) mod 12`, the
variant is `arm / 4` with integer division, and the kernel is `arm mod 4`.
Twelve samples therefore place every variant/kernel arm in every invocation
position exactly once in each complete group. A complete campaign contains
1,152 timed verifications and 96 independent full scalar winner replays.

Do not remove an exhausted or failed acquisition. All 4,096-attempt search
limits remain fixed. An exhausted group stays incomplete, with its observed
acquisition and mutation costs retained. Do not fill missing observations,
select successful repeats, or infer success from the native exit code.

## Costs, identity, and original limits

Retain actual setup, reusable preprocessing, every failed and successful proof
and ticket attempt, search recording overhead, honest acquisition, mutation,
timed verification, and separate progress probes. Keep the complete native
stdout/stderr and binary. Native process wall time includes serialization and
the untimed probes; it is distinct from summed verifier timings. Keep actual
compiler/tool identity commands and build logs/costs. Record the outer validation
and total experiment wall time with the execution evidence; do not represent
the inner verifier timer as total deployment, loading, recovery, CPU, or energy
cost. Those unmeasured product costs receive no qualification here.

Use the original pinned Rust 1.95.0 release/native-target build, with no profile
or compiler overrides. Identity commands retain their 30-second limits, build
its 900-second limit, and native execution its 180-second limit, with the
existing output bounds and five-second process cleanup grace. Preserve failures
and actual termination state at every stage. The source inventory includes
this plan, the complete native inputs, collector, scalar oracle, and controls.
Hosted receipts require unchanged, fully materialized committed source; a
sparse local diagnostic cannot supply that qualification.

The independent public-service gate remains 4 seconds, 25% of one CPU, 2 GiB,
256 PIDs, seven honest submissions, and sixteen attack producers. This
experiment changes none of those values, History deadlines, or the frozen
Chain `78d13ecb327a95609429082b05b42c19751cd2c2` / Hepta
`5b00b3aac4d4fd0d26d07436886748c0425e33e5` pair.

## Required observations and interpretation

Retain all three original native example controls and all 87 original Python
controls. Add explicit rejection controls for v1 raw and receipt schemas,
nine-sample relabeling, omission of the production arm, and the former production
label. Check the production denominator independently with distinct fixture
costs. Synthetic control durations never become performance observations.

Before accepting a new record, verify the real native raw output: four exact
kernel identities, twelve samples, 96 cohorts, 1,152 ready timed verifications,
all twelve invocation positions for each arm, and all 96 independent scalar
winner replays when no acquisition exhausts. Also apply the v2 validator to the
unchanged retained v1 raw file and to an in-memory schema-only relabeling; both
must fail. Preserve the original file digest before and after those checks.

Cross-architecture comparison requires x64 and ARM64 executions at the same
actual source/run/attempt, with matching deterministic complete proof, ticket,
search, error, progress, and order streams. Report separate hardware costs and
full retained failures. Local diagnostics do not substitute for this pair.

The five acceptance/activation flags remain false. Valid diagnostic accounting
can support later adopt, revise, or decline decisions; it establishes neither a
fastest adversary nor a hardness lower bound, worst-case rejection, public
service SLO, or production activation. No performance adoption is decided by
this contract repair.
