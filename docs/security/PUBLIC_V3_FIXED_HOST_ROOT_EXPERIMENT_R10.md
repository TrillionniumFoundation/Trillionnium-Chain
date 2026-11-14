# Fixed public Host, complete-W1 ROOT cohort: F0 reconstruction

Status: **R11 resource-gate source candidate; native and hosted service acceptance pending**.
This is a separately named finite experiment within the existing pure-PoN
development candidate. It changes no consensus relation, target, work identity,
production authorization, public CPU policy or release gate.

## Why this experiment exists

The original fixed-Host campaign successfully provisioned all nine Host phases,
but passed none of its nine service phases. Its 27 planned confirmations include
nine observed failures and 18 unobserved rounds. None of its six hostile phases
reached actual paid-credit depletion. The subsequent paired Hepta campaign also
left pressure confirmation and depletion open. The complete observations remain
in the [original campaign evidence](../../evidence/pon-131f-native-and-pq-readback-20261028/README.md)
and [paired campaign evidence](../../evidence/pon-hepta-682-pair-host-readback-r8-20261028/README.md).

F0 places the existing complete public phase, including its ordinary History
client, under the original public Host. It places all 24 hostile producer
processes in the separately observed controller service. Each hostile packet has
real accepted full W1 followed by a late M06 state-root refusal. This distinguishes
that work from the original malformed-W1 cohort and from a controller that
accidentally consumes the receiver's own constrained CPU domain. Passing process
placement would not itself pass service, depletion, consensus security or WAN.

## Recovered bytes and new source identity

The frozen base is commit
`74814e17a095f4ad2ce8017fd00a55ac30e08e2b`, tree
`c4a77960e1d8412c04a94631ccfde57d4482c2af`. The earlier F0 source ZIP,
SHA-256 `9852b9d745f64e42c2400824ae376ace77dea97523103158bcdbd538d86aafb8`,
contained nine Python/workflow files, including two original-launcher files that
already matched this base. It did **not** contain the F0 Rust module or design
document. The former local `cf845...` / `364600...` Rust source could not be
recovered. This document and Rust module are a new reconstruction; historical
test counts or unpublished commit identities do not qualify them.

The original `phase` body, ROOT supplement, actor owner and `phase_host::entry`
remain unchanged. The new `root_phase_host::fixed_phase` copies the complete
original phase relation. Its differences are explicit controller placement,
live actor membership, retained scheduled offsets, and a conservative F0 end
clock after observer snapshots. The original request, full-work verifier,
M06 path, budget debit, History import, confirmation, state comparison and cold
reopen remain present. This is a reviewed copy, not a formal Rust equivalence
proof. Future changes to either phase require reviewing both implementations.
R11 additionally records whole-controller-cgroup resources before launcher
creation, at actor readiness before the pressure epoch, and after actual actor
reaping and phase-process exit. It preserves every original pressure-window
sample and adds no runtime extension or resource allowance.

The shared broker receives one separate RAII scope. It transports spawn and
finish requests only; it does not carry Node, State, work, execution or budget
authority. The old broker profile and whitelist still reject ROOT jobs. There
are two new, explicitly ignored entry selectors; ordinary test discovery must
not run an unbounded Host experiment.

## Fixed experiment and denominators

| Item | Frozen F0 value or requirement |
| --- | --- |
| Source | Exact same-repository PR event head and tree; separate source receipts before and after |
| Controller | Unprivileged system service, CPU ceiling `400000 100000`, memory ceiling `17179869184`, Nice 10 |
| Public Host | Original parent `trnmponpublic.slice`, `25000 100000` CPU and `2147483648` bytes; no existing-parent replacement |
| Paid CPU | Burst 2,000,000,000 ns; refill 250,000,000 ns per wall second; original 100,000,000 ns start reserve |
| Work | Raw r14 complete W1; authenticated-v1 state; producer method 0; one M06 worker |
| Preparation | Real signing, Node search, execution and durable reference state; four blocks containing 1,024 seed transfers |
| Phases | Exactly one baseline and one `valid-work-root` phase, each with the original 30-second window |
| Hostile cohort | 24 distinct actual OS children; original 480-call cap; no retry cohort |
| Controller resource gate | Six mandatory real cgroup boundary samples; raw `cpu.stat`, `memory.current` and `memory.peak`; exact controller and live-child identities |
| Honest business | 21 distinct packets per phase, 42 planned packet exposures total; ACK is distinct from confirmation |
| Confirmations | Three rounds per phase, six total, scheduled at 1, 5 and 9 seconds; depth six, neither finality nor execution authority |
| Additional F0 SLO | Strictly less than four seconds from each scheduled offset to completion after the final observer snapshots |
| Outer limits | One native selector invocation, 540-second wrapper; 600-second controller service; 300-second phase services |

Controller ceilings are not reserved physical capacity. The preparation receipt
records actual CPU affinity, logical CPUs, kernel and physical `MemTotal`.
Changing the machine, compilation profile or available resources requires a new
identified observation; the 16-GiB controller ceiling is not a claim that the
runner actually owns 16 GiB.

The workflow writes all six rounds and all 42 business exposures before checkout
or compilation. Native code writes those denominators again before workload
preparation. Missing phases, setup failures, duplicate rounds, failed imports,
late calls and absent reports stay in the denominator. The F0 four-second SLO is
new to this separately identified experiment. It does not rewrite the old ROOT
code as if that code had enforced the same per-round SLO. Time spent in queues,
earlier rounds and observer readback cannot be subtracted by switching to actual
start time. An exactly four-second result fails the strict SLO.

## Placement authority and local threat boundary

An environment string or caller-provided cgroup is not controller authority.
The Rust controller capability is private and cannot be deserialized. Its
construction and reuse check the actual PID, parent PID, process birth ticks,
boot ID, unified cgroup, executable identity, root-owned cgroup inode and both
resource ceilings. The launcher independently verifies its actual parent and
membership before requesting a phase service. The public phase independently
requires the unchanged Host kernel parent.

All 24 actor identities are observed from their actual child handles, then bound
to controller PID, executable, boot, cgroup and ready receipt. The reader counts
distinct observed PIDs itself; a declared `distinct_pids: 24` cannot replace 24
different children. Incomplete membership or a changed identity prevents a
positive F0 result. Both the child readiness check and the controller observation
are retained, including any mismatch.

This assumes a trustworthy local Linux kernel, systemd manager and CI checkout.
The controlled actor programs send hostile wire inputs; they do not represent
24 independent administrators or prove resistance to a malicious local root
rewriting `/proc`, executables or cgroups. Cgroup placement has no consensus or
model authority. Neither this capability nor its JSON observations add a public
authorization mechanism to the chain.

## Actual service and budget acceptance

The baseline must satisfy the original complete-state and confirmation checks.
The pressure phase must additionally contain accepted complete work, M06
admission refusals, signed ROOT replies during each honest round, real overlap,
complete receiver observations and all actual actor outcomes. No hostile packet
may enter live or cold state. Legal counts, tip and state must match the genuine
producer and independently verifying client.

Depletion is a numeric observation of the original paid-credit identity. It
requires debit beyond the original burst-minus-reserve threshold, remaining
paid credit below the start reserve, sound clock/accounting observations and a
depletion sample wholly inside an honest confirmation round. A large reservation,
terminal CPU refusal, zero sample, exhausted actor call cap or nominal controller
load does not establish actual paid-credit depletion. The closed shared domain
must reconcile full settled CPU with observer mutation-owner CPU; overlapping
requests cannot each claim the same global debit. Every missing budget sample
or unknown paid CPU cost required by that reconciliation fails the reader.
This does not imply that every optional diagnostic field is known. In particular,
the original external-actor RSS diagnostic and optional per-actor whole/traffic
CPU fields are not a complete physical-resource or per-actor-cost certificate.

The public Host has 0.25 core while the paid bucket refills at 0.25 CPU seconds
per wall second. This geometry makes depletion assumptions material. F0 keeps
both constants and requires the actual observation; it does not lower refill,
increase burst, fabricate hostile debit or substitute another work primitive.
A failure to deplete remains an informative failed acceptance result. The
[cross-package review](../../evidence/pon-workpackage-cross-review-20261028/README.md)
retains the timely-accounting assumptions and delayed-settlement caveats.

Cold reopen here checks state and absence of hostile packets. It does not replace
the separate budget restart/UNCLEAN-credit tests, real kill-cut matrix, physical
power-loss evidence or all original malicious payload families.

## R11 resource coverage correction

Independent source review found that the retained public-phase
`live_children_rss` helper checks each actor's PPid against the public phase's
own PID. Under the explicitly external actor placement, those real PPids belong
to the controller. The old samples therefore retain `complete: false` and
`sum_rss_bytes: null`; they do not observe a zero memory cost. Each ordinary
50-ms sampling cycle still performs the original process-status and executable
reads under the public Host. This diagnostic was not part of the R10 total gate.

The [retained parser counterexample](../../evidence/pon-f0-controller-resources-r11-20261028/README.md)
uses a synthetic, internally consistent fixture on clean source
`ca4fcb2564c9747a9bd81df4e67bffd1a210634a`. Both actual old reader functions,
`check_report` and `check_f0_placement_and_timing`, accepted it while controller
resource evidence was absent and all 24 RSS rows were unknown. This is an
executed parser counterexample, not a Host, work, resource, or service result.
The older five native controls and 61 Python controls did not cover this gap.

R11 leaves those original diagnostics and the older source evidence intact.
The new mandatory evidence is explicitly the **entire original controller
cgroup**, including its controller, broker, launchers and external producers.
The separately owned public phase remains under the unchanged public parent.
Honest-miner preparation stays outside the per-phase CPU interval; it is already
reported separately. No receiver, honest-submit client, History import,
confirmation or public sampling work moves into the controller allowance.

Every boundary observes the actual controller's boot ID, PID birth, executable,
cgroup inode and exact ceilings before and after its three independent kernel
reads. At readiness, all 0 baseline or 24 pressure actor identities are read
before and after those counters, then bound to the actual Child-derived spawn
manifest and eventual reap results. Missing, failed, replaced, duplicate or
partial identities cannot become an empty/zero cohort. The before-launch and
after-reap snapshots intentionally have zero live actor handles; their complete
phase manifest still contains the expected 0 or 24 distinct, actually reaped
children.

The CPU interval is the difference of actual cumulative `usage_usec` from
before launcher creation through phase exit and actor reaping. The three
observations must be ordered, and CPU and lifetime peak counters must never
rewind within or between phases. `memory.current` may decrease. `memory.peak`
is the whole controller service's lifetime peak, including earlier preparation
and prior phases; it is neither subtracted nor described as per-actor RSS.
Shared pages and controller overhead therefore cannot be attributed to an
individual producer using these group measurements.

All three raw reads, including errors, are retained. Missing `memory.peak`,
unknown counters, impossible current/peak geometry, counter rewinds, identity
drift and inconsistent raw/parsed values fail the native total, both Python
readers and the independent finalizer. There is no fallback to RSS, RUSAGE,
nominal limits, declared counts or a copied positive boolean. Six boundary
observations and the original six confirmations/42 business exposures are
declared before execution. Success would qualify these explicitly scoped group
observations; optional per-actor diagnostics remain separately unqualified.

The resource checks are before or after the original 30-second pressure epoch.
They can consume the existing outer runtime ceiling; they cannot renew it.
Their new acceptance requirement makes R11 a separately identified source
observation. It does not relabel a previous R10 result or improve a throughput
number by removing the original public-phase sampler.

## Cleanup and retained failures

Each created service has a source-bound binary, exact job/prepared digest,
run/attempt/job identity, prior-absence observation, systemd InvocationID, live
PID birth, boot ID and cgroup inode. Both immediate phase cleanup and the always
finalizer require the same live-identity checks before addressing one exact
service. Missing receipts, a replaced invocation or a changed process do not
authorize a unit-name-only stop, wildcard operation or guessed PID kill.

Success from `systemctl stop`, a reaped launcher, an elapsed runtime ceiling or
an empty direct `cgroup.procs` does not prove cleanup. The code reads actual
manager terminal state and `cgroup.events populated`, which covers descendants.
It retains stop failures even if a later readback finds the group empty. The
always finalizer observes/stops the controller first. If controller termination
is unknown, a subsequently empty phase readback is only
`observed_empty_at_readback`; final `known_empty` remains false because the
controller could still create another phase.

Every regular partial artifact, including hidden regular files, is inventoried
and uploaded. Symlinks, special files, changed reads and missing artifacts remain
explicit errors. No source or Host failure is converted into an empty successful
experiment. The one claimed native execution cannot silently be retried.

## Qualification still required

The new source needs strict formatting, exact locked metadata/Clippy, the original
five named native source controls plus two resource-counter controls, and the
actual hosted F0 observation. Python
parser and manager fixtures test rejection behavior; they are not real
systemd kill cuts or network attacks. Native source controls also do not qualify
the real phase workload.

Even a fully passing F0 would close only this finite placement/depletion/service
cohort. Original malicious families and honest requests, restart credit,
complete PQ owners, W1 proving benefit, real model efficacy and independent
multi-day WAN remain separate gates. Production activation remains false.

F1 is **not implemented**. Any incremental History/state optimization must
preserve complete work, original-parent execution, canonical commitments and
atomic publication of a fully validated branch. Snapshot work outside a lock
must bind a versioned owner identity and recheck it before commit; cancellation,
reorg and restart must not publish partial state or refill budget. Such a design
requires a separate source identity and adversarial native comparison with the
complete reference. F0 supplies observations for that decision without changing
the original experiment or claiming a throughput improvement in advance.
