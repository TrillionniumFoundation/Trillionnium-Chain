# Fixed Host, scalar accounting and the original campaign

This is an implementation applicability analysis, not an observed network
attack, a scheduling proof or a replacement acceptance criterion. Pure PoN work,
weight, complete W1, original deadlines, CPU constants and service predicates
are unchanged by this candidate. WP2B remains HOLD.

## Source-bound parameters and the observed blocker

`trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs` defines a
2,000,000,000 ns burst, 250,000,000 CPU ns/s refill, 100,000,000 ns start
reservation and at most two mutation owners. `config/systemd/trnmponpublic.slice`
defines 25% CPU over a 100 ms period, 2 GiB memory, zero swap and 256 tasks.
`host_kernel_parent.rs` requires the original root-provisioned fixed parent,
zero `cpu.max.burst`, the current calling thread's actual membership and finite
limits. The observed kernel quota is 25,000 microseconds per 100,000 microseconds.

The prior hosted source `73ffdd94f0b5461a2217a197a3d03a55b37117d5` ran its
original finite campaign under a different 400% / 16 GiB controller cgroup. The
receiver was a thread in that controller and its History verifier was another
Node in the same process. The 24 attackers were separate processes. All 576
History imports across three runs and three modes failed
`PUBLIC_HOST_KERNEL_PARENT`, including the no-attacker baseline, before paid
History W1. This is a process-placement failure, not evidence that paid History
continuation failed. The raw unsuccessful campaign is retained by
[the original hosted run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40605070418).

## Explicit placement correction

The `fixed-public-phase-external-actors-v1` test placement runs the exact original
receiver and verifier inside a separately launched phase process under the same
fixed public parent. It leaves the honest producer, producer-cost experiments,
controller and all attacker processes in the original 400% domain. Only a finite
lifecycle broker crosses that boundary. It cannot admit a block, modify CPU
credit, evaluate work or replace an original signed response.

The controller owns and reaps every actual attacker `Child`. The phase owner
sends the original job and receives its actual PID; immutable job files, raw
actor outputs, real cgroup paths, kill/reap outcomes and absolute cleanup
deadlines remain observable. No attacker is accidentally slowed by inheriting
the public 25% parent. The original 3 modes, 30-second windows, 24 attackers,
480-attempt cap, 1/5/9-second honest schedule, 21 signed business blocks,
64-History-call ceiling, all confirmation requirements and genuine-depletion
predicate remain unchanged. The source opts into this placement explicitly.
An old local invocation has its old placement and cannot claim fixed-Host
qualification.

The launcher performs no compilation. It binds the already built native ELF,
the original complete packet inputs and the exact ignored phase selector. It
records fixed-parent identity, limits, privileges and actual membership before
and after execution. A 300-second outer process ceiling prevents an abandoned
systemd phase from living indefinitely; it grants no extra business time. The
original complete-campaign 600-second outer ceiling remains in force. Setup,
native failure, timeout and cleanup failure are retained separately. Local
parser/broker tests cannot qualify this actual hosted placement.

## Distinct four-second hosted confirmation counterexample

The later `fc23fa6de10380dd9ce9cae6cddd1db4d87551ce` candidate separated original
compilation preparation from runtime. Its four hosted from-zero lanes each
completed all five original named tests under the fixed Host; the stricter
original result reader nevertheless rejected `CONFIRMATION_TARGET` in all
four lanes. This is neither the earlier 900-second compilation failure nor
the `PUBLIC_HOST_KERNEL_PARENT` campaign failure. These are the original
four-second in-process tests: the sixteen attacker threads, receiver and
independent verifier all share the public 25% parent, unlike the new external
attacker layout described above.

| Actual lane | Attack-free confirmed transactions | Attack confirmed transactions | Timely signed Submits | Timely History pages | Reported paid mutation CPU | Final stored credit |
| --- | --- | --- | --- | --- | --- | --- |
| protocol head | 1/1 | 0/1 | 7/7 | 7/7 | 505,130,073 ns | 1,999,174,725 ns |
| cross-architecture x64 | 1/1 | 0/1 | 7/7 | 4/4 | 526,140,447 ns | 1,998,271,515 ns |
| cross-architecture arm64 | 1/1 | 0/1 | 7/7 | 5/5 | 530,522,976 ns | 1,999,839,960 ns |
| prospective merge | 1/1 | 0/1 | 7/7 | 3/4 | 536,137,517 ns | 1,998,955,909 ns |

History fractions here count every **attempted** call in the raw report, not a
substitute target: each business confirmation still requires its complete
original seven-block native replay. The first three lanes retained
`PUBLIC_REQUEST_DEADLINE` from that replay. The merge lane's fourth History
call began at 3.954 s and ended at 4.045 s with IO EAGAIN, outside the original
window. All four attack phases had unequal independent State, zero CPU-budget
refusals and no demonstrated paid-credit depletion. Reported final CPU and
credit include the original phase's settlement scope, not an invented
per-instant attribution.

The [readback excerpt](phase-qualified/fc23-readback-applicability.json) binds
the independent reader's complete summary hash, four original archive hashes,
source/merge provenance and full submission/History denominators. It is an
excerpt of retained remote observations, not a new execution on this branch.
The observation is consistent with a physical CPU/replay/queue bottleneck while
the mutation bucket remains almost full; it does not identify one dominant
component. Lowering the refill alone therefore cannot establish service
recovery. The four-second gate and strict reader remain unchanged.

## Why equal CPU rates do not prove that depletion is impossible

Let `B` be remaining *paid* credit, `R` outstanding start/termination reservations,
`F` actual credited refill, `P` actual live plus residual CPU debit and `S`
settlement discard. The existing optional diagnostic checks the exact identity:

    B = initial_credit + F - P - S
    stored_credit = B - R

The original attack predicate uses paid credit, not merely negative stored
credit while two 100 ms reservations are outstanding. A reservation is not work
and cannot be counted as budget exhaustion. Unknown accounting stays unknown
and fences starts; it is not a zero measurement.

In an ideal timely-accounted model, a 25% whole-parent CPU cap bounds the rate
of its paid subset by 250 ms/s. Matching that value with the scalar refill gives
no sustained paid-rate advantage for draining a full two-second burst. This
explains why introducing the correct Host can make the original burst-depletion
gate much harder to reach. It does **not** establish a mathematical invariant
that the real implementation can never deplete:

1. `charge_live` refills and clamps before subtracting the next observed CPU
   interval. A long nonpreemptive operation can defer its debit. While the
   account still appears full, refill can be discarded; the later lump debit
   can exceed the remaining credit even when average physical CPU is below the
   refill rate. Full-State JSON/root/SQLite work therefore matters.
2. Kernel quota applies by periods, not to every arbitrarily aligned interval.
   A conservative idealized interval includes two edge-period quotas; scheduler
   accounting, distributed per-CPU runtime slices and enforcement overshoot
   require an additional measured allowance. The zero burst field alone is not
   a proof of a continuous exact-rate bound.
3. Thread CPU and monotonic elapsed time have distinct sampling boundaries.
   Scoped-worker joining and final residual settlement must remain exact. A
   timing-error allowance cannot be silently set to zero.
4. Scalar refill currently floors each nanosecond interval and advances its
   watermark. It can discard less than one ns per update, cumulatively bounded
   by the actual update count, separately from intentional burst-cap discard.
5. Pending owner reservations affect stored credit and admission eligibility;
   they do not increase actual `P`. Nonpreemptive unobserved CPU is different
   from reservation principal.

Under explicit assumptions of known exact accounting, bounded maximum delayed
paid CPU `L`, a kernel interval allowance `E`, sample error allowance `D` and
`N` refill updates, a useful *conditional diagnostic* has a loss scale of
`L + E + D + N ns` from a full bucket. With 25 ms periods of available CPU, an
ideal two-edge-period allowance alone is 50 ms. No measured bound for all
nonpreemptive stages `L`, actual scheduler overshoot `E` or complete physical
timing error `D` has been established here. The expression must not be used as
a certificate or an attacker lower bound.

The retained >8 MiB examples are concrete honest CPU refusals, with two started,
joined and known M06 workers and exact settlement. They do not supply the
missing bound for every State size. A scheduler that promises all allowed State
sizes needs bounded working sets, bounded nonpreemptive operations and original
owner continuations; merely adding an unbounded cache or increasing burst credit
would not establish that guarantee.

## Candidates requiring a new explicit resource profile

A separately named receiver profile could set mutation refill strictly below
the public parent's physical quota. This creates room in the rate model for
signed reads, authentication and control work, and permits a physically feasible
paid attack rate above mutation refill. It does not by itself reserve that room:
unpaid work, queue service, control CPU and shared-owner scheduling still need
their own bounded admission and actual all-honest-request measurements.

If the physical paid attack rate is `a` and a candidate refill is `r < a`, an
ideal fluid estimate for draining the full burst to the 100 ms start threshold
is `(2.0 - 0.1) / (a - r)` seconds. For example, `a=0.20 CPU/s` and `r=0.15 CPU/s`
gives 38 seconds, which already exceeds the unchanged 30-second pressure window.
That arithmetic example is neither a measurement nor a parameter recommendation;
the fixed 1/5/9-second honest schedule adds another overlap requirement. A new
profile must preregister its rate, fairness target and complete denominator
before measurement, with a fresh profile/domain and no relabeling of the old
campaign as passed.

An explicit process-cold zero-credit experiment is also legitimate: the existing
cold constructor creates no new burst. The fresh retained local observation
actually depleted its original account with 118 invalid W1 transcript replays
and recovered a real signed read and mutation afterward. It does not replace the
original full-burst matrix or demonstrate continuing-attack overlap. A candidate
that changes the rate must keep all earlier failures, not selectively keep only
the profile on which a chosen finite workload passes.
