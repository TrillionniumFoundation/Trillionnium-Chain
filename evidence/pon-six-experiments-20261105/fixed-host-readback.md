# Experiment 3: preserve F0 failure and repair the real History owner

**Acceptance: HOLD. The retained no-attack baseline is FAIL; no new native F0
execution is claimed by this increment.**

The [machine readback](fixed-host-readback.json) recomputes the original
[published F0 observation](../pon-fixed-host-root-f0-b5bb-readback-20261105/README.md)
from its retained `analysis.json`. It is a consistency check on derived evidence,
not independent authentication of the original binary or raw report. The source
of that native observation remains `b5bb7bc8d7ffe79d46c6a58fd5189e2bb9e4550c`;
these source repairs do not inherit its execution identity.

## Frozen denominator and costs

The original AuthenticatedV1/RawR14 path keeps public Host `cpu.max = 25000
100000`, memory 2 GiB, zero swap and 256 pids. Each of two phases lasts 30 seconds,
contains 21 planned business packets and schedules confirmations at seconds 1,
5 and 9. Success requires completion strictly inside four seconds measured from
the scheduled start. All six confirmations and 42 packet exposures remain in
the denominator, including never-started rounds. A network ACK is not an
independent confirmation.

| Retained phase | Four-second confirmations | Timely network ACKs | Unobserved packets | Client import wall | History network wall | Account-graph wall | Host checkpoint wall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| No-attack baseline | 0/3 | 17/21 | 3/21 | 23.368587 s | 0.308889 s | 15.396977 s | 6.612843 s |
| Valid-work ROOT | 0/3 | 7/21 | 14/21 | 15.374301 s | 0.328417 s | 10.657761 s | 3.296423 s |

These are nested observed intervals and must not be added across columns. The
baseline failure already exists without a hostile proof explanation. This F0
observation does not measure the cheapest legal miner and does not qualify the
original 16-producer campaign or continuous novel-input attack service.

## Source repair and independent controls

The existing `history_import::Owner::with` executed two adjacent full Host checks
before the first shared owner acquisition. It now retains one fresh Host check
before **every** acquisition attempt, including each busy retry. The expensive
check remains outside the Node writer. Exclusive ownership retains a fresh Host
check for each action. A cheap deadline check after the Host observation refuses
an action when the observation itself used up the original deadline.

Four new native unit controls cover one Host read per uncontended acquisition,
changed Host limits during a busy retry, exclusive reacquisition, and a Host
observation crossing the deadline. They are source changes awaiting native
compilation/execution; the local environment has no Rust toolchain. Their count
is **not** added to passing tests. The original F0 workflow now watches these two
source paths, without changing its resource limits, phase schedule or finalizer.

The [follow-up source diagnosis](fixed-host-hotspots.md) confirms that the F0
independent client uses Exclusive ownership. Shared deduplication therefore does
not establish a repair of its dominant client-import/account-graph cost. Existing
bounded graph reuse remains unchanged; an accurate native observation must
separate real full/partial traversals and whole-root hits on success, failure and
cancellation before proposing another cache boundary.

The Python consistency reader has 14 passing mutation controls. They reject
missing/duplicate rounds, denominator changes, a substituted backend, relaxed
Host limits, elapsed-time resets, inconsistent ACK counts and incomplete or
malformed evidence. Source identities and the actual log are retained in
[fixed-host-validation.json](fixed-host-validation.json).

```sh
python3 scripts/ci/test_fixed_host_service_readback_v1.py
python3 formal/pon-nakamoto-v1/experiments/fixed_host_service_readback_v1.py \
  evidence/pon-fixed-host-root-f0-b5bb-readback-20261105/analysis.json \
  --out /tmp/fixed-host-readback.json
```

The next acceptance step is a fresh exact-source run of the original fixed-Host
baseline and ROOT pair. Its outcome must retain all failures and all planned
requests. A passing reader, a smaller Host-check count, or these source controls
does not establish service liveness or close experiment 3.
