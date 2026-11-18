# Fixed-Host ROOT F0: verified failed original campaign

The existing F0 entry was dispatched once at source
`7e3e454f9b18d5d135e72cc5ea373e04fc5a2ef8`, tree
`d000e0007dc963a4c152b805b36b6e9d08fb8569`:
[run 44315121617](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44315121617).
Its actual result remains **1/6 confirmations inside the original thirty-second
phases and 0/6 against the scheduled four-second SLO**. All 42 planned business
packet exposures remain, including 21 not attempted before the original phase
expired. Preparation and cleanup do not turn this into a business pass.

This is the larger existing workload: 1,024 seed transfers, four seed blocks,
21 business blocks per phase, one baseline and one valid-work/late-M06 ROOT
phase, 24 separate external attacker processes, and three rounds scheduled at
1, 5 and 9 seconds. The public receiver and independent client retain the
original root-owned 0.25-CPU/2-GiB parent. External producers remain in the
separately owned original controller. No predicate, deadline, retry count,
resource geometry, body or native test selector was changed.

## Actual business result

| Phase | Confirmed within 30 seconds | Four-second SLO | Timely Submit acknowledgements | Original independent History result |
| --- | --- | --- | --- | --- |
| Baseline | 1/3 | 0/3 | 14/21 | First round ends 19.391138538 seconds after its scheduled start; next import reaches the original deadline |
| Valid-work ROOT pressure | 0/3 | 0/3 | 7/21 | Four import attempts, ending with `PUBLIC_REQUEST_DEADLINE` before the first round confirms |

The baseline did not reach its third round; the pressure phase did not reach
its second or third. These slots remain failed/unobserved in the denominator.
The original native test returned 101 and its original business reader refuses
with `BASELINE_MUST_PASS`. The original scheduled-clock reader separately
refuses with `F0_ALL_SIX_SCHEDULED_FOUR_SECOND_TARGETS_REQUIRED`.

This result does not revoke or generalize the separate [two-architecture
four-second from-zero observation](../chain-original-window-pass-20261118-2e9b/README.md).
The two experiments have different state sizes, actors and native workloads.

## Measured limiting work

The original native observer retains each actual import, including the one
that reaches the deadline. Its observed CPU totals are:

| Import observation | Baseline | ROOT pressure |
| --- | --- | --- |
| History calls with import observations | 12 | 4 |
| Importing client thread CPU | 5,912,828,453 ns | 1,779,549,999 ns |
| Actual Host checkpoint calls | 121,963 | 34,119 |
| CPU inside those Host checkpoints | 5,159,746,559 ns | 1,559,985,793 ns |

Host checkpoint intervals are nested in the caller intervals. They must not
be added to the client CPU, public process CPU or controller CPU. This is a
measured cost concentration, not proof that any check can be removed. The
original boot, parent identity/ownership, actual calling-thread membership and
five live-limit checks remain necessary at their declared boundaries. The
next implementation investigation concerns repeated State work and the cost
of the unchanged checks; this evidence makes no claim of a successful repair.

## Actual resource observations

All six planned original controller boundaries were observed and accepted by
the original resource reader. Baseline controller/descendant CPU between
`before_launch` and `after_reap` was **1,670,017 microseconds**; pressure was
**2,846,843 microseconds**. The pressure `after_reap` observation retains a
**128,061,440-byte service-lifetime cgroup memory peak**. It includes earlier
preparation and the previous phase, excludes the separately systemd-owned
public phase, and is neither an RSS sum nor a phase-local peak.

The separate public phase process CPU was 7,990,045,938 ns for baseline and
8,344,800,947 ns for ROOT pressure. Its original intervals include receiver
and verifier setup and completion work and are wider than the traffic window.
The controller interval excludes earlier honest-miner preparation. These
intervals cannot be collapsed into an exact whole-system cost or per-success
price. All services were observed empty after exact ownership-based cleanup;
the finalizer still retained `complete_success=false`.

The existing [work-cost contract](../../../../formal/pon-nakamoto-v1/contracts/work-cost-contract-v1.json)
also charges setup, all attempts, failures, aborts, withheld results,
post-winner work, proof creation, verification, transport, storage, recovery,
cross-version state and helpers. It requires distinct CPU, wall time,
concurrent RSS, GPU, storage byte-seconds, network, energy and provider-charge
dimensions. This finite F0 observation does not close those complete physical
cost dimensions. Missing values remain unknown.

## Complete originals and independent readback

`original.zip` is the complete provider archive, including the actual native
ELF, databases, source identities, failed stdout/stderr and both owner
receipts. It contains 444 files and expands to 77,365,011 bytes. Its 443
inventoried original members all pass byte-length and SHA-256 checks.

| Identity | Value |
| --- | --- |
| Provider artifact | 14432723343 |
| ZIP bytes | 18,520,306 |
| ZIP SHA-256 | `5f91007e3ef15216caca24d898ca07438fd43a199ccfa94253023cf66b44095e` |
| Native report SHA-256 | `0871be5db4f0377ce3d97e827d7d71adaf6411cd8857f81dc0f7cd1455cb8dd0` |
| Executed native ELF SHA-256 | `6796de51c006dffda01f6f9dabf868676abdc9c77dc9e78263a42097e3ad8e7f` |

`readback.py` pins all 12 imported original reader source files byte-for-byte
to their Git blobs at the tested commit. It independently recomputes the six
scheduled round outcomes, 42 packet exposures, both original refusals, all
controller boundaries and per-attempt History cost sums. It checks original
source-before/source-after, the prepared-to-executed ELF, all seven named
preparation controls and the actually failed named native invocation.

```sh
python3 docs/development/evidence/chain-fixed-root-f0-20261118-2e9b/readback.py \
  --archive docs/development/evidence/chain-fixed-root-f0-20261118-2e9b/original.zip \
  --out /tmp/chain-fixed-root-f0-independent-readback.json
```

The output path must be new. `VERIFIED_FAILURE` means the retained failure was
independently reconstructed; `business_pass`, complete physical-cost closure
and production activation remain false.
