# Native full-path evidence readback v1

This directory records and checks a small, actual Node development experiment.
Its result is always **`COMPONENT_OBSERVATION_ONLY`**, with **security and overall
gate `HOLD`**. A complete native computation does not prove a quantum search-cost
lower bound. A successful component observation does not qualify a compressed
proof, the original protected Host service contract, a public network or production.

## What is measured

The native example uses actual PGH2/PNP2 packets, a signed development transfer,
`Node` admission and activation, and an independently opened exact packet observer.
The parent collector timestamps flushed native events on **one monotonic clock**.
It freezes four original starts before that clock's origin:

| Original start | Work actually performed | Accounting |
| --- | --- | --- |
| `valid` | New native candidate generation, packet preparation, IPC, full admission, activation and cold observation | May record one new locally accepted block; depth and deadline remain separate |
| `duplicate` | Exact resubmission and independent readback | Never adds a second block or pretends to perform a new search |
| `late_product` | Last C word changed while retaining the claimed trace/block identity | A late mathematical rejection requires exact `WORK:Product` and the actual callback prefix |
| `cancelled` | Cancellation at `BeforeVerifiedWork` | A reached callback does not replace the missing successful admission return |

The original business targets remain **4 seconds and depth 6**. The shared
development host is not a claimed execution of the original 0.25 CPU, 2 GiB,
zero-swap, 256 PID, 16 hostile-worker Host contract. Depth-zero readback remains
depth zero. A short run does not acquire a completed 4-second observation window
by writing a later timestamp into a manifest.

### Stage boundaries

| Recorded stage | Included work |
| --- | --- |
| `search` | Setup, signed transfer, execution, native candidate generation, nonce search and winner verification; this is a coalesced native-generation interval |
| `winner_prepare` | The subsequent packet serialization, canonical roundtrip and fsync, after the actual flushed search boundary |
| `propagation` | Actual same-host child stdin transport through complete read and canonical packet decoding |
| `verification` | Receiver cold-open, complete native W1 replay, execution and SQL admission |
| `acceptance` | Activation, writer close, independent observer cold-open and exact native readback |

These are not isolated kernel benchmarks. Native child-local callback durations
only check callback ordering in that child; the reader never subtracts clocks
from separate processes. End-to-end latency starts at the frozen scheduled start,
so queueing and gaps cannot disappear by summing selected stages. No compressed
winner proving was performed by this native collector.

Phase intervals are the parent process's observations of flushed events. They
include reader-thread scheduling and are not exact child execution durations.

## Files and commands

| File | Responsibility |
| --- | --- |
| [collect_native.py](collect_native.py) | Freeze source/binary/context and all starts; retain original process streams, failures and parent-clock observations |
| [adapt_native.py](adapt_native.py) | Deterministically normalize the original collector output; keep the original preregistration digest and every start |
| [fullpath_gate.py](fullpath_gate.py) | Bound all input reads, check packet and receipt identities, count complete paths and required-depth progress |
| [COLLECTOR_CONTRACT.md](COLLECTOR_CONTRACT.md) | Exact normalization fields and public parser/canonical-check interfaces |
| [test_fullpath_gate.py](test_fullpath_gate.py) | Adversarial identity, phase, denominator, canonical-progress and resource controls |
| [test_adapt_native.py](test_adapt_native.py) | Original-log normalization, cancellation, duplicate, local-error and launch/ownership-failure controls |
| [test_collect_native.py](test_collect_native.py) | Process lifecycle, timeout, cleanup, descendant/pipe ownership and failed-start retention controls |

From the repository root, run the reader controls with:

```sh
python3 -m unittest discover -s formal/pon-native-fullpath-v1 -p 'test_*.py' -v
```

After the real collector has completed, pass the **original preregistration
digest retained outside its output directory**:

```sh
python3 formal/pon-native-fullpath-v1/adapt_native.py /absolute/evidence/directory \
  --preregistration-sha256 ORIGINAL_PREREGISTRATION_SHA256
```

The adapter writes `gate-context.json`, `gate-manifest.json`,
`gate-observations.json` and `gate-readback.json` beside the original evidence.
Those normalized files are explicitly **post-collection derivations**, not a new
preregistration. The original plan, context, streams and process records remain
unchanged. Repeated normalization is allowed only when the derived bytes match.
The readback records both the original plan digest and original observation digest.

The normalized reader can also be run directly:

```sh
python3 formal/pon-native-fullpath-v1/fullpath_gate.py /absolute/evidence/directory \
  --manifest gate-manifest.json --observations gate-observations.json \
  --manifest-sha256 NORMALIZED_MANIFEST_SHA256
```

Both commands return **exit 1 for valid component evidence / HOLD** and **exit 2
for malformed, inconsistent or unreadable evidence**. Neither has a passing exit
code for the current native development collector. Unit-test success is a source
control result; it is not the reader's acceptance gate.

## Refusal and accounting rules

- The preregistered schedule is the denominator. Missing rows, missing cohorts,
  cancellations, timeouts, launch failures, unavailable observations and duplicates
  cannot be discarded to improve the success rate. Each mode needs both honest
  and hostile cohorts before recorded arithmetic can be complete.
- Every complete stage references retained native process bytes and the same exact
  claim. An `error` event mixed into a purported complete-stage receipt prevents
  completion. Ordered partial stages are retained for failed attempts; later
  phases cannot turn a failed stage into completion.
- Full native admission requires an `admission_complete` event, the exact admitted
  block and callback counts `[1, 512, 1, 1]`. An existing-work reuse has zero
  callbacks and is separately classified. `BeforeVerifiedWork` followed by a
  cancelled/error return is not a completed native verification.
- A hostile late-product rejection requires `WORK:Product`, no cancellation, and
  counts `[1, 512, 1, 0]`. A CPU/deadline/transport/local error with the same counts
  remains a failure; it is not a mathematical rejection.
- A new accepted block needs the actual canonical snapshot bound to the acceptance
  receipt. An ACK, `stored_exact` flag, or membership boolean alone is insufficient.
  The reader recomputes PGH2 block identities, parent links, heights, depths and
  target-derived descendant chainwork from the retained path packets.
- Required-depth progress must be first observed within the original deadline and
  remain observed at the frozen reorg-window end. Later reorg/absence is retained
  even if the block reappears. The same block can add effective progress at most once.
- Campaign CPU and bytes must cover the sum of every recorded attempt; campaign
  RSS must cover the largest recorded per-attempt bound. Missing counters force
  HOLD. These checks do not authenticate resource measurement or enforcement.
- Inputs reject duplicate JSON keys, NaN/Infinity, booleans used as integers,
  noncanonical hex, out-of-range integers, oversized input, absolute/traversing
  paths, symlink components and mismatched hashes. Only bounded regular files are
  read; arbitrary commands from evidence are never executed.

## Limits of the reader

`parse_packet` validates framing and the exact transaction-root/account-witness
commitments needed to bind measurements to the actual packet. Its body hash
includes the u16 transaction count and length-prefixed transaction bytes; its
witness hash covers the raw witness without the u32 length. Its header and block
hash domains match the existing PGH2 native vectors.

The Python reader **does not replay FullLimb**, validate transaction signatures,
prove task eligibility, establish source-to-binary provenance, authenticate a
clock or operator, enforce a cgroup, or establish consensus finality. Native
computation remains an observed result of the retained native executable. Raw
artifact hashes and recomputed ancestry improve evidence consistency without
turning the observer into an authority.

Synthetic unit fixtures deliberately contain no valid native work claim; they
exercise the reader's refusal/accounting behavior. Real experiment results must
come from the source-bound Rust example and original process collector. The v1
reader accepts only that explicit development native receipt namespace. Native
receipts relabeled `compressed` cannot qualify compression; a genuine compressed
collector/verification path requires a separately reviewed schema and both its
security and full-path performance evidence.

The fixed output includes `security_qualification_verified=false`,
`native_relation_replayed_by_reader=false`, `quantum_lower_bound_proved=false`,
`public_network_ready=false` and `production_activation=false`. There is no local
JSON switch that promotes these observations into release authority.
