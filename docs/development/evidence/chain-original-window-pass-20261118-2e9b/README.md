# Original four-second confirmation: two native architecture observations

The unchanged original business predicate passed on **both x64 and arm64** in
required-baseline run [44309944062](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44309944062),
at source `974049daa4b72825332b07b59084cb70f4b4c8b5`, tree
`21c3ba7c2239103f1f18dfcf8e9099020bee9f74`. This directory retains the complete
original ZIPs, including the executed native binaries, SQLite state, process
receipts, source records, and failed/retried requests inside each workload.

## Actual result

| Architecture | Attack-free confirmation | 16-worker pressure confirmation | Pressure latency from business start | Original window |
| --- | --- | --- | --- | --- |
| x64 | 1/1, 2.720172444 s | **1/1** | **3.415648125 s** | 4 s |
| arm64 | 1/1, 1.899967625 s | **1/1** | **2.400575524 s** | 4 s |

Both pressure phases accepted all seven honest submissions and completed all
seven independent History replays. They confirmed the signed transaction with
six depth/work confirmations before the original window ended. Accounting
closed, no attacking work was accepted, and real attack/business overlap was
retained. The observed final confirmation offsets from the traffic epoch were
3.480677721 s and 2.486575845 s. No post-pressure drain receives credit.

The original root-owned Host parent remained `/sys/fs/cgroup/trnmponpublic.slice`:
`cpu.max=25000 100000`, `cpu.max.burst=0`, memory 2,147,483,648 bytes,
zero swap and 256 PIDs. The before/after owner identity, prepared native binary,
execution manifest and actual original command agree.

The change under observation is the r21 bounded delay after completed native
Transcript/Product refusal for an exact body. The original four-second window,
16 workers, verification semantics, request deadlines and resource limits are
unchanged. These are two finite original-workload observations; they do not
establish fresh-body, public Sybil, independent operator or WAN service.

## Independent readback

`readback.py` performs a read-only reconstruction. It checks the exact GitHub
ZIP hashes, every one of the 55 native manifest members per architecture,
the complete retained executable, five named native executions and their
process/log identities, all three original business validators, unchanged
source/Host ownership, and the original build-to-execution binding. Its
recorded reader-source hashes make the executed reader graph explicit. All
17 imported reader files are verified byte-for-byte against the Git blobs
at the original tested commit `974049d`, and the readback enforces their SHA-256
values so a changed reader cannot silently reinterpret these originals.

The readback succeeded for both archives. The original reader returns
`original_gate_validated=true`; the conclusion is not inferred from exit code
zero. Run from this repository:

```sh
python3 docs/development/evidence/chain-original-window-pass-20261118-2e9b/readback.py \
  --archives docs/development/evidence/chain-original-window-pass-20261118-2e9b \
  --out /tmp/chain-original-window-independent-readback.json
```

The output must be a new path. The reader never runs the native workload or
rewrites the retained ZIPs.

| Archive | GitHub artifact | Bytes | SHA-256 |
| --- | --- | --- | --- |
| `x64.zip` | 14431202653 | 9,463,028 | `3bd5d0ca8a2374cf1c4d549b079530494791f4786a0e9cbfd936d4a08c9dd4c1` |
| `arm64.zip` | 14431971535 | 9,071,416 | `ed58ba96672fcd66040c81e804e95065998059df0dbee8f1d08bd8675e78db0b` |

## Cost actually observed

| Pressure observation | x64 | arm64 | Scope |
| --- | --- | --- | --- |
| Traffic and joined shutdown process CPU | 921,751,168 ns | 746,345,920 ns | All threads in the native process; interval is slightly wider than 4 s |
| Whole phase process CPU | 963,861,505 ns | 786,206,240 ns | Setup, traffic, failed/retried calls, join and final state/observation reads |
| Attacking caller threads | 96,372,437 ns | 99,476,776 ns | Nested in process CPU; do not add again |
| Independent replay/confirmation thread | 501,234,745 ns | 303,975,344 ns | Nested in process CPU; do not add again |
| Receiver application bytes read | 13,419,078 | 13,421,368 | Retained streams, including rejected requests; not physical network bytes |
| Receiver application bytes written | 1,173,700 | 1,201,565 | Same stream scope |
| Retained regular-file growth | 1,907,192 bytes | 1,907,192 bytes | Eight files; logical lengths, not disk I/O or peak storage |

The whole waited invocation separately retains CPU, peak RSS, faults and
context switches, covering both phases, construction, records and exit.
It cannot be allocated as pressure-only or per-success cost. The full readback
retains submitted, refused, late, missing and unknown attempt coverage.

**Complete physical cost remains open.** Exact four-second whole-process-tree
CPU, whole-tree peak memory, physical storage I/O, physical network bytes and
energy are absent from these originals and stay unknown. No missing field is
filled with zero or inferred from byte lengths, configured ceilings, or nested
thread clocks. The existing fixed-Host ROOT F0 workflow is the next actual
execution for whole-controller/descendant CPU and memory boundaries.

## Historical failures and source separation

The previous source `7e4b96d4ac395a61a162940624769518cf2e03f3` still has 0/1
pressure confirmations on both architectures in run 44283985539. Its complete
readback remains in [the original failure evidence](../chain-original-window-cost-20261118/ci-readback.json).
The local baseline/candidate `PUBLIC_HOST_KERNEL_PARENT` failures and original
release-control failures remain in [the scheduling candidate evidence](../chain-exact-body-delay-20261118/README.md).

At the observed `974049d` source, repository-truth, fuzz and external-evidence
lanes also failed on stale source bindings. Those failures are not changed by
the successful business windows. Successor `7e3e454f9b18d5d135e72cc5ea373e04fc5a2ef8`
repairs the bindings and must obtain its own workflow results. This evidence
does not transfer whole-tree qualification to that successor or this evidence
commit. Production activation and whole-cost qualification remain false.
