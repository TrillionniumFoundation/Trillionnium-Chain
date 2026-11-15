# Hepta 682 paired Linux jobs: exact original Host readback

## Result and source boundary

The four original jobs each executed all five selected native tests successfully.
All four strict from-zero drivers nevertheless failed with the exact reason
`CONFIRMATION_TARGET`. Across eight predeclared four-second business windows,
three confirmations completed before the original deadline; none of the four
pressure windows completed a confirmation. None of the eight sustained attack
phases demonstrated paid CPU budget depletion. These are failed service and
depletion observations, not a qualification of the current candidate, public
readiness, resource fairness, pure PoN security, or an independent WAN.

Original run: [Hepta paired run 40633626330](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40633626330).
The Hepta source was `682a88a7f847e31ffb6cd5e0a630dd71dde4bfee`; its base-merge
was `f9923f7809bf78de8e54885699b67f3816bf2be2`. Both used tree
`860d905d3ca40805f053dae7d09bc446dac5285f`.

The actual native Chain source was
`131f673d9563e72aca7139f3239856957d118d49`, or its base-merge
`66634191298767b40691d6b2a298418ec19e3673`, both with tree
`b8bdd87dca3cd6288c38f63848b24b1a2df6a09d`. They did **not** execute the r8
History repair or the later PQ cancellation repair. Source and ELF identities
were unchanged across each original execution. The pinned native test source
SHA-256 was `d10a3871e19ae2479c9eb3420ddf0bc47e89a1ef72d34ac5be5b82fad99eb023`.
Full original identities, selected source comparisons, and before/after receipts
are in [source-bindings.json](source-bindings.json),
[input-binding.json](input-binding.json), and [readback.json](readback.json).

| Job | Variant | Artifact ID | Strict driver | Baseline confirmation | Pressure confirmation |
| --- | --- | --- | --- | --- | --- |
| 122635467337 | ARM base-merge | 12793540188 | FAIL: CONFIRMATION_TARGET | 1/1, 2,195,632,476 ns | 0/1 |
| 122635467343 | x64 base-merge | 12792744792 | FAIL: CONFIRMATION_TARGET | 1/1, 3,612,787,796 ns | 0/1 |
| 122635467377 | ARM source-head | 12793306605 | FAIL: CONFIRMATION_TARGET | 1/1, 2,493,189,880 ns | 0/1 |
| 122635467442 | x64 source-head | 12793685376 | FAIL: CONFIRMATION_TARGET | 0/1, History import deadline | 0/1 |

The Host controller returned `passed=false`, systemd exit 1, and native child
exit 1 in every job. However, both `host_errors` and `final_host_errors` were
empty. The before/after parent identity and all original resource observations
were valid: `cpu.max="25000 100000"`, `cpu.max.burst="0"`,
`memory.max="2147483648"`, `memory.swap.max="0"`, and `pids.max="256"`.
The parent was `/sys/fs/cgroup/trnmponpublic.slice`, with UID 1001, no capability
bounding set, and `NoNewPrivs=1`. The strict business failure must not be renamed
as a Host configuration failure. The preparation receipt's
`native_tests_executed=false` describes its no-run build preparation; it does not
erase the five subsequent actual native executions.

## Native selector and log denominators

Each job has one actual successful invocation of each exact selector below,
with one selected test, no ignored test, exit 0, and no native-process timeout:

1. `caller_cpu_clock_keeps_missing_overflow_and_wrong_owner_distinct`
2. `from_zero_search_preserves_misses_exhaustion_and_full_replay_rejection`
3. `four_from_zero_w1_traces_keep_native_state_and_chainwork_unchanged`
4. `from_zero_service_shares_cpu_with_honest_work_and_reopened_owner`
5. `from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline`

The denominator is 20/20 original selected invocations. Exact argv, exit status,
wall time, CPU time, RSS, output hashes and stdout/stderr are preserved. The fifth
Rust test asserts native safety/accounting invariants and explicitly records
the business outcome separately. The strict Python driver then correctly
rejects its failed business report. Cargo exit zero cannot replace that gate.

The wider job logs contain 64 successful wrapper invocations and 603 passed
test **occurrences per job**, with no observed failed occurrences. Selectors
overlap: neither 603 nor the four-job sum is a unique-test count. All 256
wrapper receipts remain in the readback. They have unchanged clean source
identities; they do not establish that unselected tests ran.

The final parser retained 881 complete JSON objects per job, 3,524 total.
It handles optional interior GitHub BOMs and timestamp prefixes, as well as
JSON printed after test-name and diagnostic prefixes. A preliminary inspection
that accepted only leading JSON undercounted these objects; that count is not
used as a denominator. The complete index retains original log line, prefix,
schema, JSON byte length and SHA-256 in
[all-job-json-index.jsonl.gz](all-job-json-index.jsonl.gz).

## Every original confirmation call

All eight windows planned one business confirmation and the same seven signed
packets in baseline and pressure. No window was renewed after a failed import,
an attacker join, or service shutdown. Successful observations had depth 6 and
work delta 12, and were neither finality nor execution authority. Failed windows
retain null confirmation and latency; no invented deadline latency is assigned.

| Call role | All calls | Timely signed successes | Signed refusals | Errors | Returned after original window |
| --- | ---: | ---: | ---: | ---: | ---: |
| Honest Submit | 56 | 56 | 0 | 0 | 0 |
| Honest History | 35 | 34 | 0 | 1 IO EAGAIN | 1 |
| Honest Head | 313 | 308 | 0 | 5 IO EAGAIN | 5 |
| Hostile Submit | 909 | 0 | 845 WORK:Transcript | 54 IO EAGAIN + 10 FRAME_DEADLINE | 64 |

All 64 hostile errors are retained. Their original `returned_after_deadline`
fields are false: the original four-second phase window could end before the
individual two-second call deadline. The observed errors must not be converted
into 64 fabricated two-second timeouts. The six honest network errors likewise
remain separate from native import failures.

There were 7 History calls in each baseline and respectively 3, 1, 2, 1 in the
four pressure windows. Pages carried one packet. Three retained native
verification errors were `PUBLIC_REQUEST_DEADLINE`: ARM source-head pressure,
x64 source-head baseline, and x64 source-head pressure. The native report did
not retain an import outcome for every individual network reply. Therefore this
readback does **not** subtract these three errors from 34 network successes and
claim an exact count of successful imports. The full call ledger retains the
network response hashes and available page metadata; the original report
remains the source for its actual native verification-error array.

The two hash domains for hostile call identity are explicitly bound to each
complete packet in the retained construction table:

- The client diagnostic uses `pressure-recorded-request-v1`.
- The actual public wire/receiver observation uses `public-request-body-v3`.

For every compact hostile call, the reader reconstructs canonical Submit JSON,
checks its original recorded byte length and diagnostic digest, then derives
the actual wire digest. It retains both digests and the complete packet's byte
length/SHA-256. Matching receiver records form a **repeated-body cohort**, not
a unique per-request response pairing.

| Confirmation pressure job | All calls / matching receiver records | Full W1 started and refused | W1 accepted | M06 admission started |
| --- | ---: | ---: | ---: | ---: |
| ARM base-merge | 237 | 223 | 0 | 0 |
| x64 base-merge | 250 | 235 | 0 | 0 |
| ARM source-head | 219 | 204 | 0 | 0 |
| x64 source-head | 203 | 191 | 0 | 0 |
| Total | 909 | 853 | 0 | 0 |

There are 56 matching receiver records without a full W1 start. The aggregate
count of completed W1 refusals exceeds client-observed signed refusals by 8;
the readback does not invent individual response pairings for that difference.
These attacks reached complete W1 rejection but never the expensive valid-work
M06 ROOT path. Paid CPU is actual receiver accounting, not callback counts.

## Actual CPU budget and the separate sustained experiments

The original scalar profile is unchanged: burst B=2,000,000,000 CPU ns, refill
R=250,000,000 CPU ns per second, start reserve=100,000,000 ns, two mutation
workers, and the whole phase's Host CPU quota Q=0.25 core.

| Confirmation pressure job | Actual charged mutation CPU ns | Final stored credit ns | Mutation CPU refusals |
| --- | ---: | ---: | ---: |
| ARM base-merge | 515,057,752 | 1,999,176,220 | 0 |
| x64 base-merge | 529,737,119 | 1,998,577,235 | 0 |
| ARM source-head | 499,080,912 | 1,999,981,924 | 0 |
| x64 source-head | 529,539,341 | 1,999,968,528 | 0 |

All retained phase metrics satisfy charged mutation CPU = full-work CPU +
dispatch CPU excluding full work. All started W1 work was joined; after shutdown
there were no in-flight paid owners, unknown-accounting flags or clock failures.
This reconciliation does not split the whole paid domain into individually
attributed honest and hostile CPU costs.

The finite service report and sustained service report are separate from the
confirmation report:

- Eight finite phases retained 64 hostile calls, 64 honest reads, and 8 honest
  Submits. All original finite service targets held; these are not depletion
  or signed business-confirmation targets.
- Eight sustained four-second phases retained 2,137 hostile calls, 167 honest
  reads, 8 honest Submits, and 8 post-pressure Heads. All 2,137 attacks matched
  complete W1 refusals, with zero hostile M06 admission starts. All finite
  service targets held; the count of phases demonstrating budget depletion was **0/8**.
  Actual charged mutation CPU ranged from 556,672,272 to 621,825,595 ns per phase.
- All original budget samples remain in the readback. The lowest sampled stored
  credit was 1,786,092,414 ns; at most two reservations were in flight. Sampled
  stored credit is not a continuous physical CPU or reservation-free paid-flow
  bound. The reader makes no interpolation or hidden-dip claim.
- Same-process owner reopen retained exactly equal stored meter observations.
  This is not a kill cut, a machine restart, durable credit-recovery proof, or
  physical power-loss evidence.

At the fluid-rate level, a whole Host with Q=0.25 CPU-s/s cannot supply a sustained
paid drain rate above R=0.25 CPU-s/s; it also pays for unpaid service and verifier
work. Bucket clipping, reservation timing, scheduler periods and delayed charge
settlement make that observation an explanation of the failed exhaustion
geometry, not a proof that every transient dip is impossible. A new depletion
experiment must declare a different resource geometry separately and preserve
these actual failures. It cannot lower honest work, renew deadlines, manufacture
credit, or count callbacks as CPU.

## Readback method, correction and retained files

[analyze.py](analyze.py) read selected JSON/log members directly from the four
original ZIPs. It did not extract or execute native code. Root had already
verified each complete downloaded ZIP's byte length and SHA-256 against GitHub
metadata. This reader checked that receipt and the retained ZIP size, then
verified selected member CRC, byte length and SHA-256, and the original native
manifest's hashes. It did not claim to rehash every ELF or the whole 156 MB ZIP.

The final bounded readback used nice 19, a 30-second wall cap, 20/25-second CPU
soft/hard limits, and a 384 MiB address-space cap. It exited 0 after
1.1682307009905344 seconds wall and 1.126349 seconds settled child CPU, with
97,272 KiB peak child RSS. [readback-receipt.json](readback-receipt.json) retains
the exact argv and source hash; these are reader costs, not a new import or
throughput measurement.

The first reader invocation exited 0 but incorrectly compared the two digest
domains directly. Its empty hostile cohort is invalid and superseded. The full
first source, receipt, stdout/stderr, and readback remain in
[first-reader-superseded.zip](first-reader-superseded.zip). Its other output
files are byte-identical to the final retained versions, with an explicit
inventory binding. No native result, call count, confirmation, CPU measure or
failed gate was replaced by this correction.

The final evidence retains all 3,769 client calls, all 3,633 receiver observer
records and all 3,524 complete job JSON objects. The client index keeps every
timing/status/error plus a canonical hash and exact JSON pointer into the
original report; it does not claim to replace complete response bodies.
Receiver records are retained in full. The 61 small original receipt/log
members in [small-original-receipts.zip](small-original-receipts.zip) have all
been read back and matched to [raw-files.json](raw-files.json).

- [all-client-calls.jsonl.gz](all-client-calls.jsonl.gz)
- [all-receiver-observations.jsonl.gz](all-receiver-observations.jsonl.gz)
- [readback.json](readback.json)
- [package-verification.json](package-verification.json)

The four original large artifact ZIPs and job logs remain in the root recovery
archive, identified exactly by input bindings; no duplicate ELF or old prior
artifact was copied into this evidence package. No current candidate native
execution, systemd action, new Host permission, profile change, or qualification
was performed by this readback.
