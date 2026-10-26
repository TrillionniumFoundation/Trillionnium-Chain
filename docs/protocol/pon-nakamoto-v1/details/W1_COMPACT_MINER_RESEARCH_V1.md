# W1 compact miner research v1

## Status and exact scope

This is a research example for measuring an implemented miner without requiring
large diagnostic originals for failed attempts. It changes no consensus,
authorization, target, fork choice, proof format, or qualification rule. Source
and parser controls are not performance results. No new result in this document
closes the arbitrary-strategy, unbounded amortization, hardware-independent, or
physical minimum-cost blockers.

The implementation is
[`pon_w1_compact_miner_research.rs`](../../../../trillionnium/crates/trnm-pon-node/examples/pon_w1_compact_miner_research.rs),
with its
[research support](../../../../trillionnium/crates/trnm-pon-node/examples/support/w1_compact_miner.rs)
and the unchanged
[`DeferredPrepared` producer](../../../../trillionnium/crates/trnm-pon-node/examples/support/w1_deferred_producer.rs).
The
[strict binary reader](../../../../scripts/w1_compact_miner_reader.py)
and
[parser controls](../../../../scripts/ci/test_w1_compact_miner_reader.py)
use the existing independent
[scalar work oracle](../../../../formal/pon-nakamoto-v1/work_oracle.py).

## What is actually removed

The older
[late-assembly example](../../../../trillionnium/crates/trnm-pon-node/examples/pon_w1_late_assembly_research.rs)
already avoids assembling full losing proofs in deferred mode. It still emits a
JSON statement and an availability record for every attempt, computes diagnostic
identities, and expands every emitted full proof to hexadecimal with an additional
full-proof hash. This experiment removes those requirements from the measured
compact loop.

A winner uses the original `Packet::encode()` method. The payload is exactly
49,508 bytes: the original 318-byte header, the original two-byte zero transaction
count, and the full 49,188-byte PNW1 proof. This is not a 32-byte ticket standing
in for a proof. Neither field matrices nor the product are omitted from a winning
packet. The original `Packet::decode()` and `Node::admit()` process these exact
bytes after mining ends. No consensus decoder or verifier is modified.

The compact loop does not encode JSON, hexadecimal proof bytes, diagnostic
semantic IDs, block IDs, or a SHA-256 of each full proof. It does compute the
unchanged challenge, trace and ticket needed to decide whether it won. It also
pays for a small continuous trace commitment and counters used by this study.
Those remaining observations are avoidable by another miner and are explicitly
**not a protocol-enforced resource floor**. Their observed CPU is never subtracted
to estimate hypothetical miner throughput.

## Same legal task and deterministic stream as the deferred control

Setup uses `Settings::development_with_profiles(Some(1),
"native-public-evaluation-dev-v1", continuity_v1::PROFILE)` and the actual
maintenance material. It opens a real `Node`, obtains the active genesis parent,
and calls `make_consensus_maintenance` with empty transactions, development
miner zero, timestamp 11 and a 64-attempt cap. The original setup winner is
admitted and retained as an original production packet. Its search failures are
paid in setup, counted as `winning_nonce`, and reconstructed only later.

Research uses this exact acquired header except for nonce:

```text
nonce = 2^63 + seed * 4096 + ordinal
```

This is the same schedule, parent, task, preparation and trace/ticket function as
the old late-assembly example. Preparation pays for `DeferredPrepared::new`,
including its original AB product and proof prefix. The compact commitment's
initialization is also paid during setup. Maintenance is not evidence of actual
model training. No registration fee or task authority is fabricated.

The comparison must rerun the old deferred example on the same newly frozen
source and current exposed machine. A result from an older campaign is not a
matched control. A paired ratio additionally requires identical complete setup
header/proof identity and the same actual overlapping sequence of semantic ticket
identities. Different observations, censoring, or an unequal prefix produce a
null matched ratio. Two seeds and a finite fixed stream do not cover arbitrary
adversarial input or task selection.

## Online commitment and complete failure counting

For setup-complete runs, initialize SHA-256 with these bytes:

```text
"TRNM-W1-COMPACT-ATTEMPTS1\0" || original_template_header || seed_u64_le
```

Append `ordinal_u64_le || trace_32_bytes` for every completed research attempt,
including every target miss. The original header and fixed nonce schedule let a
reader independently reconstruct each challenge, ticket and semantic identity.
The online commitment binds the entire completed prefix; it is not a collection
of missing diagnostic proof originals. Each completed target miss increments the
actual miss counter. Every target hit outputs its complete production packet.
No winner may be silently omitted from this protocol's successful transcript.

The seal records completed attempts, target hits, target misses, the commitment,
original packet bytes, the B-available prefix, and the first/last attempt timing.
The reader runs the independent scalar equations for **every nonce** and checks
that the complete winner set, all failures and final commitment match. It also
reconstructs every original setup search nonce. Recomputed miss proofs are
posthoc audit artifacts, have zero new credit, and cannot establish when their
original bytes existed. The reader does not attest the native process, clocks,
physical hardware, or local counter execution.

## Budget and phase semantics

There is one setup CPU budget P and one miner CPU budget B. There is no per-epoch
budget refill. Setup must finish and flush its preparation records within P
before any miner attempt starts. CPU polling precedes every new attempt. The
max-attempt cap is a safety bound; reaching it is reported as censored, including
when the final atomic operation also crosses B. A budget stop and a cap stop are
never merged. Zero and tight budgets retain their actual outcomes.

A winning packet becomes available only after `write_all` and `flush` succeed on
its original packet frame. The completion stamp is taken afterward. A winner
whose stamp is after B remains a complete original packet and is passed to the
receiver, but earns zero B credit. One atomic attempt may overrun B; no next
attempt may start afterward. Miss completion is a trace-and-commitment observation,
not availability of a full losing proof.

Per-attempt ledger updates following the availability stamp remain paid. The
seal explicitly reports the sum of observed availability-to-accounting CPU/wall
spans. Instructions after those observation stamps, loop polling and all other
work remain inside actual measured miner CPU. This subspan is neither a
subtraction allowance nor an exhaustive profiling of every ledger instruction.
The final hash, seal encoding and seal flush occur after the last stop poll and
are included in `post_stop_seal_cpu_ns` and actual miner CPU. They do not backdate
winner completion.

The four contiguous native phases are setup, miner, receiver and audit. Boundary
record encoding is charged to the next phase. No `Node` or verifier is available
to the miner loop. Receiver work starts after the complete miner seal; it decodes
the actual original production bytes, calls the unmodified `Node::admit`, records
all winners including late ones, and never feeds an outcome back to mining.
The active genesis tip remains unchanged; admitted candidates are not activated.
Candidate work is not canonical growth, mature reward or TPS.

Native state/directory teardown is charged to receiver. Audit recomputes all
attempts through the original proof implementation and reference verifier and
checks the original winner bytes. These proof and cache buffers are dropped
before the audit endpoint. The direct total process CPU endpoint is recorded
separately from the sum of the four phases. Initial argument handling before the
recorded origin, final summary serialization, and remaining drops remain in the
whole-child observer residual. The whole waited command is not replaced by a sum
of phase CPU, and the residual is not reclassified as enforceable miner work.

## Binary container and failure handling

The research container has fresh magic `W1CMR1` followed by two zero bytes. Every
frame is a one-byte type, a four-byte little-endian length, and exactly that many
payload bytes. Frames are bounded to 65,536 bytes and raw/decompressed output to
256 MiB. Metadata is strict JSON; the setup packet is raw original production
wire bytes; a winning frame is an eight-byte ordinal followed by raw original
production wire bytes. No production packet field uses the research framing.

| Type | Payload |
| --- | --- |
| 1 | Start options and exact research claims |
| 2 | Actual native context |
| 3 | Original setup production packet |
| 4 | Setup native receipt and original search count |
| 5 | Paid preparation record |
| 6 | Ordered phase boundary |
| 7 | Ordinal and complete original winning production packet |
| 8 | Miner seal, all failure counts and online commitment |
| 9 | Post-seal native receipt with retained availability observations |
| 10 | Posthoc audit summary, with zero new credit |
| 11 | Final reconciliation and direct native CPU endpoint |

Ordinary short writes are completed by `write_all`. An unrecoverable write or
flush error aborts; it does not generate a successful availability receipt or
final success record. Partial bytes and stderr remain evidence of failure.
Unknown tags, oversized frames, noncanonical packet lengths, nonzero transaction
counts, duplicate JSON keys, boolean/float integer aliases, trailing bytes,
missing seals and incomplete output are rejected. A collector output cap cannot
be treated as a successful budget stop. Native producer errors are fatal and
retain ordinal, completed-prefix and miss counts in stderr; there is no silent
fallback or successful stub.

Existing
[lossless raw compression](../../../../scripts/w1_lossless_raw.py)
may gzip a job only after it finishes. It verifies original and decompressed
bytes before removing a redundant uncompressed copy. Compression is not part of
miner production CPU and does not change the original output availability stamp.
A collector must bind the clean committed head/tree, complete source closure,
registered job arguments/order, actually built executable, raw byte hashes,
compression map and the actual external CPU observers. The local per-stream
reader is one component of that binding, not an external source or binary
attestation by itself.

## Interface and intended finite comparison

The example accepts only `--setup-budget-ns`, `--miner-budget-ns`,
`--max-attempts` and `--seed`. All are unsigned decimal integers. The cap is
1–4096 and the seed is at most `2^32-1`. A typical registered invocation is:

```sh
pon_w1_compact_miner_research --setup-budget-ns 1000000000 --miner-budget-ns 128000000 --max-attempts 4096 --seed 7101
```

The matched existing control has the same four arguments plus `--mode deferred`.
The intended small grid uses B=128 ms and 512 ms, seeds 7101 and 7102, both output
paths, P=1 s and cap=4096, with explicit setup-zero/setup-tight/miner-zero/
miner-tight/cap controls. The canonical registered plan owns exact order and
parameters; this document is not an alternative plan and records no performance
claim. No parameter is selected using an unfrozen throughput observation.

The reader API is `read_compact(path, expected_options=None)`. It returns original
raw SHA/length, options, phase CPU, direct total process CPU, the actual seal,
winner availability/native acceptance, all independently recovered semantic
identities and target outcomes, original winner packet identities, and separate
original-packet versus posthoc-recomputation counts. A standalone pinned read is:

```sh
python -B scripts/w1_compact_miner_reader.py --raw JOB.stdout.gz --expected-raw-sha256 TRUSTED_RAW_SHA256 --out readback.json
```

The parser's explicitly synthetic zero-work unit fixture checks grammar and
rejection behavior only. It is not native execution or performance evidence.
Actual functional output and formal samples, including every failure and
negative result, must be separately retained and source-bound.
