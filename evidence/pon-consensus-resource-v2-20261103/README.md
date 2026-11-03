# PoN complete verifier and finite legal-work rates

**Development continuation; qualification HOLD.** The parent is the combined
W1 / State / History candidate `af064bf751ed92c82da0b113682a7dfff3225d97`
(PR #688), tree `06c2a2493183a48ade725db226fc44b24c1f9b0f`.
This increment changes the complete W1 verifier and the existing V3 evidence
reader. It does not change a proof, task, difficulty, confirmation or activation
profile. The previous failed public-service and rejection-cost observations
remain failed and are not replaced by the measurements below.

## Complete verifier changes

The default full-limb verifier keeps the original complete transcript and product
relation. It now transposes its operation-owned B-prime matrix in place; the
explicit column kernel retains its original row-major input. The two complete
correction products are subtracted row by row into this invocation's private
result, without allocating two full correction outputs. Canonical operands make
each subtraction fit in `u64` and require at most one conditional subtraction of
the modulus. The independent scalar verifier remains unchanged.

The original progress events and validation/error order remain. A cancelled
partial product is local and discarded, and only complete successful verification
can construct `VerifiedWork`. Moving arithmetic between callbacks can change
the event at which a particular time-based cancellation occurs; identical timing
is not claimed.

The measured final primitive has SHA-256
`da3c6d28be39effcdb0d792e858d11aabbe83cafaaff326c45c9133cb4b818c7`
and Git blob `f76b8ddbbcb62174ad55edd07ebee70d33b71668`.
The single corresponding current-source pin was refreshed; the other 363 pins
and every qualification assertion remain unchanged. Historical source hashes
are preserved.

## Actual legal-work resource observation

The existing [legal observer](../pon-work-resource-v1-20261103/valid_work_observation.rs)
prepares 24 full legal proofs across three fixed matrix classes and eight sample
IDs. Every proof is checked by both the independent scalar verifier and the
current native verifier. Baseline and candidate proof fingerprints match exactly.
No new invalid-work generator or network/service workload is executed here.

| Per complete default verification | Integrated baseline | Final candidate |
| --- | ---: | ---: |
| Successful allocation requests | 18 | 15 |
| Cumulative requested bytes | 153,600 | 104,448 |

The reduction is **3 requests and 49,152 bytes (48 KiB; 32%)**. The existing
glibc allocation observer counts successful allocation requests for one and two
verification loops; their difference divided by 24 is the per-call result.
This is cumulative requested memory, not peak RSS or maximum live memory.
Exact counts, proof fingerprints and artifact bindings are retained in the
[native observation summary](native-observation-summary.json).

After compilation, eight uninstrumented processes run in two consecutive ABBA
groups. Each process performs 512 complete native verifications on each of the
same 24 proofs. Each variant therefore completes **49,152 timed verifications**.

| Timed complete native loops | Baseline | Final candidate |
| --- | ---: | ---: |
| Aggregate observed thread CPU ticks | 2,850 | 2,620 |
| At the observed 100 ticks/second | 28.50 s | 26.20 s |
| Aggregate per-fixture monotonic wall time | 28.501197272 s | 26.219972349 s |
| Whole-process CPU, including preparation and observation | 28.831371 s | 26.489553 s |

The native-loop CPU difference is **about 8.07% lower in this capture**. All
observations remain included. Thread CPU resolution is 10 ms and timings vary
between processes; this finite single-environment observation establishes no
performance bound, public throughput, worst-case rejection cost or hardware
fairness. Repeated fixtures are not independent new challenges.

The local environment is x86_64 Linux with an observed eight-CPU-equivalent
cgroup quota and 8-GiB memory limit. It is not the original public Host envelope
and supplies no independent hardware attestation. The observation uses Rust
1.95.0, locked dependencies and the ordinary release profile. Baseline and
candidate have separate Cargo output directories and distinct compiled library
and executable hashes. The final candidate binary is
`a529d2fad39c0a944d882b2e63dd78f3cc8fc05503838a5484de6900f6bfad35`;
the baseline binary is
`f07cf6278c1e4da143a5fe991bd115170aba375656608f6f67a92810ce0e4dc2`.

### Earlier attempts remain visible

The first attempt shared one Cargo output directory across two source roots.
Cargo returned the baseline rlib as fresh for the candidate; both executable
hashes were identical. That comparison is **invalid for the candidate**, even
though every executable returned success. Its logs and explicit invalidity
record are retained separately.

The next isolated candidate removed the buffers but used two general modular
reductions per output cell. Its complete legal timing was slower in that small
capture. Those measurements and its exact intermediate source are retained.
The final source substitutes the bounded conditional subtraction described above;
the intermediate result is not relabelled as a final-source measurement.

These are exact primitive/reader observations made while the candidate tree was
being prepared. Parent commit IDs identify provenance. They do not claim that
an unmodified parent contains the change or that a final clean Git commit was
executed at the earlier measurement time. Final committed-source identity and
hosted qualification remain separate checks.

## Finite production-rate accounting

The existing V3 reader now retains every individual sample's setup, complete
attempts, misses/exhaustion, target hits, proof materializations, serialized bytes
and inclusive producer CPU. Exact integer fractions report attempts per CPU
second, recorded relation-valid hits per CPU second and hypothetical required-
work equivalents per CPU second. Aggregation is a ratio of sums; a hit counts
once despite being checked by four native verifier paths.

Any semantic alert suppresses validity-based rates across the entire shard,
including the older reciprocal cost metric. Observed attempt counts remain
visible. Common material preparation, evidence, verification and complete node
costs retain their separate scopes. Reuse horizons are not pooled, and no
network work share or confidence bound is inferred.

The [retrospective readback](legal-rates/README.md) checks all 84 archive members
and reprocesses all **30 legal V3 shards, 120 strategy groups and 960 sample
cohorts**. It retains 960 setups, 23,360 searches, 389,788 complete attempts and
23,360 hits, with zero exhausted searches, zero semantic alerts and zero removed
samples. All 61 historical descriptive timing flags remain visible.

Those clocks and native outcomes belong to historical source
`2b250859e7c07088e6c3c01f75006372c684de61`; this new analysis is not a native
measurement of the final verifier. The new reader itself is identified by
SHA-256 `88657a45b22a350c140ae8bcbe7f294544e8d9788c86592238cc9c6437bd58ff`.

## Validation and system boundaries

Native validation covers the three added arithmetic/permutation/cancellation
tests and eight existing complete legal-verifier controls. Existing M12/M09
regressions check that ordinary legal reorganization and reopen preserve pending
reconciliation, completed external effects and physical storage obligations.
They validate current owner behavior, not previously absent implementations or
independently operated public services. Exact outcomes and retained logs are
listed in [validation.json](validation.json).

| Executed local check | Result |
| --- | --- |
| Selected complete W1 arithmetic, permutation and cancellation controls | 11 passed |
| Existing M12/M09 and real Node reorganization/reopen controls | 6 passed |
| Native consensus arithmetic group, including its 75 independent integer vectors | 10 passed |
| Finite-rate reader controls | 18 passed |
| Query-work model controls | 21 passed |
| Source-integrity controls | 34 passed |
| Current-source pin controls | 34 passed |
| Full workspace, all-target, all-feature strict Clippy | Passed, `-D warnings`, pinned OpenSSL 3.5.9 |
| Workspace formatting and embedded source inventory | Passed |
| Locked native Linux all-feature Cargo graph | 26 workspace packages, 138 resolved nodes |

The original unfiltered offline Cargo metadata command failed because
`anstyle-wincon 3.0.11` is absent from the local cache. Its failure is retained.
The successful graph explicitly selects `x86_64-unknown-linux-gnu`; it is not an
unfiltered cross-platform graph result. No dependency or lockfile was changed.
The 27 selected native tests are not a claim that every workspace test ran.

No development DAA or confirmation parameter changes. The public confirmation
result continues to distinguish chain confirmation from finality and local
execution authority. In particular, this increment does not establish:

- a lower bound on the cheapest legal W1 producer, preprocessing advantages or
  cross-challenge reuse on all hardware;
- the original CPU rejection-cost condition or honest service within the
  original public Host/resource/business envelope;
- CPU/GPU/FPGA/ASIC/quantum production-share equivalence;
- new useful learning from the work or production-ready DAA/confirmation values;
- independent operators/evaluators, future storage availability, general safe
  model execution or economically funded public capacity.

The original 1,440-call rejection CPU ratio near 20.73 has a different scope and
denominator. Neither allocation savings nor this legal-only timing updates it.
All original work-hardness, public-readiness and activation flags remain false.

## Retained raw observations

[native-records-manifest.json](native-records-manifest.json) binds 281 exact
text records: final builds/launches/results, the slower intermediate candidate,
the invalid shared-cache comparison and the local driver sources. The
[encoded archive](native-records.tar.gz.base64) contains no native executables
or shared libraries. Their measured hashes are observations, not authenticated
execution or proof that a reader received those binaries.

Restore into a new directory without executing any native workload:

```sh
python3 evidence/pon-consensus-resource-v2-20261103/restore.py --out /tmp/pon-consensus-observation-records
```

The [restorer](restore.py) checks the encoded/archive hashes and every member's
identity, size and content. Its local readback restored all 281 members. Driver
paths identify the original local execution layout; a fresh measurement needs
its own source/toolchain/artifact binding and separate Cargo output roots.
