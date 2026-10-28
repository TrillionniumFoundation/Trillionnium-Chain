# Full W1 staged proving experiment

This remains the complete `PNH1` / `PNW1` relation. The guest and native W1
arithmetic are unchanged. No Node dependency, consensus version, work identity,
work weight, network authorization or fallback is introduced. Every optional
randomness choice in proof generation contributes **zero additional tickets**.

## Predeclared experiment

The first new experiment uses the exact original public `input-0.bin`, freshly
rebuilt complete guest, pinned official local RISC Zero 3.0.3 backend and guest
Rust 1.88.0. Segment limit is 18 and Rayon concurrency is 8. The machine exposes
an 8 CPU cgroup quota, 8 GiB memory limit and no NVIDIA device. This is a local
resource experiment with no cloud prover or paid infrastructure fallback.

Preparation has a 180 second bound. The first **actual** segment proof has a
300 second wall bound. Only after that measurement will continuation receive a
new explicit time bound. The old one-hour run is retained as a failed full-proof
attempt, never pooled with the new configuration or removed from the denominator.
If a segment completes, its saved cryptographic receipt and raw output are
retained before later work. If recursion cannot run or exceeds resources, the
full proof gate stays open with that precise substage identified. One proof
cannot establish a prover p99. Concurrent builds or other agents' campaigns
must be disclosed; no isolated throughput or latency is inferred from overlap.

## Checkpoint statement and verification

`w1-staged-prover --r0vm ABSOLUTE_PINNED_BINARY prepare NEW_DIR INPUT_FILE 18`
exports every actual executor segment. It records the clean exact Git commit,
runner bytes, guest bytes/image ID, full input, full journal, original successful
claim, backend digest, segment order, sizes and asset digests. The journal is
checked against the exact native complete verifier. Successful execution and
all exports are necessary before a complete manifest is written.

`... prove DIR 1` proves one previously unproved segment. Existing receipts are
cryptographically verified again; source, runner, input and image must match the
frozen manifest. Each receipt must have the expected index and continuation
pre-state. Every nonfinal segment must split without output. The last must halt
successfully with the full expected output and no assumptions. Saved receipts
use bounded decoding that rejects trailing data. Files use `create_new` and
`fsync`; partial files are retained and rejected, never silently repaired.
`... prove DIR 0` only checks the existing prefix, without creating new proofs.
A successful prefix command is explicitly **not** a full-proof result.

`... compress DIR` requires every segment in the original order. It opens only
the last output whose digest already equals the original full statement,
constructs an internal Composite receipt and verifies its cryptographic
continuation, full original image, successful halt, journal and empty assumption
set. A missing, permuted or differently terminated segment fails this gate.
The intermediate Composite cannot satisfy the experiment's final acceptance.
Only actual recursive compression to `Succinct`, then verification and saved
bytes, qualifies for a fresh-process check using the existing strict
`trnm-w1-zk-host verify HEADER_FILE RECEIPT_FILE` command. The existing decoder
rejects Composite, Fake, Groth16 and trailing encodings before accepting input.

The local manifest is not a new cryptographic certificate. A malicious local
editor can change it; final acceptance still requires the original complete
cryptographic image and statement. Individually verified segment prefixes prove
only their execution intervals; they do not certify completion or all private
input constraints. There is no final-success shortcut for execution, partial
segments or internal Composite verification.

## Costs and source lineage

The supervisor in `../experiments/w1_stage_measure.py` persists declared commands,
raw stdout/stderr and the kernel's `wait4` usage. That usage covers its child and
descendants the child actually reaped. If a stage is killed, CPU is potentially
incomplete; largest single-process RSS is not an aggregate process-tree peak.
Preparation, every resumed prefix verification, failed stages, per-segment
proving, complete Composite validation, recursion and final verification are
separate costs. None may be omitted when reporting end-to-end full-proof cost.

This is new reproducible source. It does not restore the lost second-run carry
kernel or turn conversation readbacks into recovered raw measurements. The
original dense full relation is retained so that a successful receipt covers
all canonical decoding, task/target binding, noise rejection, matrix product,
transcript prefixes, ticket and block identity checks.

Primary implementation references are the official tagged RISC Zero 3.0.3
[API client](https://github.com/risc0/risc0/blob/v3.0.3/risc0/zkvm/src/host/api/client.rs),
[prover pipeline](https://github.com/risc0/risc0/blob/v3.0.3/risc0/zkvm/src/host/server/prove/prover_impl.rs)
and [Composite verification](https://github.com/risc0/risc0/blob/v3.0.3/risc0/zkvm/src/receipt/composite.rs).
The SDK's transparent STARK construction alone is not a proof of 128-bit quantum
security, useful PoN anti-shortcut work, DAA stability or production economics.

## Continuation declaration after actual first-segment measurement

Source `aea6edd72670d12edb817ef5e6d32ff60cd18cc7` produced a real segment-0
receipt: 63.233552735 seconds proving, 18.215207 milliseconds verification,
255,842 bytes. The bounded process measurement was 64.318867810 seconds wall,
428.359577 CPU seconds and 2,468,683,776 bytes maximum single-process RSS.
This is one of 59 original full-relation segments, not a complete W1 proof.
Concurrent compilation occurred and the raw stage logs retain exact timestamps.
Multiplying the first prover time by 59 gives an approximately 62.2 minute
**projection** for segments alone, not a measurement or a tail estimate.

The next source version exports the identical full guest/input again, then
`... import-prefix NEW_DIR OLD_DIR` requires the same image, input, journal,
full segment list and every actual segment asset digest. It cryptographically
verifies every imported seal and its continuation. The prior manifest, source,
runner, receipts and entire stage history are retained, and prior costs remain
in the experiment denominator. This explicit source transition does not permit
changing a work relation or accepting a claimed checkpoint without its proof.

`... lift DIR 0` performs an actual recursive lift of that saved real segment,
with a 300 second calibration bound. A lift of a prefix is not an entire-W1
receipt. Compression checkpoints each actual lift and ordered join, verifies
each saved seal and its exact range claim on reuse, and still requires the full
original successful claim and strict final receipt verification.

After the current History/PQ controls finish, run all 59 segments with a
**5,400 second cumulative bounded-stage wall budget**, including the completed
first-segment and preparation/lift stages, and at most 300 seconds for each new
segment invocation. This budget is informed by an actual proof measurement.
Source/build work and pauses are reported separately. Any full run that runs
out of budget remains incomplete; all completed receipts and raw failed stages
survive. Final compression uses the remaining declared budget and retains its
own per-lift/per-join progress. A fresh process verifies the saved complete
Succinct receipt and reports 100 fixed-receipt verification samples; these do
not establish a population prover p99 or a production verifier tail.

The first export occupies approximately 3.3 MiB including its one receipt.
At the observed receipt size, 59 segment receipts would occupy approximately
14.4 MiB. Reserve 256 MiB for all segment/recursion receipts and logs; record
actual disk usage and stop before starting another stage if shared free space
falls below 1 GiB. Build caches remain outside the repository. The expected
proof benefit is an open question: a complete cryptographic result can still
fail package 2A if its size, verification or generation cost loses to native W1.

## Whole-session adoption after the import refusal

The second execution/import attempt under source `16fcadcee30a9f749adaaab04ce5e856a4721d0d`
was retained as a failed import. The image, original input, journal, segment
counts, cycles and byte lengths matched, but segment-0 differed in 48 bytes:
32 bytes in its post-state claim and 16 bytes in its first host-read record.
Both actual executor logs record `SYS_RANDOM: 4`. In pinned upstream source,
that syscall supplies four u32 words from fresh host randomness. The serialized
segment contains both its claim and the recorded host-to-guest reads. This is
why identical public input does not imply identical intermediate VM state.

The raw asset equality check remains strict. `... adopt-execution NEW_DIR OLD_DIR`
copies **all 59 original frozen segment assets together**, after checking every
original digest and the exact original full input/image/journal. It preserves
the original execution manifest and explicitly records the old execution source
and the new runner source in a fresh adoption record. It does not claim a new
execution or create a proof. `... import-prefix NEW_DIR OLD_DIR` then imports
only cryptographically verified original receipts with that same entire session.
Freshly randomized second-execution assets are never mixed with first-execution
receipts. All second-attempt preparation/import costs remain in the run ledger.
