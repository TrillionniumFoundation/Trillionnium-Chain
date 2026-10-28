# One-leaf conditional receipt and real resolve pilot

**Status: new host-only source, not yet compiled or executed.** The preceding
[actual build](../../../evidence/pon-w1-batch-build-20261028-r8/README.md)
preserves a baseline host and the guest image. No proof success, cost saving,
tail bound, quantum theorem or production acceptance is claimed by this plan.

## Exact statement and input

The staged command accepts exactly one existing complete leaf, SHA-256
`ca4d3c9f5159b7001abae7491604cadbbbfa97c0f93d90d5943e48936813ca2b`, original
work ID `ccf544056c6df13a5ab4e6c021e587ff0008d92388270e64f72a6e2168a326cd`.
The normal loader must first verify that actual receipt with the frozen full-W1
image and empty assumptions, then derive its identity from proved bytes.
The manifest cannot supply a claim, work identity or image override.

The staged host also requires the actually compiled batch guest SHA-256
`734eb42893951b0915f86e4517a231b04279ace8f8d81ca2dd79d6ed95771219` and image
words `[1000984451,3139256748,3364805072,2363167537,26593440,771198122,3700220126,2888495343]`.
Guest, statement, methods, both independent locks and SDK 3.0.6 remain unchanged.
No full original leaf is reproved. Repeated references to this leaf remain one
work, even if several batch/conditional/resolved proof artifacts are produced.

## Actual protocol exercised by the host

1. Execute the fixed batch guest with the actual verified leaf receipt as an
   assumption and request a genuine composite proof from the pinned local
   `r0vm 3.0.3`. Preserve the bounded returned receipt before validating it.
   Require the full expected journal, one attached succinct leaf, successful
   composite verification and the original leaf assumption in the last segment.
2. Lift every segment from **that one batch session**. Join only consecutive
   segments from that same session. Save each returned inner receipt, verify its
   actual STARK, and check that lift/join preserves the expected segment or
   continuation claim. There is no join of independent leaf executions.
3. Save the real unresolved conditional receipt, reload its bounded wire bytes,
   verify its inner STARK and match the complete expected claim: fixed batch
   image, zero input, successful halt, final post-state, full journal and exactly
   one assumption equal to the verified original leaf claim with zero control
   root for self-composition. Open and inspect the actual nonempty assumption.
4. Call the real final `Receipt::verify(compiled_batch_image)` and require
   rejection. The expected `ClaimDigestMismatch` diagnostic is checked only
   after the successful proof and whole-claim checks. A damaged seal, fabricated
   claim, wrong image or malformed metadata cannot substitute for this control.
   Also retain and actually reject the valid original leaf under the wrong
   batch image; that is a second existing-proof negative, not new work.
5. Call the real local API `resolve` with the retained conditional proof and the
   already verified original typed leaf proof. Preserve and verify the returned
   STARK, require its complete claim to equal `ReceiptClaim::ok` with the same
   image and journal, require empty assumptions, and require actual final
   `Receipt::verify` success. Save and reload `succinct.bin`, then run the normal
   batch verifier and identity checks again.

Expected `ReceiptClaim` values are comparison targets only. They are not
provided as assumptions, witnesses or substitutes for receipts. The code is in
[staged.rs](host/src/staged.rs); the bounded loader and final verifier remain in
[main.rs](host/src/main.rs).

## SDK details that determine correctness

The pinned 3.0.6 client exposes `lift(opts, Asset, AssetRequest)`,
`join(opts, Asset, Asset, AssetRequest)` and
`resolve(opts, Asset, Asset, AssetRequest)`. Inputs are bincode encodings of
typed segment or succinct receipts. All requests use `AssetRequest::Inline`
and convert returned typed receipts back to `Asset`. A `Path` output would be
protobuf and cannot be blindly reused as a bincode input. The resolve API
expects a typed `SuccinctReceipt<ReceiptClaim>`; the server performs its own
`into_unknown` conversion after decoding the actual receipt.

`CompositeReceipt::claim()` removes assumptions whose receipts are attached.
It therefore cannot demonstrate the genuine unresolved conditional statement.
In addition, the current `Receipt::verify_integrity_with_context()` also
requires empty assumptions. The pilot uses the inner succinct STARK verifier
plus a complete explicit conditional-claim comparison, then calls the actual
final verifier to observe rejection. The public API's normal narrow version
checks remain active. No compatibility override, default/remote backend, fake
proof, claim-only assumption or development mode is enabled.

These API findings were checked against cached official SDK source and
independently reviewed read-only. Source reasoning is not a substitute for the
planned real proof and negative-control run.

## H0: normal host rebuild and qualification

Changing host code requires a new native host binary and its actual SHA-256.
The guest needs no semantic rebuild. Use ordinary offline Cargo with the same
complete official 1.91.1 compiler, supported isolated `RISC0_HOME`, locked
graphs, one Cargo job and no incremental compilation. Do not set skip-build,
modify the guest, replace generated methods or disable version checks.

Proposed one-attempt envelope: **180 wall seconds, 360 child CPU seconds,
2.5 GiB sampled process-tree RSS, 256 MiB target growth and a 1 GiB free-disk
floor**. Use the existing namespace-safe supervisor. It is a separately
declared candidate budget, not permission to execute or automatically retry.
It includes the normal release host build, retained release workspace tests,
release workspace/all-target strict Clippy and formatting/source/lock checks.
Any actual methods/guest rebuild is included in this same envelope. Compare
the final guest bytes and image with the preserved attempt5 artifact and fail
if they differ. Preserve the normal Cargo/cache observations and all failures.

Only an actual successful, source-bound H0 receipt supplies the new host hash
for P1. A future binary hash is not invented here. The old successfully built
host is preserved separately and is not claimed to contain this new command.

## P1: one 600-second attempt

After the new host's real build/qualification result is reviewed and its hash
bound, run the new staged command under one fresh outer budget:

```sh
env RAYON_NUM_THREADS=8 \
    /tmp/trnm-w1-r2-target/release/trnm-w1-batch-host \
    prove-staged --r0vm /tmp/pure-pon-risc0-3.0.3/r0vm \
    formal/pon-nakamoto-v1/w1_batch/examples/one-leaf.json \
    /tmp/trnm-w1-staged-r8-one-leaf/pilot
```

The external runner must first verify the exact newly built host, current
source/tree, both locks, compiled guest and the pinned r0vm SHA-256
`2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6`.
The unchanged proposed proof limits are **600 wall seconds, 4,800 child CPU
seconds, 3.5 GiB sampled RSS, 512 MiB proof-directory growth and a 1 GiB
free-disk floor**. Actual session-segment files are placed inside the measured
proof directory. The guest stays capped at 2^24 cycles with 2^18-cycle segments;
the host caps the returned composite at 16 MiB and at most 64 segments.

One absolute deadline covers preparation, composite proving, all lift/join
steps, the valid conditional negative, actual resolve, output verification and
fresh-process `verify`, `verify-many` and `controls` commands. Those final
commands do not obtain a second time budget. Complete logs, all returned
bounded proof artifacts, session files, mutants, failed/timeout stages and
observer accounting gaps remain retained. No automatic retry, partial-receipt
resume, new full leaf proof or post-timeout deadline reset is allowed. Sampled
resource triggers are not kernel cgroup hard limits.

## Interpretation

A successful pilot establishes only actual one-leaf composition and observed
cost for this source, backend and envelope. It does not establish proof tail
latency or batch benefit. The complete leaf already incurred at least
41,887.28597837 observed CPU seconds in its earlier pipeline. That cost and all
failed builds/setup must remain in the complete ledger, separately from this
incremental calibration. Thirty-one different works is an arithmetic verifier
screening threshold under unmeasured constant-cost assumptions; it is not an
executed denominator or a solution to full-leaf prover economics. Remaining
parent/task-window/M06/authorization checks retain their costs. Quantum
soundness and independent multi-operator WAN acceptance stay open.
