# Failed observations and attribution

This successor retains unsuccessful work and distinguishes a disproved attack
hypothesis from successful native verification. Nothing below changes a
production gate or constitutes a demonstrated false-statement attack.

## Zero-difficulty PoW malleability conjecture: disproved

The initial source-level question was whether skipped zero-bit grinding implied
that the serialized witnesses were ignored. That inference was wrong. P3 0.8.0
performs separate canonicality checks. The OOD witness is checked by the
uni-STARK verifier, and batching, commit and query witnesses are checked by FRI
before the skipped transcript PoW steps.

The native experiment changed one selected witness from zero to one at a time.
It tested OOD, batching, first commitment, last commitment and query witnesses
on each of SHA1, R3 packed4, SHA5 and R4 packed4. All twenty mutations passed the
shape scanner and all twenty were rejected by the original native verifier;
none panicked. The receipts retain exact mutated hashes, changed-byte offsets
and errors, including `NonCanonicalOodPowWitness` and phase-specific
`NonCanonicalPowWitness`. Original proof bytes and independently supplied
expectations were not replaced. There is no supported raw-proof dedup bypass.

The mutated binary files remain in the original remote evidence directories
`sha-v1`, `packed-v1`, `scheduled-v1` and `packed-r4-v1` under
`/home/qian-qi/work/w1-security-r4-evidence-f16ac`. The small committed receipts
record them without duplicating approximately forty megabytes of proof bytes.
The successful probe source includes deterministic mutation/reproduction logic.

## Native build v1: failed, exit 101

[artifacts/build-v1/receipt.json](artifacts/build-v1/receipt.json) retains the full
compiler output. Deriving `Debug` for the wrapper required the native AVX2
Poseidon2 external layer to implement `Debug`, which it does not. This was an
instrumentation build defect. Removing the unnecessary `Debug` derives from
the counting permutation/challenger made build v2 succeed. No protocol or
cryptographic parameter was changed to make the build pass.

The failed source is retained at
[artifacts/build-v1/failed-probe.rs](artifacts/build-v1/failed-probe.rs), SHA-256
`3d8dc605f589d01e59f2bbbe1f80f6ade33b0daa7f25f2ea1b88af537c9c3d65`.
The successful R3 source is retained at
[artifacts/probes/r3-v2.rs](artifacts/probes/r3-v2.rs), SHA-256
`d0fcb79f5f5ef2178bfa00e223fb37fe21f05c8e44e50f3a53443ea21e260857`.
Its native run is [artifacts/native-run-v1.json](artifacts/native-run-v1.json).

## Profile 5 attribution

Build v3 fast-forwarded the isolated worktree to backend code commit
`eb944645cc3e30af5955edf9dbbcb43488fa38c1`, added the ScheduledShaAir branch to the
probe and formatted the example. Its source SHA-256 is
`1d2deb4e6e79877de6a21ab2fcc2d0dedb7fcf86fa92c0f808a48ebc980c096e`.
The R3 receipts remain attributed to `cc836dfc`; they were not relabelled as
profile-5 observations. New native runs, immutable fixture hashes, probe/binary
hashes and before/after equality are retained in
[artifacts/native-run-v2-profile5.json](artifacts/native-run-v2-profile5.json).

## Retrieval and transport limitations

The direct CO25 PDF fetch returned HTTP 403. The retained retrieval receipt
records its URL and timestamp. The report uses inspected primary abstract,
metadata and slides without inventing missing constants. The BGK proceedings
copy and the three new official crate archives were fetched successfully with
their hashes. Source retrieval and theorem applicability remain different
questions.

Host-tool reads occasionally reported SSH admission capacity exhaustion before
submitting a child. Those are transport non-executions, not verifier results.
Durable launched jobs used stable identities, and their outputs were retrieved
by lossless byte cursors. No timeout or unavailable artifact was converted into
a passing test. Subsequent actual native and checker failures, if any, must be
preserved alongside their corrected successors.

Delivery v1 additionally exceeded the single shell-source limit, and a local
output-token truncation contaminated its base64 payload. Its first split part
failed Python parsing; the other parts were never assembled or installed. The
exact observations remain in
[artifacts/delivery-transport-v1.json](artifacts/delivery-transport-v1.json).
Delivery v2 checked the complete base64 alphabet, decompressed the payload
locally, and checked both the full payload SHA-256 and every part SHA-256 before
installation. The subsequent real source/receipt checks passed. This failure
affected delivery only, not the already completed native measurements.
