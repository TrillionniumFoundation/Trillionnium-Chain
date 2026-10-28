# Finite transparent W1 recursion research

This separate research driver measures whether the actual, complete original
W1 Composite STARK can become a smaller transparent Succinct STARK without
changing its guest, full public input, image, claim, or additional-PoW-off
relation. It grants no Node admission or consensus authority. No new Succinct
proof or cost result exists at source freeze; the hosted workflow must produce
and verify it before a positive result can be reported.

## Exact input and proof chain

[policy.json](policy.json) pins the successful a54 run `40608715148`, artifact
`12784520070`, its 80,366,759-byte ZIP and the original 15,862,780-byte receipt
`0a5336a797c51829ed25d4ec2f1a03f4f56fda4c737a230b493d4abbe96f0ec8`.
The complete original artifacts are durably recorded in
[#529](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/529),
commit `303afe7a4581e67117bff135eed5892232aabb70`. The original result and
its failures remain in the
[complete W1 evidence](../../../../../evidence/pon-w1-complete-a54-20261028/README.md).
The new fetch checks the exact successful run, all three original source
snapshots, archive SHA-256, member inventory, and original image/input/receipt
bytes. It never executes a fresh guest or generates replacement segment proofs.

The unchanged Composite verifier and a new native `prepare` command both
verify the actual original proof before any recursive proving. `prepare`
also independently executes the complete native W1 relation and checks its
public journal. Nine native negative controls require refusal of substituted,
truncated, trailing, nonregular material and output overwrites. These controls
are a mandatory hosted gate, not simulated proof acceptance.

The graph has exactly 62 ordinary lifts and 61 ordinary contiguous joins.
Every leaf is an original segment; every result is checked with the official
SDK STARK verifier against the exact original range claim, and every join
checks the neighbouring pre/post state digests. SDK 3.0.6 and recursion circuit
4.0.5, ordinary lift/join program IDs, Poseidon2 control root, po2=18, verifier
parameters and depth-eight control inclusion proofs are fixed. Development
receipts, Groth16, PoVW and remote proving are not permitted. The root then
passes full SDK image/successful-exit/empty-assumptions/journal verification.

The sibling crate uses the original shared dependency versions and checksums.
It does not alter `w1-risc0`, its lockfile, any of its 30 source pins, the guest
ELF, or the old Composite acceptance policy. Its native source and new policy
are included in the normal generated distributed-source inventory.

## Independent finite cost window

The entire new recursion graph, preparation and root finish share one
3,500-second work window and one 3,600-second outer timeout. There are at most
two workers, each with two Rayon threads and a 300-second stage cap. The
unchanged resource gate requires four effective CPUs and 8 GiB observed
available memory. A failed or expired window does not resume or retry. Every
completed stage, partial receipt, started/terminal record, raw log, actual
CPU/wall/RSS cost and owned-family cleanup outcome is retained after failure.

Sixteen independently bounded outer phases record installation, fetching,
builds, controls, compression, verification, rejection and transport costs.
Stage CPU is already included in `compress` and is not added twice. Checkout,
runner provisioning, preflight/source readers, record copies and artifact
upload are explicitly outside these phase CPU totals and remain in the raw
hosted job log. These are incremental costs of obtaining a new proof from an
existing complete receipt, never a complete from-zero W1 generation cost.
The original failed 3,500-second proof window and both original continuation
windows keep their own accounting.

## New research certificate and complete propagation measurement

`PWSR0001` is a fresh research namespace: eight magic bytes, two little-endian
u32 lengths, all 49,640 original public-input bytes and the complete new
Succinct receipt. The allocation-free receipt scanner rejects foreign receipt
kinds, excessive lengths/dimensions, unsupported claims, and trailing bytes
before bincode deserialization. The original `PNW1` fixed 49,188-byte codec
and the existing 1 MiB packet cap are unchanged.

If a complete Succinct proof exists, the workflow records 31 actual verifier
samples, all 17 proof-negative controls and seven full-certificate negative
controls. Loopback sends the **whole certificate**, including its full input,
through actual IPv4 TCP. Fresh native verifications run before sending and
after receiving, each with the unchanged 900-second cap; transport has a
30-second cap. The receiver checks magic, exact lengths, the total length,
the original input bytes and the official proof using the received input and
receipt. It does not substitute a local public input for received bytes.
Payload/framing/CPU/wall observations are local loopback observations, not WAN
or public-ingress qualification.

Capacity fields compare the measured certificate against 1 MiB. The optional
318-byte-header plus 256 transactions of 2,048 bytes calculation is explicitly
the **legacy transaction profile**; it is not a general bound for PQ
transactions. Even a certificate that fits the byte budget is not accepted by
the current Node codec. Compression and public-input binding do not by
themselves establish QROM security, complete recursive composition bounds,
PQ-128 security, production throughput, or the global worst invalid input.

## Reproduction and sources

The standalone workflow is
[pon-w1-succinct-research.yml](../../../../../.github/workflows/pon-w1-succinct-research.yml).
Its paths trigger this new finite experiment independently of the completed
Composite proof workflow. It checks the exact source before and after work,
uses `--locked`, runs native tests, formatting and strict Clippy, and retains
failure artifacts. Local controls and resource limits are recorded in the
[source-freeze evidence](../../../../../evidence/pon-w1-succinct-research-20261028/README.md).

The reviewed primary implementation is RISC Zero commit
[`1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`](https://github.com/risc0/risc0/tree/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9):
`zkvm/src/host/api/client.rs` ordinary `lift`/`join`,
`zkvm/src/host/recursion/prove/mod.rs`, `zkvm/src/receipt/succinct.rs`,
`circuit/recursion/src/control_id.rs`, and `zkp/src/verify/mod.rs`.
The exact local registry source hashes reviewed are retained with the evidence.
The official [SuccinctReceipt API](https://docs.rs/risc0-zkvm/3.0.6/risc0_zkvm/struct.SuccinctReceipt.html)
describes a recursive STARK; the separate
[security model](https://dev.risczero.com/api/security-model) documents
conditional soundness assumptions rather than a PQ-128 qualification here.

## Continuation of the observed failed recursion window

The first hosted recursion at `bfdb557412204244e43fef2007c31e20c9c8e5ff`,
run [40624205143](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40624205143),
reached the original 3,500-second work stop. Its 115 closed stage terminals comprise
one preparation, 112 successful recursion stages and two interrupted joins.
It did not produce a complete Succinct receipt. The original failure remains a failure.

The separate `continuation.py`/`continuation_policy.json` profile consumes only its
exact 122,897,597-byte, SHA-256-pinned artifact. It binds all extracted original
records to the full retained ZIP, checks the exact source/tree and closed process
family, rechecks all 112 retained STARKs against the original contiguous range
claims, and generates the 11 missing stages. Current and original source identities
and process costs remain separate. The original Rust relation, SDK locks,
2 MiB decode cap, two workers, two Rayon threads, 300-second stage limit,
3,500-second work stop and 3,600-second outer limit are unchanged.

The final reader requires every retained and new stage, original native controls,
the complete proof, 31 verifier samples, all 17 proof and seven certificate
negative cases, and received-certificate verification after actual TCP transfer.
Both windows' exclusive outer process costs include the failed work and rechecks;
included stage costs are never added again. Composite generation, provisioning,
source readers and artifact upload remain separately identified exclusions.
No result here claims a from-zero measurement, a global invalid-input maximum,
WAN qualification, PQ128, a production codec change or activation.

Actual new-source native completion must be obtained from its hosted run.
The prior 112 successful stages do not establish that the continuation succeeded.
