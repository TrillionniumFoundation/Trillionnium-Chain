# Independent checkpoint tile material replay V1

This is a separate native software relationship check. It does not install a task
selector, command, network, genesis, State, model release, source permission or work
qualification. Existing QWT1/lifecycle and PNW1 signed/wire bytes remain unchanged.
The [external recipe](CHECKPOINT_TILE_PROVENANCE_V1.md) remains historical input
provenance; this contract has its own descriptor and domains rather than relabeling
that recipe's descriptor as native admission.

The implementation is [checkpoint_tile_material_v1.rs](../../../../trillionnium/crates/trnm-mvcc-fee/src/checkpoint_tile_material_v1.rs),
with [controls](../../../../trillionnium/crates/trnm-mvcc-fee/tests/checkpoint_tile_material_v1.rs)
and a finite [local example](../../../../trillionnium/crates/trnm-mvcc-fee/examples/checkpoint_tile_material_v1.rs).
`CheckedCheckpointTileMaterialV1` has private construction. Its descriptor is a
read-only result, not a decoded caller certificate or ledger eligibility fact.

## Independent pinnings and exact original reads

`PinnedTileContextV1` independently fixes network/parameters, full checkpoint SHA256
and size, activation SHA256, and the expected QWT1 model/input hashes. Descriptor
claims cannot select these expectations. The reader must supply the complete actual
checkpoint. Hashing a tensor slice, trusting a file name or accepting a source's
signature alone is insufficient.

The checkpoint is at most 512 MiB. The initial u64LE header length is 2..16 MiB and
must fit the file. JSON forbids duplicate keys recursively and floating numbers;
its existing deserializer depth limit remains enabled. Each object has at most
8192 entries and each array at most 65536 entries, within its raw byte limit.
Tensor names are at most 256 UTF-8 bytes. Headers accept only tensor objects with
`dtype`, `shape`, `data_offsets`, and optional string-to-string `__metadata__`.
Dimension count is 1..8, dimensions are exact positive integers below 2^31, widths
and products use checked arithmetic. Sorted spans must cover the complete payload
with no gaps or overlaps. Metadata keys are at most 256 bytes, values at most 4096.

The selected original tensor is `model.layers.0.self_attn.q_proj.weight`, BF16
`[576,576]`. The selected output and input coordinates are exactly `[0,64)`.
After parsing the header, one full streaming read both computes SHA256 and collects
all selected BF16 rows. Parsed length/header bytes must equal that same hashed stream.
There is no un-hashed later tile read. An EOF extent check rejects added/truncated
bytes. The whole SHA includes unselected tensor bytes. Hash collision resistance
remains an ordinary SHA256 assumption, not a neural-work hardness claim.

The library accepts a `Read+Seek` and cannot promise filesystem type or an I/O
interrupt. The Linux x86_64 example rejects final symlinks/nonregular files with `O_NOFOLLOW`
and checks the same open checkpoint's identity, size and nanosecond modification/change
metadata before and after replay. It never reads keys. Complete original bytes are
required; there is no missing-file fallback. Other architectures/platforms return
an unavailable file-adapter error; a guessed ABI is not used. Hard wall/CPU/address-space limits belong
to the external bounded process supervisor. The callback reports cumulative original
read bytes between bounded operations; it cannot preempt a blocked read or JSON parse.

## Original input bits and integer quantization

The activation record is at most 1 MiB and uses the closed external
`checkpoint-qproj-postnorm-activation-v1` schema. It retains original F32LE bits,
shape `[1,T,576]`, exact tokens/mask/positions and observed CPU runtime fields.
`1<=T<=64`; unknown fields, Bool dimensions, dtype aliases, changed origin/scope or
noncanonical lowercase hex are rejected. Every original activation value is checked
for nonfinite bits, including coordinates outside the selected 64. The runtime/hook
fields are software observations; verifying their syntax is not execution attestation.

BF16/F32 quantization uses sign/exponent/significand integer arithmetic. Scale is
`2^14` for weights and `2^4` for activation; round nearest with ties to even, then clip
weights to `[-32767,32767]` and activation to `[-128,128]`. Large finite exponents are
clipped before an unsafe shift; subnormals and both signed zeros round exactly. NaN
and infinities reject. There is no approximate GEMM, float comparison or host-endian
conversion in the producer relation.

`A[out,k]` contains selected quantized weights; `B[k,token]` contains selected input
bits after quantization. Columns T..63 are explicitly zero padding. Each matrix is
4096 canonical u32LE values modulo 4294967291, exactly 16384 bytes. All values and
bytes are compared against the supplied expected A/B. The implementation recomputes
`H("artifact", A)` and `H("qualified-task-input-v1", B)` and the unchanged PNW1 task ID.
The full checkpoint root and installed artifact A root are distinct recorded identities.

## Closed result and current admission boundary

`derive_checkpoint_tile_material_v1` verifies original bytes before constructing the
checked value. `verify_checkpoint_tile_material_v1` also requires the closed canonical
sorted JSON descriptor to equal the recomputed result. Descriptor limit is 32 KiB.
Policy identity uses `checkpoint-tile-material-policy-v1`, result identity uses
`checkpoint-tile-material-receipt-v1`; fixed limits and numeric recipe are committed.
Unknown fields, trailing whitespace, changed coordinates/policy/hashes/counts or any
true acceptance field reject. This descriptor does not reinterpret QWT1 layer/recipe IDs.

`bind_admission` additionally compares network/parameters, exact model/input/task and
existing QWT1 layer/recipe against a source-signature/context-checked crypto
`DevelopmentTaskAdmission`. Its hash uses `checkpoint-tile-admission-binding-v1`.
It does not perform native branch slot eligibility, withdrawal, output consumption,
consensus execution, data-retention verification or an independently authenticated
model forward. The original Node owner must still check current parent slot/source
validity, withdrawal, replay and output consumption from actual chain State. The example uses
explicit known development source signatures and maintenance output limit zero;
it is not a production custodian or a fresh demand.

The result records actual clipping/nonzero/padding counts, dense base-product
262144 multiplies and `64*B_nonzero` sparse base-product multiplies. These are material
structure/component observations, not the cost of nonce-dependent transcripts,
preprocessing, fastest valid mining, a hardware-independent lower bound or usefulness.
Source signature, high rank, density and full-file membership do not certify hardness.
All chain authority, full-forward, genuine-demand, marginal-contribution and hardness
acceptance fields remain false.

Synthetic parser/numeric controls do not stand in for real checkpoint replay. A real
run must preserve independently pinned original checkpoint, activation, expected A/B,
all hashes, original-byte denominators, failed preparations/controls and bounded process
receipts. The external original Stage A artifacts are not embedded in the repository.
If unavailable, the corresponding real run is unavailable, regardless of unit success.

Making this relationship mandatory for a future chain or operator deployment requires
an explicitly reviewed selector with fresh parameter/network/genesis identity, signed
policy and binding, complete material availability and branch/current-source rules.
It cannot be silently activated by an opaque `source_record` digest or this sidecar.
