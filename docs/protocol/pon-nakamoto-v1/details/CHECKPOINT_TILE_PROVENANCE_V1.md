# Checkpoint tile recipe — external development contract v1

This specifies an external, bounded material adapter. It installs no wire codec,
source authority, cost class, checkpoint inclusion proof or model reward. The current
chain continues to admit the [QWT1 material contract](QUALIFIED_WORK_TASK.md) and
[full matrix transcript](WORK_PROFILE.md). All production, public, independent,
hardness, full-forward and marginal-contribution acceptance remains false.

## Original file, tensor and coordinate commitments

The named development recipe is `checkpoint-qproj-prefix64-material-development-v1`.
Its original source is SmolLM2-135M revision
`12fd25f77366fa6b3b4b768ec3050bf629380bac`, a 269,060,552-byte `model.safetensors`
with SHA256 `5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c`.
Hash the complete original file; a file name, model name or raw slice does not prove
membership in that file. Reject a changed file identity/size/metadata during replay.
Reject final symlinks and nonregular files. An external supervisor must separately
enforce wall/RSS budgets; a byte limit alone is not an I/O deadline.

Read the first eight bytes as a little-endian u64 header length. The external recipe
limits that header to 16 MiB, rejects duplicate JSON keys, and permits only tensor
objects with `dtype`, `shape`, `data_offsets`, plus a string-to-string `__metadata__`
object. Check integer dimension/offset types, dtype byte widths, exact element counts,
in-file bounds, ordered nonoverlap, no gaps and exact payload coverage. This is a
recipe-specific accepted subset, not a claim to support every safetensors file.

The actual target is `model.layers.0.self_attn.q_proj.weight`, BF16 `[576,576]`.
Recorded payload-relative offsets are `[62818560,63482112]`; the observed header is
30,528 bytes, so these offsets exclude the eight-byte length and header. Independently
check them against the actual pinned header, not these printed numbers alone. Select
output coordinates `[0,64)` and input coordinates `[0,64)`, with row stride 576.
Read each of the 64 selected rows as exactly 128 BF16LE bytes.

## Activation observation and exact quantization

The activation record schema is `checkpoint-qproj-postnorm-activation-v1`, with exactly
these fields: `schema`, `checkpoint_sha256`, `dtype`, `shape`, `token_ids`,
`attention_mask`, `positions`, `hidden_hex`, `producer_script_sha256`,
`prompt_utf8_sha256`, `runtime`, `activation_origin`, `scope`. Limit the record to
1 MiB. Its accepted dtype is `F32LE`, shape `[1,T,576]`, integer `1<=T<=64`;
`hidden_hex` contains exactly `T*576*4` original bytes. Reject Boolean dimensions,
unknown fields, duplicate keys, wrong lowercase hex lengths and dtype/endianness aliases.
Token IDs are integers below 49152; mask is exactly T ones and positions are `0..T-1`.
No truncation or undeclared padding changes an input observation.

The development capture uses one CPU float32 base-model forward, no LoRA or training,
and a pre-hook on layer-0 `q_proj`. Retain its input bits and check exact equality with
the observed layer-0 input-RMSNorm output. Origin is
`actual-layer0-q_proj-prehook-post-RMSNorm`. Commit the public prompt, actual tokens,
material manifest and capture source hash. This is an operator's software observation,
not a cryptographic proof that every earlier/full decoder operation was executed.

The closed `runtime` fields are `device`, `python`, `torch`, `transformers`,
`safetensors`, `numpy`, `threads`, `base_only`, `training`, `local_files_only`,
`trust_remote_code`, `forward_calls`, `hook_calls`, `parameter_count`, `storage_dtype`,
`material_manifest_sha256`. The observed recipe uses CPU, two threads, one forward/hook,
134,515,008 parameters, float32 storage, local files and no remote code or training.
Version strings are bounded observations, not signed software attestations.

Decode each BF16/F32 original sign, exponent and significand as an exact rational.
Reject NaN and infinities. Multiply weights by `2^14` and activation by `2^4`, round
to nearest with ties to even, then clip weights to `[-32767,32767]` and activation
to `[-128,128]`. Commit scales, rule, exact original ranges and every clipping count.
Positive/negative zero map to integer zero; retain their original byte commitments.
Do not substitute approximate floating equality, decimal input or platform-native endian.

Define `A[out,k]=weight[out,k]`, `B[k,token]=postnorm[token,k]`. Both matrices have
4096 canonical Fq u32LE values, 16,384 bytes each, q=4294967291. Columns T through 63
of B are declared zero padding. Negative integers map modulo q. The integer product
has absolute bound `64*32767*128=268427264<q/2`, permitting unique signed recovery.
`C*2^-18` is this quantized 64-coordinate partial sum. It is not the original 576-input
projection, attention, LoRA-modified layer or entire floating-point model forward.

## Public descriptor, replay and existing chain boundary

An external descriptor commits the schema and original file SHA/size; tensor
name/dtype/shape/offsets and header hash; selected coordinate spans and matrix layout;
activation SHA/shape/T and exact padding columns; adapter source SHA; closed
quantization fields; modulus and A/B/signed-i64LE-C hashes; and the explicit false
acceptance fields. Encode one canonical sorted JSON object with no duplicate/unknown
fields. Its identity is SHA256 of those exact bytes. Full replay must recheck the
original file/header/activation and compare every derived A/B value and descriptor
field; a descriptor digest or freely constructed decoded object is not admission.

The closed descriptor field groups are:

| Group | Exact field names |
|---|---|
| Original tensor | `schema`, `checkpoint_sha256`, `checkpoint_bytes`, `tensor`, `tensor_dtype`, `tensor_shape`, `tensor_data_offsets`, `safetensors_header` |
| Coordinates/input | `output_coordinates`, `input_coordinates`, `matrix_layout`, `activation_sha256`, `activation_shape`, `real_token_columns`, `zero_padded_columns` |
| Replay/numbers | `source_module_sha256`, `quantization`, `field_modulus`, `matrix_a_sha256`, `matrix_b_sha256`, `signed_product_i64le_sha256`, `scale_product_power` |
| Scope | `existing_QWT1_provenance_activated`, `native_source_registered`, `full_projection_or_forward_proved`, `marginal_contribution_accepted`, `hardness_qualified`, `scope` |

`safetensors_header` has exactly `header_bytes`, `header_sha256`, `tensor_count`.
`quantization` has exactly `weight_scale_power`, `activation_scale_power`, `rounding`,
`weight_clip`, `activation_clip`, `weight_clipped_count`, `activation_clipped_count`,
`nonfinite`, `signed_zero`, `weight_exact_range`, `activation_selected_exact_range`.
The ranges use reduced exact-rational strings; counts/spans/scales use exact integers,
not booleans or floats. Full replay regenerates all these values, not just hashes.
Reject changed coordinates/scales/padding/source/activation identity, noncanonical
field values and any changed A/B byte. Every scope acceptance Boolean above is false.

In the existing [Rust QWT1 codec](../../../../trillionnium/crates/trnm-protocol/src/qualified_work_task.rs),
`model=H("artifact",Araw)` and `input=H("qualified-task-input-v1",Braw)`.
`layer_id=H("qualified-task-layer-v1",model,"entire-row-major-field-layer-64x64")`;
`recipe_id=H("qualified-task-recipe-v1","canonical-field-matrix64-product-v1")`.
These name the entire derived 64x64 field-material contract. They do not name the
checkpoint's layer-0 tensor, original 576-dimensional coordinates or extraction recipe.

A fresh operator deployment may publish the external descriptor and bind its digest
in `source_record`, with strict source/requester approvals under the fresh N/P context.
The native lease binds that opaque source commitment; it does not replay this adapter
or verify the underlying checkpoint/activation provenance. Availability commitments
for A/B do not certify retention of the whole checkpoint or future data availability.
`chain_checkpoint_mapping_verified` and `native_checkpoint_provenance_activated` must
stay false; using the matrices as maintenance requires `useful_output_limit=0`.
No current PNW1 extension/trailing slice is accepted. Installing extraction verification
would require its own reviewed, versioned signed/wire/profile/genesis contract, explicit
data limits and malformed-proof costs; publishing a sidecar cannot activate it.

## Structured preparation costs and required qualification scope

An external ordinary offline prototype observed T=10 and 54 padded columns. Only 140
B entries were nonzero. A legitimate sparse base-product algorithm therefore uses
`64*140=8960` multiplications, versus a dense loop's 262144. All 4096 signed outputs
and all 4096 outputs modulo q matched the same gold in 32 samples of each implementation.
The separately observed B index preparation was excluded from those per-product samples.
This is an AB-material preparation comparison, not nonce-dependent transcript mining,
verification, total preprocessing, fastest possible mining or an adversarial lower bound.
The external execution receipts/source snapshots are not yet published in this repository;
these observations cannot serve as repository-replayed qualification evidence.

Two ordinary maximum-target proofs under different challenges retained the same base
AB output while their transcripts differed. They were local scalar replays, not actual
chain/header-nonce experiments. Fresh consensus challenges do not by themselves create
new LLM/learning output. Useful-output deduplication and maintenance output limit remain
separate from lottery work. Sparse AB does not establish that the challenge-masked
transcript can be computed at the same sparse cost.

A qualified effective cost class must specify padding and actual nonzero/rank structure;
valid task/lease choices available to producers and funded requesters; matrix selection;
reuse across nonces, blocks and renewals; independently retained preprocessing and total
search costs; fastest implemented valid producer candidates, their memory/hardware and
per-attempt resources; full honest/invalid verification and admission costs at the same
target; and distinct useful outputs/adoption. Keep slow samples and failures. A logical
multiply-add count, dense baseline, one implementation or a faster observed method is
not an unavoidable lower bound, hardware fairness certificate or public-cost acceptance.
