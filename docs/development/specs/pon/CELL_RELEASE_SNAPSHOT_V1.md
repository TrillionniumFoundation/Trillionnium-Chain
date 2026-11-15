# Tensor-aware immutable release snapshot

Status: candidate byte-plane API. Actual model compatibility, restricted loader
assembly, independent custody and ordinary Hepta FinalUse remain separate gates.
This specification is subordinate to the
[sole development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## One independently selected snapshot

CTS1 pairs the complete TCV1 byte inventory with mandatory TMA1 dense tensor
metadata. Its single commitment covers the complete model/environment TCV1,
the TMA1 whose full TMR1 is exactly equal to the TCV1 model root, one actual
Configuration file in that model closure containing the composition rules,
and the independently selected composition profile.

The composition file's path, payload digest, bytes and dependencies are covered
by the original TCD1/TCV1. TCD1 retains its full dependency DAG, roles, generation
and loader profile; TMR1 retains its router-roster and lineage metadata. No
existing wire or profile is reinterpreted. A collection of content hashes does
not select a complete snapshot or establish a compatible model.

The composition profile is an owner pin, not an interpreter or a compatibility
proof. The real loader must implement that profile and verify the declared
rules. CTS1 cannot infer an omitted dependency, validate an unimplemented expert
ABI or establish useful numerical behavior.

## Wire contract

All integers are unsigned big endian; `frame(x)` is `u32(len(x)) || x`.

```text
CTS1 || frame(TCV1) || frame(TMA1)
     || u16(composition_file_index) || composition_profile[32]
```

The index uses the model closure's canonical path order. It must name an
existing Configuration file, and the profile must be nonzero. The total wire
bound is `46 + MAX_CELL_VERSION_BYTES_V1 +
MAX_CELL_TENSOR_MODEL_MANIFEST_BYTES_V1`; each frame retains its original bound.
`decode_pinned` rejects unknown magic, oversized frames, suffixes, truncation and
a different expected pin. The commitment is SHA-512 over the literal
`TRNM/Cell/TensorReleaseSnapshot/v1`, a zero byte and the complete canonical wire.
The wrapper does not change the original inner SHA-256 identities or establish
a new whole-system post-quantum security bound.

TMA1 retains the current TMT1 dense safetensors codec: F32, F16 and BF16 with its
existing bounded rank, shape and roster rules. Unknown codecs and quantization
have no fallback. Actual resident safetensors headers and complete payloads are
checked; an envelope hash alone is insufficient for tensor admission.

## Task admission and use

`CellResidencyV1::admit_local_release_snapshot` verifies the independent snapshot,
composition profile, complete TCV1 and both loader contexts. It then uses the
existing complete-version and dense-tensor admissions under the same original
absolute deadline and cancellation token. Task RAM/reference accounting includes
both model and environment before parsing tensors. There is no disk, network or
device fallback at this entry point.

The result borrows the immutable residency manager and snapshot. Safe Rust
cannot evict or switch these allocations while the handle is live. `with_local`
checks the original task, snapshot, composition profile, TCV1 and both current
loader contexts before exposing the paired version, typed tensors and rule-file
bytes. Observed expiry or cancellation is latched even if the same call supplies
a wrong snapshot pin. Resetting a cancellation flag cannot revive the task.

No provider `latest` is consulted. Another snapshot or generation requires a
separate explicit admission. Lookups cannot preempt consumer code or recall
copied bytes. Publisher authority, revocation, execution resources and FinalUse
remain guards held by the real host owner during actual use.

## Regression scope

The seven module tests use a real dense safetensors fixture with separate rule,
tokenizer and environment files. They cover exact pins and generation pairing,
unknown codec and bounded decoding, actual tensor-shape mismatch despite equal
byte size, missing environment and aggregate RAM refusal, typed access after
cache deletion, and non-revivable cancellation. They do not establish a deployed
large model, model efficacy or independent physical custody.

See [the complete version contract](CELL_COMPLETE_VERSION_V1.md) for retained
TCV1 graph, authority and complete-byte boundaries.
