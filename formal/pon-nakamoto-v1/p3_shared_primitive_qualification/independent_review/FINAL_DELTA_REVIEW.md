# Final model-assisted source delta review

## Outcome and scope

**HOLD_NO_GO remains unchanged.** I found no new accepted-proof failure in the
examined source delta. The final descriptor, actual role API calls in the new
known-answer test, and the independent reference encoding agree at the source
level. I independently recomputed all 31 fixed vectors and reproduced the
fixture byte-for-byte with its reference generator.

This is a model-assisted source review with local Python correctness controls.
It is not an external cryptographic audit, a security proof, a native Rust test
receipt, or a review of an exact final native commit. I did not run Cargo, the
qualification runner, any full W1 proof, or the ABBA benchmark, and did not
access or modify the frozen native worktree. Native execution and source/commit
binding must be established by the separate integration receipts.

The reviewed snapshot is the local `tagged_profile_impl` staging directory and
the selected `root_docs` files. `final_delta_source_receipt.json` records their
SHA-256 identities, the preceding review identities, and the raw outputs of
the local controls. The preceding `REVIEW.md` remains applicable unless this
report explicitly updates a finding. Actual P3 pruned multi-opening mapping
was outside this review and remains uncompleted.

## Exact delta from the preceding source receipt

| File | Observed change |
|---|---|
| `src/tagged_sha3.rs` | Exactly the descriptor labels `blowup`, `final`, and `arity` changed to `log_blowup`, `log_final_poly`, and `max_log_arity`. Reversing those three label changes reproduces the preceding SHA-256 identity. |
| `tests/tagged_sha3_profile.rs` | The preceding file is an unchanged byte prefix. The appended test consumes 31 external vectors through the actual role APIs. |
| `src/tagged_sha3_wire.rs` | Byte-identical to the preceding reviewed snapshot. |
| `examples/tagged_sha3_backend.rs` | Byte-identical to the preceding reviewed snapshot. |
| `Cargo.toml`, `src/lib.rs` | Byte-identical to the preceding reviewed snapshot. |
| `tests/tagged_sha3_reference_vectors.json` | New fixed-vector fixture, SHA-256 `c891c42cbd7751c920073c7701494d710016cbf56e933408893b0536996cc0a5`. |
| `examples/tagged_sha3_wire_controls.rs` | New structural-admission harness; reviewed as source only. |

The descriptor now says explicitly that the FRI blowup value is a logarithm.
Its `log_blowup=2`, `log_final_poly=0`, `max_log_arity=1`, and `queries=64`
match the constants used to construct `FriParameters`. The change alters every
application hash frame and therefore changes proof commitments/challenges.
It must be integrated with its final fixture and native evidence as one
profile snapshot. The new labels do not change the underlying FRI settings.

The earlier constant-drift repair is preserved. This delta does not reopen it.
The descriptor is still a frozen semantic specification, not a digest of every
AIR constraint, source file, or dependency. Later behavior changes need their
own controlled profile versioning and receipts.

## Independent vector and role-API review

The Python reference generator contains its own constants and uses
`struct.pack` plus standard-library `hashlib.sha3_512`; it does not import or
parse the Rust implementation. The additional local review control rebuilt
the same messages using integer `to_bytes` conversions and explicit field
concatenation, without calling either reference `frame()` or Rust
`frame_header()`. All 31 expected digests and framed-message lengths matched.
The root fixture, Rust fixture, and regenerated stdout were byte-identical.

| Role | Coverage per component | API used by the Rust KAT |
|---|---|---|
| Leaf | Five cases each for SHA and packed carry: empty, zero, one, one followed by zero, and values including the maximum canonical field element | `LeafHasher::hash_slice` after canonical field decoding |
| Branch | Two cases each, including all-`ff` digest bytes, the field modulus as a raw digest word, and nonuniform ordered children | `BranchCompressor::compress` with two arrays of eight raw `u64` words |
| Transcript | Seven payload lengths each: 0, 1, 71, 72, 73, 144, and 201 bytes | `TranscriptHasher::hash_slice` |
| Statement context | Three typed triples, including the ambiguous-unframed pairs `a / bc` and `ab / c`, and the all-empty helper case | `statement_context` with the original three byte strings |

This checks the magic/version fields, little-endian length fields, final
descriptor, component, role, 64-byte context, payload and final payload-length
suffix. The branch vectors specifically preserve digest words at or above the
Goldilocks modulus; they would expose field reduction at this interface. The
Rust KAT also pins the descriptor and profile ID directly against the fixture.

The KAT source calls each actual implementation rather than a shared framing
helper used as its sole oracle. I inspected that routing; I did not execute
the Rust test. Fixed vectors remain finite interoperability evidence. They do
not establish collision resistance, a primitive replacement theorem, or
transcript security.

The low-level public `frame_header(u32, ...)` remains an encoder and can encode
values beyond the closed application component enum. It is not an admission
API. The concrete leaf, branch, transcript and configuration constructors
take the closed enum; statement-context hashing uses the separate component-0
domain. The independent reference's restrictions describe these application
paths, not a rejection guarantee for arbitrary calls to the low-level helper.

## Transcript and statement boundaries

The history-alias regression and metadata are preserved unchanged from the
preceding review. They accurately record two inherited `HashChallenger`
behaviors: adjacent observation-call boundaries are not recorded, and the
number of bytes consumed within one output block is not recorded when a new
observation appends to the complete digest chaining state. The test compares
histories that differ by one versus two sampled bytes within the same block,
then supplies the same next observation. Their future states agree without
a SHA3 collision.

This is a boundary on any generic transcript-history claim. The fixed P3
observation and sampling schedule still needs its own protocol argument.
No new per-message semantic tags, independent role oracles, quantum
Fiat-Shamir theorem, or complete W1 soundness claim has been introduced by
the KAT or descriptor update.

The unchanged backend continues to validate `plans(expected)` before deriving
the context from the complete canonical public statement and the independent
expected header/artifacts. Both proof components receive that context. Both
bounded immutable proof buffers pass structural admission before either
allocation-owning decode; cryptographic success still requires both original
PCS verifications. This remains a research relation check, not authorization
of the expected values for production Node admission.

## New structural-admission control harness

The harness first scans its supplied positive files and checks canonical
decode/re-encode equality. It exercises foreign envelopes, component confusion,
huge vector lengths, unsupported Option tags, noncanonical field values,
truncation, trailing data, changed widths/counts/degrees, and excessive
frontier lengths. The direct byte offsets for the first two cap lengths,
random-commitment tag, trace-vector length, and first field agree with the
fixed envelope layout. Typed mutations are serialized before admission.

The all-`ff` digest control intentionally remains structurally admissible.
The report expressly says it performs no cryptographic verification. Its
allocation counter observes the scanning thread while `scan_proof` runs;
it is not a total process allocation, memory, or time certificate. The source
does not infer exact pruned-frontier correctness from the full-path upper
bound. Those checks remain with P3.

No runtime results for this harness are claimed here. The input identities
reported by a future harness run need to be linked to independently verified
full proof fixtures. Zero-difficulty PoW witnesses are still admitted as
canonical fields by the scanner and rejected unless zero by the subsequent
locked verifier; this remains the earlier optional early-rejection improvement,
not an accepted-proof malleability finding.

## Qualification-runner review and corrected blind spot

The initially reviewed runner accepted Python output containing `Ran 40 tests`
and any `\nOK`. Standard `unittest` reports `OK (skipped=40)` with exit code 0
when every test is skipped, so all 40 skipped tests satisfied that former gate.
I reproduced this with a real 40-case skipped suite; no test bodies executed.
The raw stdout/stderr are retained as a parser counterexample, not as passing
correctness tests.

After the finding was sent to the root agent, the runner was changed to
require a terminal standalone `OK`. Its Rust parser was strengthened to require
zero failed, ignored, measured, and filtered tests, at least 56 passing tests
in aggregate, and an explicit successful role-vector KAT. It also regenerates
the independent vectors and compares the bytes with the Rust fixture. JSON
consumers now read stdout separately from diagnostics on stderr.

I inspected the updated source and extracted only the Python/Rust guard
expressions from its AST for local controls. Five Python cases and six Rust
cases passed their expected accept/reject outcomes. They include all-skipped,
expected-failure, unexpected-success, too-few-test, ignored, measured, and
filtered cases. This confirms the reported skip-coverage blind spot is closed
in the receipted source. It does not mean the full runner was executed here.

Remaining runner scope is explicit: doc-test execution is checked for command
success without asserting a nonzero count; the new full-proof wire harness
and ABBA executions require their separate receipts. The runner's output is
`FOCUSED_CHECKS_PASS`, with `complete_repository_ci=false`,
`production_activation=false`, and `HOLD_NO_GO`. Those limits should remain.

## Evidence and unresolved gates

The local reproduction command is:

```text
python3 -B independent_review/verify_final_delta.py
```

It succeeded with exit code 0. Its raw stdout/stderr and the reference/parser
subprocess outputs are indexed and hashed in `final_delta_source_receipt.json`.
The source file itself is also hashed. This control deliberately does not
touch Git or execute native qualification commands.

All earlier cryptographic and resource limitations remain: actual P3 pruned
multi-opening binding, the concrete shared-primitive and Fiat-Shamir model,
quantum/precomputation/advice composition, adversarial lifecycle accounting,
recursive verification cost, and production service qualification. The
inherited field rejection sampler also lacks a deterministic iteration bound.
Neither the vector checks nor this source review closes any of those gates.
