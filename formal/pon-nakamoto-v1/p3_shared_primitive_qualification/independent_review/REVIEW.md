# Independent review of the tagged SHA3 research profile

## Conclusion and scope

The reviewed source implements a separate SHA3-512 research profile with
explicit role/component/context framing, full 512-bit Merkle digests, a bounded
structural wire scanner, and independent reconstruction of statement-derived
preprocessing. I did not identify a new accepted-proof forgery or a digest
field-reduction bug in the reviewed snapshots. This is a static source review,
not an independent native build, a full W1 run, or a security proof.

Qualification remains **HOLD_NO_GO**. The code appropriately keeps concrete
binding, complete noninteractive, quantum and lifecycle security bits unknown.
It does not claim independent role oracles or a recursive SHA3 AIR.

`source_receipt.json` pins the reviewed files and supporting dependency source.
The P3 archive checksums were compared to the supplied base Cargo.lock, and the
reviewed dependency files were compared byte-for-byte with those archives.
The new profile's final generated lockfile and native execution receipts must
be checked by the integration pipeline; they are not certified by this review.

## Findings requiring explicit treatment

### R1 — The inherited HashChallenger aliases some interaction histories

**Scope: confirmed interface behavior, not a SHA3 collision or W1 forgery.**

After a flush, P3 `HashChallenger` stores the complete hash output in its input
buffer and also in an output buffer. Sampling pops output bytes. Observing a
new nonempty value clears the unused output but preserves the full chaining
value. Consequently, for the same initial observations `M`, these histories
have identical future state after their final observation:

1. observe `M`; sample one byte; observe `x`;
2. observe `M`; sample two bytes from the same output block; observe `x`.

Their next hash input is the same digest followed by `x`. Also, adjacent
observation calls are concatenated without recording the call boundaries.
Neither equality requires a collision in SHA3.

The implementation agent added `inherited_state_alias` to profile metadata and
the regression `inherited_hash_challenger_history_alias_is_recorded_not_hidden`
during this review. I inspected both additions. Their native execution remains
part of that agent's test run. The fixed P3 protocol schedule must supply its
own security argument; a generic interaction-history injectivity claim would
be incorrect. Future custom transcript users must not infer one from the
application role tags.

Related low-level distinction: `observe_slice(&[])` is a no-op in the upstream
byte challenger, whereas its generic zero-length array observation clears the
output buffer. The reviewed fixed-width field/digest observation path does not
need that generic empty-array operation. This is another reason to freeze the
actual call schedule rather than describe only an informal byte transcript.

### R2 — Syntax bounds are not a deterministic verifier time bound

The scanner bounds allocation-owning decoding and validates fixed shapes.
`SerializingChallenger64` nevertheless uses a rejection-sampling loop with no
iteration cap. The current code does not establish a deterministic worst-case
runtime for that loop or the subsequent PCS verifier. This is an open resource
qualification obligation, not a demonstrated exploitable SHA3 denial of service.
The module's explicit disclaimer of a runtime/resource bound is appropriate.

### R3 — Zero-difficulty PoW fields can be rejected earlier

The scanner currently admits any canonical field value at the batch, commit,
query and OOD witness positions. The locked P3 verifier subsequently requires
zero at every zero-difficulty site: `check_canonical_pow_witnesses` covers FRI
and the uni-STARK verifier checks its OOD witness. Therefore this is **not** an
accepted-proof malleability finding. Optionally checking zero in the scanner
would reject this known invalid class before AIR/preprocessing construction.
The existing separation of structural admission from proof acceptance must be
retained either way.

### R4 — Do not re-run the stale generation helper over the reviewed files

The staging-only `build_overlay.py` still derives wire/runner files by textual
replacement of old-profile templates. Its replacement set does not reproduce
all the later independently frozen constant imports and metadata changes.
The final Rust files contain the already requested constant-drift repair; that
repair is not reopened here. The helper should be excluded from deliverables
or updated and guarded before it is used again. This concern was sent directly
to the implementation agent.

## Checks of the substantive implementation

| Area | Source observation | Boundary |
|---|---|---|
| Application framing | Magic, framing version, length-delimited profile and descriptor, fixed component, role byte and 64-byte context precede the payload; a fixed-width payload byte count follows it. | This is an injective complete-message encoding for the fixed fields. It does not itself provide a prefix-free encoding of arbitrary successive transcript messages. |
| Branch hashing | Ordered children contribute exactly 128 bytes to a complete SHA3-512 hash invocation. | The old full-width public-permutation truncation is not reused. No concrete collision theorem follows merely from choosing SHA3. |
| Digest representation | `digest_words`/`digest_bytes` round-trip eight raw little-endian `u64` words. Branch hashing and `SerializingChallenger64` preserve those bytes. | No reduction modulo Goldilocks is applied to digest words. Every 512-bit string remains representable. |
| Field encoding | Leaf fields use `to_unique_u64`; the scanner rejects field encodings at or above the modulus. The locked Goldilocks serde decoder also rejects those encodings. | Normalizing an internally noncanonical representation of the same field value is intentional and does not make digest words field elements. |
| Parameters | The new module owns the FRI constants and Goldilocks alias; field order and AIR widths have compile-time assertions. The locked quadratic extension uses `X^2-7`. | The descriptor is a frozen semantic label, not a hash of every AIR constraint or dependency source. A source/encoding/schedule change still requires controlled profile versioning. |
| Statement context | Both prove and verify call `plans(expected)` before deriving a context over the complete public statement plus independently supplied header and artifact expectations. Both hash configurations receive that same context. | The runner verifies a W1 relation. Authenticating those expectations as a production Node admission contract is outside this code. |
| Components | Public configuration takes the closed `Component` enum; integer conversion admits only SHA and packed carry. | The raw frame helper is a low-level encoder, not an admission function. |
| Wire separation | New SHA and carry magics are distinct from each other and the old profile. The scanner fixes component geometry, field canonicality, Option tags and vector lengths, and rejects trailing bytes. | Bounded path-frontier size is only an upper bound; exact transcript-dependent frontier checks remain in P3. |
| Decode ordering | The CLI reads bounded immutable buffers and scans both proofs before either allocation-owning decode. The decoder fixes bincode integer encoding, rejects trailing bytes and checks the degree. | Scan success is never treated as cryptographic verification success. |
| Sampling | Output bytes are popped in reverse digest order, then eight sampled bytes are interpreted little-endian. Base-field candidates at or above the modulus are rejected; extension coefficients are sampled separately. | Uniformity statements remain conditional on the source-byte model; the loop's termination/resource qualification is separate. |
| Shared primitive | All roles, including statement-context hashing, use one concrete SHA3-512 implementation. Metadata states that role-oracle independence is not claimed. | The context hash and adaptive transcript create a joint construction. The conditional sponge arithmetic tool is not a proof of this composition. |
| Reporting | Successful verification is labeled research-only; every CLI result carries HOLD_NO_GO. Unknown security quantities remain null. | No claim of quantum W1 soundness, recursive SHA3 cost, production admission or minimum physical work was found. |

## Validation evidence still supplied by integration

I inspected the tests for a standard SHA3 vector, raw digest round-trip,
streaming/reference agreement, role/context distinctions, rejection sampling,
the old collision-witness embedding, and small SHA/carry proof verification
with mutations. The newly added history-alias test and quadratic-extension
check were also reviewed. I did **not** execute these native tests here.

The streaming reference test calls the same `frame_header` helper as the code
under test. It therefore checks streaming equivalence but does not independently
pin the entire framing specification. The root agent's separate fixed-byte KAT
is useful for that remaining check.

Before an integration report claims a working full profile, it should retain
the actual new-lock/native-build evidence, full-size proof scan/decode/verify
results, and mutations for foreign profile/component magic, noncanonical
fields, unsupported shape and trailing data. None of these execution results
is inferred from this static review.
