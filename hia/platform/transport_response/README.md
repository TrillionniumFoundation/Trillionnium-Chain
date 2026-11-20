# Classical authenticated response components

This package builds and exercises complete original classical response bytes.
The six reusable HIA components cover default-profile JSON numbers, full finite
`serde_json::Value` admission and serialization, Ed25519 signing of a 32-byte
message, signed-response framing, and strict authenticated-response verification.
The compiled HIA kernels and HIA-written ELF emitters execute the runtime work.
Python supplies build orchestration, captured test bytes, independent test
references, and process receipts. It does not implement a runtime handler.

This package is not a network, replay, durable terminal-commit, application
dispatch, or private-key owner. Its binary owner context is a checked data
representation of inputs that a real owner must supply. The `terminal` and
`outcome` bytes describe response content; they grant no authentication or
commit authority. The ordinary Node's PQ selection and separate PQ transport
remain distinct requirements.

## Original boundary and ordering

The retained source is `trillionnium/crates/trnm-pon-node/src/ingress.rs`, pinned
by the actual build receipt and the audited source hashes in `provenance.json`.
`signed_response` constructs the original field order:

1. `schema`
2. `session`
3. `replay_nonce`
4. `request_digest`
5. `terminal`
6. `ok`
7. `value`
8. `signature`

`session` preserves `network`, `parameters`, `genesis`, `profile`, `peer`,
`server`, `session`, `generation` in that order. Its seven string identities
come from the normal original owner as lowercase 32-byte hex values. The
binary context represents exactly this normal-owner domain, not arbitrary
caller-created `AuthSession` strings.

The body limit is **2,097,152 bytes**, plus the original four-byte big-endian
length prefix. A frame exceeding that limit is refused; a finite capture that
has not supplied the declared bytes returns `NeedMore`. This finite-input
result is compared with original `FRAME_EOF` in the test hook. It is not a
socket EOF, timeout, readiness, or deadline owner.

Verification preserves the original sequence: framing, complete typed serde
grammar, exact reserialization canonicality, combined expected context, then
strict Ed25519 verification. Unknown or duplicate struct fields are typed
errors. Valid struct sequence representations and different field order are
noncanonical. An invalid nested Value remains a serialization error even if
an earlier field already establishes a canonicality or context mismatch.
Successful metadata includes the consumed frame length and the exact Value
slice; following frames remain outside that consumed extent.

The authority is the canonical `ResponseAuthority` with no signature field,
using schema `trnm-authenticated-response-v1` and PON tag
`native-authenticated-response-sign-v1`. The actual incremental SHA256 input
is `TRNM-PON1\0`, a little-endian u16 tag length, the tag, a little-endian u32
part length, and the complete authority bytes. Normal Ed25519 signs the
resulting 32-byte digest. This is not Ed25519ph. Large Values are hashed as
one exact stream; they are not truncated or replaced by independent chunk
hashes. The verifier's Ed25519 message stays 32 bytes regardless of body size.

Successful application outcomes retain their complete Value. An error becomes
`{"error": error.to_string()}` with the entire UTF-8 text. The unrelated
protected-untrusted-error truncation is not applied to authenticated responses.

## Full Value and number semantics

The lock selects `serde_json 1.0.149` with exactly the ordinary `default` and
`std` features, and `zmij 1.0.21` for formatting. `float_roundtrip`, arbitrary
precision, and insertion-order maps are not silently enabled. The independent
Cargo oracle checks the actual compiler artifact's feature set.

`json_value_wire.hepta` checks valid UTF-8, all JSON escapes and valid surrogate
pairs, finite numbers, arrays, objects, duplicate names, and decoded Unicode
key ordering. It returns a canonical JSON **view**, not an unrestricted typed
tree. Duplicate object names are syntactically valid but noncanonical because
the original serde Map resolves them before reserialization. Syntax continues
to be checked after discovering a canonicality mismatch. Ordinary recursion
allows at most 127 containers; a Value inside the response uses one outer
container and therefore admits at most 126 more. Standalone stored-row JSON
uses `outer=0`; a later M06 projection must not reject Unicode or floats before
this full JSON admission.

`jn_parse(a,start,end,w)` parses a numeric token and records its integer/float
kind, exact bits, canonical text and equality flag. It implements the locked
default coefficient/exponent path: u64 coefficient accumulation, documented
overflow/discard behavior, signed zero, saturated exponents, separately rounded
power-of-ten scaling, and finite-range refusal. This is intentionally the
original default parser, including its distinction from a correctly rounded
decimal-to-binary parser. Some correctly formatted finite binary64 texts do
not survive this default parser followed by reserialization byte-for-byte;
the response verifier then returns the same noncanonical family as the
original implementation. The test data preserves that behavior.

The formatter handles every finite binary64 sign, subnormal, normal, and zero.
It uses shortest round-trip digits and the locked zmij presentation: decimal
notation for decimal exponents -5 through 15, scientific notation otherwise,
and `.0` for an integer-valued float. Nonfinite values are not serde Value
numbers and are refused by the typed representation.

### Typed `JVT2` Value container

The serializer's local input is `JVT2`, an `outer` byte, and one complete node.
Each node contains a one-byte tag, a little-endian u32 payload length, and its
payload. Tags and exact layouts are in `abi.json`: null/false/true, u64, i64,
finite binary64, UTF-8 string, array, and object. Arrays carry an exact child
count. Objects carry an exact count and raw UTF-8 key/node pairs whose keys
must be strictly increasing and unique. HIA checks every length, tag, UTF-8
sequence, count, ordering requirement, and extent itself.

The input limit is 16 MiB plus its five-byte header. It accommodates the worst
typed overhead of any Value whose serialized JSON fits the original 2 MiB
body bound, including over a million small numeric nodes. It is not a reduced
wire limit. The serializer first validates and measures, then writes to its
private work arena, then copies the successful result to public output. All
reported failures leave public output unchanged. This is a call-level output
contract, not a rollback guarantee after a process trap or external effect.

## Native ABI and private work

Every exported component uses the locked
`f0(readbuf,mutbuf,mutbuf)->u32` native ABI. `abi.json` gives exact offsets,
capacities and result codes. Input, output and work must be valid disjoint
regions, with exclusive output/work ownership for the call. Internal helper
offsets are private implementation contracts; they are not an arbitrary-offset
public field-arithmetic API. No concurrent aliasing guarantee is asserted.

The producer's owner context has magic `TRNMAS01` and contains the original
network/config/session identities, generation, nonce and request digest. It
then receives terminal/outcome bytes, six zero reserved bytes, a 32-byte seed,
and either a complete `JVT2` Value with `outer=1` or a full UTF-8 error message.
The native signer derives the seed's public key and refuses a server mismatch.
Only after validation, exact measurement, hashing and signing does the kernel
publish the complete frame. A trusted owner's successful verification of the
original request and its durable choice of `terminal` remain prerequisites.

The verifier uses `TRNMAR01`, the same 280-byte context, and complete captured
framing. Success publishes 96 bytes of metadata; all refusal results preserve
the output region. The expected context stores full u64 fields because the
original verification function compares u64 values. The original live request
owner imposes its separate nonce and generation domain before creating them.

### Signing scope and an actual erasure failure

`ed25519_sign.hepta` accepts seed32 plus message32 and returns public key32 plus
signature64. Its fixed-control field/scalar arithmetic uses three carry/fold
rounds, masked conditional subtraction, fixed 256-bit point multiplication,
512-step scalar reduction and 64-column scalar multiply-add. The complete
native output is compared with independent modular arithmetic and, when
required, the original Rust identity implementation.

`es_expand_public(w)` expects seed at `w[0,32)` and puts the public key at
`w[140160,140192)`. `es_sign_loaded(w)` additionally expects the message at
`w[141248,141280)`. These helpers leave private work for their owner to manage.
`es_wipe` clears exactly `w[0,141568)`; higher arena data remains intact. It
does not erase caller-owned readbuf input, native stack spills, or registers.

There is an actual independently observed **raw-kernel stack-erasure failure**,
retained in `known_failures.json`. With three publicly synthetic seeds, the
unchanged kernel returned success and fully cleared the low HIA work arena,
yet returned stack locations retained zero-extended seed, clamped scalar,
prefix and nonce-scalar bytes. Their values tracked all three cases. The
observation pins the exact compiler, raw kernel, ELF and test caller source.
The host-assembled caller was an independent diagnostic only and is not
included as runtime source. The default complete producer build now wraps its
unchanged native image with the [HIA private-stack adapter](../private_stack/README.md).
It runs the whole producer call on a separately mapped and guarded 1 MiB stack,
clears that stack on ordinary return, and reports OS allocation/protection/release
failures distinctly. Its raw and guarded image hashes remain separate in build
receipts. The standalone mathematical signer fixture remains unwrapped so the
original residual failure is still reproducible and explicitly reported.

The native variable-output caller publishes no bytes when the adapter returns
a cleanup error, even if a complete signature has already been written into its
private output. Qualification applies an additional real seccomp restriction
that makes `munmap` fail after signing, and requires exit 70 with empty stdout.
This checks the actual complete producer and caller together; the independent
stack observer checks all 1 MiB of retained stack memory under that same OS error.
These controls do not grant a socket, terminal-commit or seed-lifetime capability.

No claim of formal machine-code constant time, comprehensive register erasure,
trap/cancellation cleanup, private-key custody or production signing ownership
follows from the arithmetic controls or absence of HIA secret branches.

## Build, qualification and independent original oracle

Use the exact clean checkout and compiler selected by `hia/toolchain.lock.json`
and the existing compiler binding, then run:

```sh
PYTHONDONTWRITEBYTECODE=1 python hia/tools/qualify_response.py \
  --output /tmp/hia-response-observation --require-rust-oracle
```

The output directory must be fresh and outside the HIA source tree. An isolated
promotion overlay can supply `--repository` pointing to the retained original
Cargo source tree; HIA composition always uses the executing driver's own
source tree and manifest. The same explicit composer independently Core-checks
each dependency, permits selection only from its own raw functions, requires
all callees to be listed by the caller, and records every input used for those
checks. All captured source bytes are rechecked before and after native builds
and before the final report. The fixed compiler and bounds are unchanged.

The existing request fixture supplies small fixed-output native calls. The
single response-specific HIA emitter supplies variable outputs for Value and
signed-frame encoding. It captures bounded stdin, marks input read-only, calls
the exact compiled kernel image, checks every unused output byte and redzone
canary in native instructions, and only then publishes the result. A separate
test-only HIA kernel deliberately attempts an output write before an error,
an unused-tail write, an invalid return length and an actual checked bounds
violation. Its receipts test the fixture's refusal behavior. An invalid emitter
profile is also actually executed and refused. These controls do not create a
network adapter or key owner.

Each native stage keeps exact raw stdin/stdout/stderr, executable and input
hashes, return code, timeout and bounded cleanup receipts. Native calls retain
the existing 30-second observation limit and three-second cleanup limit; these
are test containment budgets, not a runtime deadline. No host assembler,
business interpreter or alternate compiler is a runtime fallback.

With `--require-rust-oracle`, the driver makes a fresh isolated copy of the
retained `trillionnium`, `config` and `formal` source inputs. It preserves every
original production byte, appends one `#[cfg(test)]` module declaration, and
builds the original Node lib tests with `cargo test --locked`. The test-only
hook directly calls the original response, framing, authority, identity and
serde functions. JVT2 decoding constructs test Values; no original response
grammar or signature algorithm is replaced. The test thread uses a 64 MiB
stack to hold the deepest legal test containers, without changing the original
Cargo profile or production recursion bounds.

The oracle runs six retained response/replay tests and compares complete
successful bytes, exact successful metadata and refusal families. Number-token
controls with surrounding whitespace belong to the new token ABI and are
excluded from direct Number parsing comparisons; full JSON whitespace behavior
is separately compared through the Value parser. Invalid new JVT2/context
containers likewise remain native ABI controls. Original frame EOF maps to
finite-capture `NeedMore`; original frame overflow maps to the producer's frame
limit result. No other unknown Rust error is silently classified. Missing Rust
tools, failed builds, unexpected feature sets, failed retained tests or any
difference fail a required run. Without that flag, a successful native run is
explicitly `NATIVE_PASS_RUST_NOT_RUN`, never an original Rust PASS.

The corpus covers all five original request authority variants with
representative response Values, full Unicode and untruncated errors, the exact
2 MiB body boundary, dense containers, default serde number behavior, 20,506
finite binary64 formatting values in a complete array, strict signature
negatives and error precedence. The fixture Values do not claim that the five
application dispatch implementations have been migrated or executed in HIA.

## Provenance and license

The HIA Schubfach formatter and compressed power tables are derived from
[David Tolnay's zmij 1.0.21 source](https://github.com/dtolnay/zmij/blob/6531ba31ccf5d14b604ca41f6e2414a8dd779af0/src/lib.rs),
at immutable commit `6531ba31ccf5d14b604ca41f6e2414a8dd779af0`. The exact source,
Cargo lock checksum, Git blob identity and license identity are recorded in
`provenance.json`. The upstream
[MIT notice](https://github.com/dtolnay/zmij/blob/6531ba31ccf5d14b604ca41f6e2414a8dd779af0/LICENSE-MIT)
is retained verbatim in `LICENSE-MIT.zmij`; no attribution year or copyright
line absent from that source has been invented. Shared HIA binary64, JSON
primitives, SHA256, SHA512, public Ed25519 and original request helpers remain
single canonical sources selected by explicit function lists.
