# Classical authenticated request kernel

This component consumes a complete captured frame and verifies the original
classical request grammar, canonical JSON, session domain, nonce, full authority
hash and strict Ed25519 signature. Its five request variants and 2 MiB JSON-body
limit match the ordinary `trnm-pon-node` classical inbound path. The four-byte
big-endian prefix is additional to that body limit. A following frame remains
unconsumed.

The implementation is HIA source compiled by the locked native compiler. The
Linux fixture emitter is also HIA: it emits a small captured-input syscall
adapter and appends the exact compiled kernel image. Python captures inputs,
checks source identity and runs isolated native artifacts. It supplies no
runtime parsing, hashing, signature verification or result on behalf of HIA.

The current local observation is **178 request controls and 14 incremental
SHA256 controls executed successfully**. The local machine has no Rust
toolchain; the original Rust differential is explicitly `NOT_RUN` in that
observation. CI must execute the independent original-function gate below.
That gate is separate from the four existing Rust oracles and never replaces
or weakens them.

## Exact scope and source correspondence

The reference functions are the existing `read_frame_deadline`,
`authenticate_request`, `request_authority_digest`, `authenticated_session` and
`authenticated_request_bytes` in
`trillionnium/crates/trnm-pon-node/src/ingress.rs`. The original transport value
checks are in `trillionnium/crates/trnm-transport/src/lib.rs`. Original signature
policy comes from `trnm-crypto-primitives` and the already qualified canonical
HIA Ed25519 group helpers. The new streaming SHA256 does not change the existing
SHA256 arena helper or its qualified capacities.

The source reproduces the ordinary targeted Node dependency profile with
`serde_json` 1.0.149, `serde` 1.0.229, default/std JSON features and the default
recursion guard. A whole-workspace Cargo test may unify the data-availability
dev dependency's `arbitrary_precision` feature. That is a different profile.
The oracle driver inspects the actual Cargo artifact's feature list and refuses
an unexpected profile rather than silently treating it as the default grammar.

Requests are `head`, `submit { packet: String }`,
`history { tip: String, after: String }`,
`confirm { transaction: String, block: String }`, and
`confirm_many { queries: Vec<{ transaction: String, block: String }> }`.
Authentication permits arbitrary valid UTF-8 string contents and any query
count that fits the frame. Packet/hash decoding and the later 1..256
confirmation-query policy belong to application dispatch and are not moved
ahead of signature verification. The dense 2 MiB test contains 69,878 queries.

The typed parser also preserves rejection order for noncanonical map order,
whitespace, escapes and struct/enum sequence forms. An unknown field on the
unit `head` variant can be accepted by the original typed deserializer and then
refused as noncanonical; it is not automatically a JSON/type error. Ignored
values still obey JSON syntax, UTF-8, recursion and the original default-number
overflow behavior. The exact shared software binary64 function subset is
declared in `hia/components.json`; there is one canonical math source.

## Trusted owner and authority boundary

The new local ABI carries a **trusted owner configuration**, followed by
untrusted frame bytes. It is not an authentication boolean. HIA checks the
binary configuration's shape, generation range, strictly sorted unique raw
public keys and strict canonical/nonweak public-key encodings. It checks all
wire bytes and performs the actual signature equation relative to that
configuration.

The future connection owner must obtain this configuration from the current
validated `Settings` and its owned identity/allowlist. It must enforce the
original current account-profile guard and the Node's explicit classical/PQ
transport selection before submitting bytes. Supplying arbitrary configuration
bytes to this pure function grants no trusted peer, session, socket or replay
capability. Output buffers and private configuration must be owned, nonaliased
and stable for the duration of the call; no concurrent mutation guarantee is
claimed.

The original private `AuthenticatedPeerFrameV0` is an owner-side value. This
kernel returns metadata and digests only. It does not construct a private HIA
peer capability, acknowledge a nonce, persist pending work, dispatch a request,
authorize state changes, sign a response or recover an outbox. The durable
replay owner, signed response `serde_json::Value` codec, private signing-key
owner, PQ grammar/selection/authentication, connect/listen/accept owner and
reactor integration remain **OPEN**.

The kernel's `NeedMore` code means the captured bytes do not yet contain the
required prefix or body. It is not an observed EOF or a deadline. The original
socket reader observes `FRAME_EOF` when a finite test sender closes early; the
oracle explicitly maps that fixture observation to `NeedMore` without claiming
these are the same live-stream event. All elapsed-time/deadline enforcement
remains with the stream owner. A 30-second test cleanup budget does not certify
service latency or the original 5-second request deadline.

## Wire and error order

The canonical JSON envelope field order is
`schema, session, replay_nonce, request, signature`. Session fields are
`network, parameters, genesis, profile, peer, server, session, generation`.
Schema is `trnm-authenticated-request-v1`. All canonical bytes participate in
the original domains; no JSON field, trailing payload byte or frame-length
boundary is truncated to fit the public verifier's separate message cap.

The original PON hash is one continuous SHA256 over `TRNM-PON1\0`, the tag
length as u16 little-endian, the tag, then each part prefixed by its u32
little-endian length. Authority uses tag
`native-authenticated-request-sign-v1` and the canonical envelope with no
signature field. The Ed25519 signed message is this **32-byte authority
digest**, regardless of the frame size. Payload uses
`native-authenticated-payload-v1`. Peer, profile and session domains retain the
original tags and field order.

After local configuration admission, the order is framing bounds, complete
typed JSON validation, canonical-byte comparison, schema, peer allowlist,
session context, nonce, strict signature, and original nonzero transport-value
checks. Output is unchanged on every nonzero return. The numeric ABI preserves
these refusal families and their ordering. It does **not** preserve each
original JSON line/column/type diagnostic or every `AUTH_SIGNATURE:*` message
verbatim. The original oracle retains the full original diagnostic separately;
an owner requiring the old human-readable wire error must provide an explicit
mapping rather than invent equivalent text.

## ABI

`abi.json` specifies the complete byte layout. `f0(readbuf, mutbuf, mutbuf) ->
u32` requires an output capacity of at least 384 bytes and private workspace of
at least 204,800 bytes. On success it writes exactly 384 bytes, including the
consumed-frame count, original payload offset/length, operation, nonce,
generation, ten complete digests/keys and query count. On refusal it writes no
output bytes. The mutable workspace is private scratch, not a persisted state
or a caller-authenticated proof object.

The new streaming SHA256 holds one 1,208-byte private context and accepts at
most 2,098,176 cumulative bytes. It supports actual incremental updates followed
by one final padding/length operation; it never hashes chunks independently
and combines their digests. The `tr_sha_*` helpers are internal functions with
explicit arguments and retained context. Callers must initialize and privately
own that context. This qualification tests length/padding/chunk boundaries and
the standalone entry's refusal limits; it does not claim fault-injected
coverage of arbitrary corrupted private context states.

## Reproduce

Use the same explicit `HIA_TOOLCHAIN_ROOT`, `HIA_NATIVE_COMPILER` and
`HIA_NATIVE_COMPILER_SHA256` settings as the other native gates. Then run:

```sh
python3 -B hia/tools/qualify_transport.py --output /tmp/hia-transport-local
python3 -B hia/tools/qualify_transport.py --require-rust-oracle --output /tmp/hia-transport-original
```

Each output directory must be new and outside the HIA source tree. Local-only
mode reports `NATIVE_PASS_RUST_NOT_RUN`; it does not report a Rust skip as a
complete gate pass. CI uses `--require-rust-oracle`, which fails if Cargo/rustc,
the original tests, the exact profile or any comparison is unavailable.

The Rust driver copies the original `trillionnium`, `config` and `formal`
inputs into a fresh isolated directory and captures their hashes. It appends
only a `#[cfg(test)]` child-module declaration to an otherwise byte-identical
copy of `ingress.rs`; the hook source is a separate file. It builds the actual
original Node library test target using `cargo test --locked -p trnm-pon-node
--lib --no-run --message-format=json` and a fresh target directory. It runs six
unchanged original authentication/account-scope/frame-deadline tests. The hook
first obtains a real `Settings::development(Some(1))` context and five original
signer-generated golden frames. The differential corpus is regenerated for
that context, checked by the native HIA executable, and supplied to the
original `read_frame_deadline` over real loopback TCP and original private
`authenticate_request`. New binary-configuration errors are explicitly outside
the old function's domain and are excluded from that differential.

The emitted Linux executable is a finite test fixture. Its HIA-emitted adapter
reads stdin to a 3 MiB bound, makes captured input read-only, invokes native
`f0`, and writes the return word plus 512 output/canary bytes. It handles
partial stdin/stdout and EINTR. The adapter's mmap/mprotect/read/write/exit ISA
effects are outside HIA Core's buffer-effect proof; a valid ELF header and Core
acceptance do not prove those machine instructions' semantics. The final
source-bound observations retain actual native return codes, stdout, stderr,
input/output hashes, budgets and cleanup results. Generated ELF files, compiler
copies, authoring scripts and intermediate source versions are not repository
deliverables.
