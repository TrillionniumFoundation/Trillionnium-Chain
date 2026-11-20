# Owned native ML-DSA Candidate interface

This interface implements the explicit `pq_candidate.rs` API using the canonical
HIA ML-DSA owner and a native HIA emitted allocation and lifetime boundary.
The twelve explicit methods cover four algorithm queries, four signing-key
methods, and four verifier methods. The ordered `ALL` constant and all seven
original error displays are also exposed. An execution is qualified only by the
complete source-bound report and its independent reader described below.

The public interface is [pq_candidate.h](pq_candidate.h). It is Linux x86-64
SysV. Algorithms are selected by the trusted caller as 65 or 87. Pure ML-DSA
uses the empty FIPS context and deterministic signing, followed by native
self-verification before returning any signature. The original message maximum
is 65,536 bytes. Successful mathematical verification grants no application
authority or production activation.

## Ownership

Opaque handles must be live values created by this library. The caller provides
valid readable input extents, keeps them constant during a call, and must not
drop a handle while another call or borrowed view still uses it. The interface
does not validate arbitrary foreign pointers or dangling handles.

`seed_copy` creates the explicit private seed owner. `signing_from_owned_seed`
consumes a valid seed on every return, including invalid algorithms and failed
allocations. Neither seed nor expanded private key has a byte view or clone API.
There is no hidden entropy source, file loading or OpenSSL key import.

Signing keys and verifiers are immutable. Each operation uses a private copy of
the relevant state and an independent workspace, permitting concurrent read
operations. Signature, error, metadata and verification results own independent
copies and remain valid after the originating key is dropped. Public-key views
expire when their key owner is dropped; all other views expire with their result.
Every heap allocation is physically overwritten before `free`. This does not
claim stack/register erasure or constant-time execution.

`status == 0` transfers a nonnull owned result. A result of kind 255 represents
an original business error, whose code, expected and actual fields are readable.
ABI statuses 103, 104 and 105 return a null result and indicate allocation,
argument or internal failure. Scalar queries instead return a scalar in their
second result word. Invalid views return null and zero. `drop(NULL)` succeeds.

## Complete input lengths

The HIA descriptor gate checks original public-key, message and signature length
errors before allocating or copying their bodies. It accepts full u64 lengths
from a valid native slice. It checks message size before signature size.
Only admitted bounded bodies reach the canonical private borrowed-buffer owner;
its internal 1 MiB transport extent does not shorten the original public API.
Input pointer arithmetic is checked before any payload read. Live readable
allocation validity remains a caller obligation.

The public library hides both private `f0` entries and the native allocation
helpers. The HIA emitter emits the actual ELF object used by the link step;
Python authoring tools are not part of execution.

## Original method surface

| Original owner | Explicit methods | Public native entries |
| --- | --- | --- |
| `CandidateAlgorithm` | `name`, `public_key_bytes`, `signature_bytes`, `nist_category` | The four `algorithm_*` queries |
| `CandidateSigningKey` | `from_owned_seed`, `algorithm`, `public_key`, `sign` | `signing_from_owned_seed`, `signing_algorithm`, `signing_public_key`, `sign` |
| `CandidateVerifier` | `from_pinned_raw`, `algorithm`, `public_key`, `verify` | `verifier_from_pinned_raw`, `verifier_algorithm`, `verifier_public_key`, `verify` |

`algorithm_all` preserves `[ML-DSA-65, ML-DSA-87]`. The seed, result, typed-view,
error-display and explicit-destruction helpers complete the 25-symbol C ABI.
An invalid C algorithm discriminant or wrong live-handle kind is an ABI error;
it is not representable as an original Rust `CandidateAlgorithm` value.

Public-key length precedes key expansion. Verification checks message length,
signature length, signature decoding, then challenge verification. Canonical
signature decoding checks the hint encoding before the response-vector norm.
The public message maximum remains 65,536 bytes; real larger buffers exercise
rejection without copying their bodies into the private owner transport.

The exact `ml-dsa 0.1.1` dependency has a panic/nonce-overflow edge if its signing
rejection loop exhausts the u16 nonce domain. The native signer explicitly
returns `SigningFailed` at exhaustion and never wraps a nonce. This is a
documented failure-path difference, not a claim that the original has a normal
`Result` error there. The qualification does not force that extreme rejection
sequence or establish constant-time behavior.

## Complete qualification

Run from a checkout with the pinned HIA toolchain and a prepared, independently
validated OpenSSL 3.5.9 provider for the unchanged Rust all-features gate:

```sh
python3 -I -S -B hia/platform/pq_candidate/qualify.py \
  --output /absolute/fresh/candidate-qualification \
  --rust-bin /absolute/rust-1.95.0/bin \
  --provider-receipt /absolute/provider/pq-provider/provider.json \
  --provider-environment /absolute/provider/environment

python3 -I -S -B hia/platform/pq_candidate/readback.py \
  --report /absolute/fresh/candidate-qualification
```

`HIA_TOOLCHAIN_ROOT`, `HIA_NATIVE_COMPILER` and
`HIA_NATIVE_COMPILER_SHA256` select the canonical pinned compiler. The required
compiler SHA-256 is
`87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54`.
The original Cargo gate requires Rust 1.95.0, the unchanged locked graph, all
343 retained tests and 2 doctests, strict Clippy and rustfmt. No original
business code is substituted. The existing unchanged `rust_ml_dsa_reference.rs`
adapter calls all twelve original methods and the original error formatter.

The test corpus has 892 original/native pairs and 14,680 ABI calls, partitioned
deterministically into 156 method cases, 324 ML-DSA-65 verification cases and
412 ML-DSA-87 verification cases. Twelve context/internal/prehash/raw-mu/digest
fixtures first verify successfully in their own original mode and are then
rejected by the Pure Candidate verifier. Two further original/native pairs use
a live public-key borrow as the signed message. No incoming data chooses an
algorithm or enables another verification mode.

Ownership qualification checks 186 controls, including every one of 109 real
allocation failures, and observes every allocation immediately before `free`.
Its C observer first deliberately releases an uncleared test buffer and detects
all 32 bytes. Native release paths must add no uncleared or unknown frees.
The production objects are unchanged in the observed link; the observer only
wraps `calloc` and `free`. A separate 992-call lifetime check uses eight actual
threads sharing each immutable algorithm/key owner and reads 132 independent
values after those owners have been destroyed. A compiled C consumer calls all
25 header entries against the production library.

Every native partition and the native build run under the same actual absolute
240-second execution deadline and one independent three-second group cleanup.
Ownership and C-consumer stages use 180 seconds with the same cleanup. The
unchanged aggregate Rust build/test gate retains its own 1,200-second budget
and its exact inner command limits. Eight real short-deadline process controls
exercise timeout, orphan descendants, held pipes, failed execution and an
explicitly injected kill denial. The injected-denial fixture is removed by a
separate recorded teardown; it is never relabeled as successful supervisor
cleanup. The previously qualified full 240-second demonstration belongs to its
original PQ report and is not represented as a new Candidate execution.

The independent reader reassembles HIA Core, checks compiler wire and actual
ELF observations, checks every original command and retained executable,
reconstructs the complete deterministic corpus, and matches native values to
fresh original output. It checks all process clocks and the single cleanup
deadline, ownership accounting, actual concurrency, header use and every
retained input. Every component-manifest key is captured with its actual source
bytes because the canonical composer checks all key paths before selecting the
Candidate call closure. A capsule cannot replace an unused key with an empty
placeholder or omit that file. Fifty-nine adversarial controls must be refused before a report
can become `PASS`. Partial, failed, changed-source and differently parameterized
runs are not accepted.

For a retained source capsule, the reader also accepts `--source-root` and
`--source-sha256`; both refer to the exact captured source set. The report records
the actual Git head, tree and dirty state. An integration or CI run on another
source graph must execute a fresh full gate. This interface does not retire the
crypto crate, implement the OpenSSL key provider, TUF or TLS, or activate a
production cryptographic profile.
