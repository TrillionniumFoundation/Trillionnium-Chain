# Native PQ authentication ownership

This candidate library implements seed-backed ML-DSA-65 authentication, TPQ1,
and the ML-DSA-65/87 CPQ1 candidate verifier in HIA. The public interface is
[`pq_auth.h`](pq_auth.h), for Linux x86-64 SysV. It constructs private owners,
allocates an independent invocation arena for each operation, and returns
independently owned values. No Rust, Python or C business implementation runs
inside this library.

The original method contracts are
[`pq_auth.rs`](../../../trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs)
and
[`pq_profile_auth.rs`](../../../trillionnium/crates/trnm-crypto-primitives/src/pq_profile_auth.rs).
Original protocol policy, signed domains, SPKI, TPQ1 and CPQ1 bytes remain
unchanged. The optional OpenSSL `from_owned_key` provider, `Backend(ErrorStack)`
formatting, TUF integration, whole-crypto retirement, node activation and secret
timing qualification remain open. A candidate observation grants no role,
current status, nonce, funds or final-use authority.

## Ownership and return values

Every handle must be a live object returned by this library. Callers must not
forge, mutate, free externally or reuse a dropped handle. Input pointers must
refer to the stated readable extent for the duration of the call. Null is
accepted only for an empty variable-length input or by `drop`. These are the
ordinary C live-memory obligations, not an arbitrary foreign-pointer gate.

`trnm_pq_result` is a two-register return value. A zero `status` returns one
non-null owned object. It can be a business error of kind 255; check `kind`
before interpreting it as a successful owner or observation. Nonzero ABI status
returns a null value: 103 is allocation failure, 104 is an invalid ABI argument,
and 105 is an internal refusal. Allocation failures are an explicit C-platform
extension, distinct from the original Rust business-error enum. Request copying
can allocate in proportion to the supplied input before the HIA business check.
There is no additional one-mebibyte acceptance limit.

The returned value belongs to the caller, which releases it with `drop`.
An allocated seed is **consumed on every return** from
`signing_from_owned_seed`, including pin mismatch, allocation failure and a
null pin pointer. A null or wrong-kind handle is not a seed and is not consumed.
The caller must clear its consumed handle variable. `public_spki_from_seed`
borrows the seed and leaves it live. No secret-key export or key clone is
provided.

Signing, verifier and profile owners are immutable. Concurrent operations on a
live immutable owner use separate private arenas. A budget is mutable and must
be exclusively borrowed for the entire operation; dropping any object also
requires exclusive access. Caller-provided bytes are copied before native
processing. A valid public-key view may be supplied as a subsequent input while
its owner remains live.

Observation, signature, identity, profile snapshot and key-list values own
their public bytes. Their validity does not depend on the original owner or
input buffers. This is an intentional ownership extension to Rust's borrowed
observations. A `trnm_pq_view` borrows from the particular value passed to the
getter and expires when that value is dropped. Views are read-only. Getters do
not expose seed bytes, expanded secret keys, private work buffers or writable
budget state. A mismatched getter returns a null, zero-length view; a mismatched
scalar getter returns `UINT64_MAX`, except `kind`, which returns zero.

Every successfully allocated library buffer is overwritten before `free`,
including seeds, owner payloads, request copies, private arenas and public
results. This describes heap-buffer destruction. It does not claim register or
native-call-stack erasure, timing independence, hardware fault resistance, or
protection against a caller violating the live-handle contract.

## Original surfaces and result kinds

| Public entries | Original surface / result |
|---|---|
| `seed_copy`, `public_spki_from_seed`, `signing_from_owned_seed` | Owned 32-byte seed; public identity (100); seed-backed signing owner (2) |
| `verifier_from_pinned_spki`, key getters | `PqNativeVerifier` (3), exact strict SPKI and pinned key ID |
| `sign_exact_message`, `verify_exact_message` | Signature (101) or authenticated message observation (102) |
| `sign_statement`, `verify_frame`, `verify_tpq1` | Signed TPQ1 (103) or authenticated statement observation (104) |
| `verify_ml_dsa_65` | Original raw public-key/message/context/signature verifier; unit value (105) |
| `profile_from_pinned_keys`, `profile_snapshot` | `CandidateProfileVerifier` (4), immutable `BoundCryptoProfile` snapshot (112) |
| `profile_signer_ids`, `profile_pinned_keys` and indexed getters | Independently owned sorted signer IDs (113) and pinned public keys (114) |
| `profile_verify` | Candidate signature observation (107), including message, profile ID and signer count |
| `budget_new`, `budget_reserve`, `budget_snapshot` and budget getters | Cumulative `CandidateVerificationBudget` (5), public snapshot (108) |
| `profile_candidate_message`, `profile_commitment` | Canonical candidate message (109), original commitment digest (110) |
| `profile_active_at`, `profile_require_claim` | Original profile predicates / query value (111) |
| Error formatting entries | Original non-provider native errors and all profile errors; UTF-8 text (115) |

For public result values, `value_code` and the two detail fields expose the
native reply's first three unsigned 64-bit words. They are not valid owner
accessors. `value_bytes` gives the subsequent public payload. A successful
`profile_active_at` stores its boolean in `value_detail_a`; a successful claim
query has no payload. Budget snapshots put attempts and bytes in the two detail
fields and the exhausted boolean in their single payload byte. Budget getters
read the live budget without allocating.

Native-authentication error codes are Frame=1, KeyAlgorithm=2, KeyPin=3,
SignatureRejected=4 and OpenSslVersion=6. Frame detail codes preserve the ten
original `PqFrameError` variants. Compatibility/raw `PqAuthError` uses
PublicKeyLength=1, SignatureEncoding=2, ContextLength=3, MessageLength=4,
Signature=5 and Frame=6. Profile errors use category 1 for `ProfileError` and
category 2 for `CandidateError`, with the original subcode in detail A.
`error_display` accepts an actual native-authentication or profile error value;
`PqAuthError` has no original `Display` implementation. The two explicit enum
formatters preserve publicly constructible error-enum formatting without
exposing an observation constructor.

## Argument encodings

Integers in ABI descriptor byte strings below are little-endian. Their reserved
bytes must be zero. These are C-to-HIA argument encodings; the signed network
domains and their canonical big-endian fields remain unchanged.

| Argument | Exact bytes |
|---|---|
| Pin | 32-byte ML-DSA-65 key ID |
| TPQ1 expectation (136) | purpose U8, 7 zero bytes; network, owner context, signer key ID (32 bytes each); generation, operation sequence, expiry, now (four U64) |
| Profile binding (128) | network, parameters, genesis (32 bytes each); version U32, scope U8, retirement-present U8, 2 zero bytes; activation U64, retirement-or-zero U64, zero U64 |
| Pinned-key list | count U64 followed by each length U64 and that many raw public-key bytes |
| Expected candidate envelope | purpose U16, 6 zero bytes; generation, epoch, sequence, valid-from, valid-until, signer count, payload length (seven U64); signer IDs (64 bytes each); payload |

Profile tags are the original values: legacy ML-DSA-65=1, candidate ML-DSA-65=2,
candidate ML-DSA-87=3. Legacy policy is refused by the candidate constructor with
the original policy error. The constructor preserves binding-before-key-set
validation and the original canonical sorting/duplicate checks.

The exact-message bound is 65,536 bytes. TPQ1 payload processing accepts the
original maximum 67,108,864 bytes and streams the payload through canonical HIA
SHA-384; bounded internal chunks do not impose a smaller total limit. Candidate
policy keeps at most eight signers, 64 cumulative attempts and 8,388,608
cumulative bytes. Original reserve-before-verify behavior and error priority
remain in HIA. If result allocation fails after an attempt has been charged,
the updated budget is still committed; an allocation failure before dispatch
does not charge the budget.

## Construction

[`build_owned.py`](build_owned.py) compiles three canonical HIA business images
and the HIA [`owned_emitter.hepta`](owned_emitter.hepta). It actually executes
that emitter to produce the SysV ownership object, renames the three private
entries, and links one DSO using libc allocation/copy primitives. The exact
[`owned.map`](owned.map) export list hides private invocation and minting
symbols. Hosted Python only drives this build and test process. C allocator
observers are qualification-only and are excluded from the delivered DSO.

## Complete qualification and independent readback

Run the qualification on Linux x86-64 with the repository's pinned clean HIA
toolchain and native compiler, Rust 1.95.0, and the receipt and environment
produced by `scripts/ci/prepare_pq_provider.sh` for OpenSSL 3.5.9. The output
directory must not exist. The driver rejects unbound Rust, Cargo, loader and
native-tool overrides before creating its output.

```bash
python3 -I -S -B hia/platform/pq_auth/qualify.py \
  --output /tmp/pq-public-qualification \
  --rust-bin /path/to/rust-1.95.0/bin \
  --provider-receipt /path/to/provider.json \
  --provider-environment /path/to/provider-environment
python3 -I -S -B hia/platform/pq_auth/readback.py \
  --report /tmp/pq-public-qualification
```

This executes the unchanged crypto crate's 343 retained tests, two doctests,
formatting and strict Clippy with all features in a fresh Cargo target. The two
public API adapters are compiled from that actual Cargo graph. It then builds
the delivered HIA DSO, executes 1,609 native/original comparisons and 24,671 ABI
calls, tests all 55
exports, checks 190 allocator controls including 125 real allocation failures,
checks independent value lifetimes and eight concurrent read-only owner users,
and compiles and runs a C consumer of the public header. The extended corpus
includes all three public TPQ1 verification paths with an actual 64 MiB payload.
The Rust adapters and C consumer are observers and are absent from the product.

The reader checks the captured source graph, exact commands and limits, all
original test executables and raw output, actual native compiler requests and
objects, the HIA-emitted ownership object, the linked public image, the complete
case roster and lifecycle observations. It uses the pinned Core parser to
reconstruct the captured HIA compositions; it never executes a tested image.
Forty-nine rejection controls operate on the actual completed evidence,
including filtered Rust commands, substituted objects, omitted allocation
positions, false concurrency and altered process supervision. A failed or
partial run remains failed.

### Process deadlines and cleanup

The six native observation processes have fixed, disjoint case rosters. Each
process receives an absolute 240-second execution deadline, starting before
launch. A case's complete sequence of owner, budget and result operations stays
inside its process. The complete case order, original comparison requests and
24,671 ABI-call roster remain unchanged.

| Process | Cases |
|---|---:|
| `methods` | 1,480 |
| `extended-small` | 116 |
| `extended-max-sign` | 1 |
| `extended-max-frame` | 1 |
| `extended-max-tpq1` | 1 |
| `extended-tail` | 10 |

[`qualification/supervision.py`](qualification/supervision.py) starts each child
in its own process group and session. After execution, one independent absolute
three-second deadline covers group termination, pipe draining and reaping. It
sends at most one SIGKILL to that group, adopts orphan descendants through the
Linux child-subreaper facility, and refuses success if a descendant outlives the
leader, a stream remains incomplete, the group remains present or cleanup
exceeds its deadline. There is no second cleanup budget or unbounded child wait.
Receipts preserve the actual clock readings, timeout, group/session identities,
signal attempt and direct/adopted-child observations; scheduler delay is not
reported as an exact deadline wakeup. The reader rejects nonfinite clock values
and a supervisor duration that exceeds its enclosing stage's measured duration.

The native-build process and original comparison adapters also use 240 seconds;
the allocator, lifetime and header-consumer processes use 180 seconds. The
unchanged original Cargo aggregate retains its separate 1,200-second budget and
the original reader checks its complete 79-stage command and timeout contract.
These are qualification-process bounds, not an assertion that production
cryptographic calls have constant latency.

Eight short, real process controls cover normal output, nonzero exit, native
pause, a paused grandchild, an orphan after leader exit, a descendant holding a
pipe, a deliberately injected SIGKILL refusal and an absent executable. The
refusal is injected only at the supervisor's `killpg(SIGKILL)` call; it must
produce an incomplete-cleanup failure. A separate, recorded fixture teardown
then uses the real signal operation to remove the test process, without
promoting the supervisor's failed receipt. A separate algorithm control injects
clock and `waitpid` results to verify that even a continuous supply of reapable
children cannot extend the inner reaping loop beyond the existing deadline;
it makes no claim about actual process cleanup. The independent reader requires the
six production groups' exact 240/3-second contracts and the actual controls.
One full 240-second native-pause demonstration is retained as development
evidence; routine CI runs the same supervision code with short control
deadlines. Its total job duration is measured separately from that demonstration.

The output captures source inputs and all required original executables,
libraries, provider inputs, receipts and observations. `original/target` is a
reproducible intermediate build directory and is excluded from the retained
artifact inventory. Archive all other files without changing their bytes.
For a relocated source capsule, provide `--source-root <report>/inputs` and
`--source-set-sha256 <independently-recorded-digest>` to the reader. The digest is
an external trust anchor; it must not be invented from an untrusted report.

These gates qualify the documented public owner contract. They do not qualify
secret-dependent timing, stack/register erasure, arbitrary foreign pointers,
the OpenSSL-owned provider wrapper, TUF, the entire crypto crate, or a native
Node runtime.
