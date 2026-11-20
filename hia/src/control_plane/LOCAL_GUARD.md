# HIA local guard and explicit Ed25519 provider

`guard.hepta` implements the original `LocalPlanGuardV0::new` and `evaluate`
policy, using a concrete HIA-native signature provider. The complete original
Rust guard is the differential oracle. Its canonical plan, action and receipt
domains are unchanged.

The original repository defines the generic `PlanSignatureVerifierV0` trait;
its only implementation is the test-only `AcceptSignature`. There is no
production provider or node consumer to reproduce. This component therefore
introduces the distinct **`trnm.control.local-ed25519-provider.v1`** profile.
It is a local control-plane evaluator, with no consensus or activation authority.
It does not establish a production key policy, a persistent signature service,
or a node execution consumer. Those integrations remain separate work.

## Concrete signature contract

The constructor fixes one public key and a table of actual 64-byte detached
signatures in private HIA-owned memory. It also fixes the graph, contract set,
current generation and local parameter bounds. A caller does not supply a
verification boolean or a preverified-state record.

Let `H(domain, part)` be the original `Digest32V0::hash` with one part:

```text
SHA256(be64(domain.length) || domain || be64(part.length) || part)
```

The new provider uses exactly these byte strings:

| Item | Exact definition |
| --- | --- |
| Expected `signer_id` | `H(b"trnm.control.local-ed25519-provider.signer.v1", public_key_32)` |
| Signature table key | `H(b"trnm.control.local-ed25519-provider.signature.v1", signature_64)` |
| Ed25519 message | `b"trnm.control.local-ed25519-provider.plan.v1" || canonical_plan_digest_32` |

The message is 75 bytes: the 43-byte fresh domain followed by the original
32-byte canonical plan digest. It is signed as an ordinary Ed25519 message.
The signer and signature hash domains are 45 and 48 bytes respectively. No
domain terminating NUL, extra hash, length prefix or legacy domain is added to
the Ed25519 message.

Evaluation first runs the original plan shape and canonical-digest validation.
The provider then checks the expected signer, resolves `signature_digest` to
actual retained signature bytes by an internally computed hash, and performs
strict Ed25519 verification. It reuses the admitted HIA field/group arithmetic,
SHA-512 and joint verification functions. The original crypto crate supplies
the independent strict Rust verifier; neither adapter copies its arithmetic.

The strict policy retains canonical point encodings, point membership,
small-order rejection and canonical scalar bounds. A valid signature under a
different message domain is rejected. The original plan canonical digest
intentionally excludes `signature_digest`; the provider binds that field to
actual signature bytes separately. A zero signature digest is still rejected
by the original plan shape validator before the provider runs.

The constructor's public key is the configured verifier identity, as the
generic Rust constructor permits. Choosing which key a running application
trusts belongs to the application's configuration owner. A plan cannot replace
the key held by this guard.

## Owned execution and original policy

The exported entry allocates three private owners: an immutable copy of the
entire typed session, a guard index/configuration buffer, and a staged output
buffer. Bounds, signature bytes and digests are retained within those owners.
The externally supplied scratch buffer holds only temporary arithmetic and
hashing workspace. No externally returned guard-state record is accepted on
the next call.

Each entry call constructs one guard and evaluates an ordered sequence of
plans against it. Its lifetime ends after that sequence. Every success,
protocol rejection, capacity rejection and allocation-failure branch releases
all owners. Only a completely staged session result is published. A late
capacity failure publishes none of the earlier results.

The original semantics are preserved:

1. Construction checks nonzero source/contract digests and a positive current
   generation before examining bounds. Each bound is validated before checking
   whether its exact `(module_id, parameter_bytes)` target duplicates an earlier
   bound. Consequently an invalid duplicate bound reports invalid-bound first.
2. Evaluation checks plan shape, the concrete signature provider, graph/contract
   identity, checked generation increment, exact successor generation, inclusive
   activation window, then nonzero resulting-configuration/invariant facts.
3. A valid plan can produce an ordinary receipt with rejected individual actions:
   unknown parameters report error 19, out-of-bound values report error 20, and
   the receipt's `accepted` field is false. Action order and original action
   digest bytes are retained.
4. Parameter names are arbitrary bytes, including NUL and invalid UTF-8. The
   original 1..128-byte validation rule applies. Values and bound endpoints use
   the full signed i128 domain; no float, i64 narrowing or text conversion is used.
5. The optional governance and determinism values remain ignored by the original
   implementation. Their presence cannot authorize critical parameter classes,
   worker placement or forbidden actions; the original shape validator rejects
   those first.
6. `evaluate(&self)` does not advance the guard generation or mark a plan as used.
   Repeated identical evaluations return identical receipts, including after an
   accepted or rejected earlier receipt. The component adds no replay ledger or
   state transition absent from the original API.

## Local test and embedding ABI

All scalar transport fields are unsigned u64 little-endian, except signed i128
values, which use 16-byte little-endian two's complement. Digests and keys are
raw fixed-width bytes. This is a fresh local ABI, not an existing network or
stored-state schema.

```text
f0(session: readbuf, output: mutbuf, scratch: mutbuf) -> u32
```

The complete input must be typed and have exact EOF before construction begins.
Its 136-byte header is:

| Offset | Field |
| --- | --- |
| 0 | `b"NCPG0001"` (8 bytes) |
| 8 | Source graph digest (32 bytes) |
| 40 | Contract set digest (32 bytes) |
| 72 | Current generation (8 bytes) |
| 80 | Fixed Ed25519 public key (32 bytes) |
| 112 | Bound count (8 bytes) |
| 120 | Signature count (8 bytes) |
| 128 | Evaluation count (8 bytes) |

The header is followed by the bounds, signatures and evaluations in that order.
Each bound has a length word followed by the existing control-plane bound
payload: module, parameter class, i128 minimum, i128 maximum, parameter length,
then parameter bytes. Each signature occupies exactly 64 bytes; duplicate
signature entries are allowed and do not change the verification result.
Bounds and signature counts have no new protocol cap. Input extent and actual
memory availability bound their local representation.

Each evaluation has a length word followed by:

| Field | Width |
| --- | --- |
| Current height | 8 bytes |
| Resulting configuration digest | 32 bytes |
| Invariant result digest | 32 bytes |
| Governance presence | 8 bytes, exactly 0 or 1 |
| Present governance value | 104 bytes: plan digest, activation height, validator set digest, authorization digest |
| Determinism presence | 8 bytes, exactly 0 or 1 |
| Present determinism value | 160 bytes: plan digest, shadow replay digest, worker invariance digest, pre-root, post-root |
| Plan | Existing complete control-plane plan payload, consuming the remaining evaluation bytes |

The existing value payload definitions are in [README.md](README.md). Presence
flags do not validate the optional values' digests; the original typed API also
allows arbitrary values and ignores them during evaluation.

Successful construction and a completely staged evaluation sequence return 0.
Output begins with total byte length and evaluation count, each an 8-byte word.
Each result then has category, error and payload length (three 8-byte words),
followed by its optional original receipt payload:

| Category | Error | Payload |
| --- | --- | --- |
| 0 | 0 | Complete original `ActionReceiptV1` payload, including receipt digest and ordered action decisions |
| 1 | Original protocol enum 1..26 | Empty |
| 2 | 1: signer mismatch; 2: missing signature; 3: strict signature rejection | Empty |

Invalid construction returns its original protocol error directly and publishes
no output. Wrapper failures are 100 for malformed typed frames, 101 for output
capacity, 102 for scratch/extent, and 103 for allocation failure. They publish
no output. Precedence at this wrapper boundary is typed-frame validation,
scratch/minimum-output checks, ownership allocation, then original construction
and evaluation. The minimum output extent is 16 bytes; additional space depends
on the actual results. Each full receipt occupies `184 + 48 * action_count` bytes.

Scratch must hold at least `max(140800, 65536 + 3 * input_length)` bytes.
Unrepresentable extent arithmetic is rejected before allocation. The native
test process has a separate 1 MiB argument budget; that infrastructure budget
does not become an original control-plane API limit.

## Reproducible qualification

Run the repository preflight first. Set the pinned HIA toolchain/compiler
variables required by [native_support.py](../../tests/native_support.py), then:

```sh
HIA_CONTROL_GUARD_OUTPUT=/new/empty/evidence/path \
  python -m unittest hia.tests.test_control_guard -v
```

If `HIA_CONTROL_PLANE_SHA2` identifies the already-built sha2 0.10.9 rlib from
the locked original Cargo graph, its dependency directory supplies the exact
external libraries. Ambiguous dependency selection fails. Otherwise the test
builds the original locked Cargo packages in a temporary target directory.
It always compiles the complete unchanged original control-plane and crypto
sources, executes all five retained control-plane tests, builds the direct
original guard adapter, and builds the original Rust crypto signing adapter.
Absence of an oracle never becomes a skip or successful fallback.

The test output directory must be new. The evidence includes the actual HIA,
Rust oracle, retained-test, Rust-signing and allocation-observer binaries;
composed HIA source and build provenance; the Rust build, retained-test, signing,
oracle and allocator subprocess commands, stdin, stdout, stderr and exit;
every actual native call's input, output and scratch; source identities captured
before compilation and after execution; and a complete test roster. NativeModule
parses its isolated worker's JSON response into the retained native observations;
that worker's original stdout JSON is not separately retained. A finalized
PASS requires all expected test methods to finish successfully with unchanged
source. Partial runs, failed tests and skipped tests cannot produce a PASS.
The five original unit tests are retained unchanged; their test-only
`AcceptSignature` is not used as evidence of this provider's verification.

The tests cover actual Rust-generated signatures, fresh-domain negative
controls, malformed signatures and strict encodings, constructor error order,
all signed i128 boundary regions, u64 generation overflow, inclusive windows,
optional-evidence behavior, complete 128-action receipts, repeated evaluations,
typed truncation/scalar errors, output/scratch capacity, and all three real
allocation-failure positions. The C helper only observes allocation and calls
the emitted HIA entry; it implements no guard or signature behavior.
