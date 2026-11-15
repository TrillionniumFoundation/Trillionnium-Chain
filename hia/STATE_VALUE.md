# Native Value foundation: exact boundary and remaining Node work

The two HIA sources are the runtime algorithms. The pinned native compiler
emits their machine code; Python supplies build orchestration, independent test
data and an isolated native test process. No host parser, sorting routine,
normalization algorithm, supplied verdict or digest performs their runtime work.
This qualification concerns the String type and an explicit finite generic Value
constructor profile. It does not retire the Node's current State or storage
owner. Source composition and tests remain hosted build/test tooling.

## Actual owner and source path

The ordinary Node owns `db: rusqlite::Connection` directly in
`trillionnium/crates/trnm-pon-node/src/store.rs`. Its State is imported from
`trnm_mvcc_fee::pon_executor` and is exactly
`BTreeMap<String, serde_json::Value>` (`pon_executor.rs:32`). There is no global
fixed `{balance, nonce}` State schema. The other M06 `ObjectStateV1` / Borsh engine
is a separate API and must not be substituted for this Node's State.

The live read path is `read_active_with_readback` (store.rs:3624): progress,
namespace, active identity/generation, state slot, `slot_state_with_progress`,
continuity checks against the block height, checked commitment/root, and optional
authenticated-state readback. `slot_state_with_progress` (3204) preserves SQL
types and dimensions before decoding each value. It checks count, key UTF-8 byte
length 0..160, stored value byte length 0..4096, key TEXT conversion and value
BLOB type, then original serde parsing and exact reserialization equality. It
returns no partial State. Progress checkpoints occur initially, every 256 rows,
and finally; cancellation identity is distinct from local integrity failure.

Snapshot replay (`state_at_with_replay_prefix`, 3980 onward) parses the complete
State snapshot, checks canonical snapshot bytes, continuity, and its commitment.
Each delta checks the old canonical value against its `before` bytes, inserts a
parsed `after` or removes the row, then checks the next commitment and continuity.
`apply_delta_with_progress` (6198) separately compares exact persisted bytes,
performs one SQL replacement/deletion, and requires exactly one affected row.
These transaction/undo/publication rules are not implemented by this codec.

## Original M06 Value domain and traversal

Source: `trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs:228-249`.

| Value alternative | Accepted M06 domain | Failure |
| --- | --- | --- |
| Null | `null` | None |
| Bool | `false`, `true` | None |
| Number | Original Number is u64 or i64; mathematical range -2^63 through 2^64-1 | `RANGE` for the F64 alternative, including 1.0 and -0.0 |
| String | Every byte is ASCII, including NUL, all ASCII controls, and DEL | `NONCANONICAL` |
| Array | Validate each child in original vector order | First child error |
| Object | In original map order, check each key is ASCII, then validate its value recursively | First key/value error |

The locked serde_json is 1.0.149. Its Map uses ordered keys in this dependency
configuration; no preserve_order/indexmap feature appears in the lock closure.
Object order is decoded UTF-8 String order, not the textual spelling of JSON
escapes. Duplicate insertion keeps the last Value. A discarded earlier value
does not participate in M06 grammar validation. It was nevertheless parsed by a
JSON text parser before that construction could succeed.

M06 `root` (327-347) first validates **all** State values in State BTreeMap order.
Only afterward does it check count <=65536 and call the wire root over each
key's raw UTF-8 bytes and the original serde canonical value bytes. Wire keys
are <=160 bytes and canonical values <=4096 bytes. Top-level State keys are not
subject to M06's nested Object ASCII-key rule. A late Unicode value or floating
number must precede LIMIT from an early oversized key or excessive State count.
The retained tests at pon_executor.rs:3993 explicitly enforce that order.

Node stored-byte decoding and M06 Value validation are separate layers. Node's
serde roundtrip can accept canonical Unicode strings or canonical floating
numbers and only later reject them through continuity/commitment/M06 logic. A
strict ASCII codec cannot replace that earlier Node parse operation without
changing error order. The new codec is not installed there.

## Complete String type codec

`src/state/json_string.hepta` exports f0(readbuf,mutbuf,mutbuf)->u32. Input byte 0 selects:

* 0: remaining bytes are the raw ASCII String. Validate the complete String,
  measure its JSON representation, check output capacity, and write that exact
  JSON string.
* 1: remaining bytes must already be a canonical ASCII JSON string; validate the
  complete encoding, check output capacity, and write its raw String bytes.

Success returns bytes written. `0xfffffffd` is local capacity,
`0xfffffffc` is rejected String/canonical-string content, and `0xfffffffb` is an
invalid operation envelope. Output stays unchanged on refusal and after the
successful returned extent. Scratch is unused. The explicit borrowed profile
limits total input to 1 MiB. Capacity is not M06 LIMIT.

The exact serializer escapes quote/backslash and ASCII controls. Backspace,
tab, newline, form feed and carriage return use their short escapes. Other
0x00..0x1f values use lowercase `\u00xx`. Slash and DEL remain literal. The
inverse rejects alternate spellings such as `\u0041`, `\u0008`, `\/`, uppercase
hex, raw controls, whitespace/trailing bytes and non-ASCII strings. This inverse
is deliberately not general serde JSON text parsing.

## Generic JVT1 typed constructor

`src/state/json_value.hepta` accepts `JVT1` followed by exactly one node. A node has:
`tag:u8`, `payload_bytes:u32le`, then its exact payload.

| Tag | Payload |
| --- | --- |
| 0 / 1 / 2 | Empty; null / false / true |
| 3 | u64 little endian, 8 bytes |
| 4 | i64 two's-complement little endian, 8 bytes |
| 5 | finite IEEE754 f64 bits, 8 bytes; represents an original Number that M06 rejects with RANGE |
| 6 | Raw valid UTF-8 String bytes |
| 7 | u32le child count followed by that many complete nodes |
| 8 | u32le insertion count, then repeated u32le UTF-8 key length, raw key, complete value node |

This constructor may receive unsorted object insertions and duplicates. The HIA
program validates all constructor framing, UTF-8 and finite-number shape,
constructs the private tree iteratively, heap-sorts each object's children by
decoded key and original insertion position, and keeps only the last member of
each equal-key group. It then performs M06's depth-first grammar pass on the
winning tree, in sorted object or original array order. Only after that complete
pass succeeds does it check output capacity and encode compact canonical JSON.
No host parser, sort, duplicate reducer, supplied digest, or claimed verdict is
used by the native algorithm.

The current explicit local ABI is input <=65536 bytes, <=8192 constructed nodes,
scratch >=721152 bytes. Its 80-byte node records begin at scratch 256, and the
8192-element private sort index starts at 655616. Traversal uses parent/sibling
links and does not recurse. Success returns canonical byte count. RANGE is
`0xfffffffa`; NONCANONICAL is `0xfffffffc`; malformed constructor framing is
`0xfffffffb`; local capacity is `0xfffffffd`. There is no M06 LIMIT return here.
Framing, UTF-8/type shape and local capacity are the constructor admission layer,
before the original Value semantic layer. Container/number/string shape for a
node is checked before its node-allocation capacity. Those new ABI failures
must not be relabeled as an original M06 grammar or wire error.

`components.json` explicitly includes `json_short_escape`,
`json_ascii_measure` and `json_ascii_encode` from `src/state/json_string.hepta`.
The byte-identical UTF-8 and integer helpers now live once in
`src/codec/json_primitives.hepta`; this component explicitly selects
`value_utf8`, `value_integer_size`, `value_word` and `value_integer_write`.
The generic file carries no duplicate String or shared primitive algorithm.
The regular repository builder captures all three sources and the include declaration, verifies the closed
program through the pinned Core assembler, and selects the fixed native
compiler's official `selfhost_elf` output profile. Neither source requires a
source-path guard exception, a generator at build time or a host emitter fallback.
The HIA output is an actual object/shared library; it does not by itself qualify
a complete independently native build toolchain or an executable Node.

A compact constructor without discarded duplicate history can represent every
accepted canonical Value of <=4096 bytes in this profile: by structural
induction its node tape uses at most 13 times the JSON byte length, plus the
4-byte JVT1 prefix, and its node count is at most the JSON byte length. Thus the
maximal bound is 53252 tape bytes and 4096 nodes. This representation fact does
not cover all oversized/deep rejected State inputs, nor make this profile an
equivalent upper bound for State. An oversized constructor can encounter local
capacity before a later Unicode/float; that remains an ABI refusal, never LIMIT.

## Account fields are not a replacement schema

`View::account` (pon_executor.rs:1373) supplies `{balance:0,nonce:0}` only when the
account is absent; existing records retain all fields. `field` (208) produces
STATE for missing/non-object access and RANGE for a present non-u64 value.
Credit changes only balance using checked u64 addition. Debit checks balance
first, then positive amount/sufficient funds, and retains other members. Nonce
fee admission reads nonce, checked-adds one, compares NONCE, then computes fee.
The independent Node `next_nonce_from_state` (store.rs:1277) instead uses
STATE_NONCE for malformed existing nonce and NONCE_OVERFLOW for successor
overflow. These distinct getters/errors cannot be unified by narrowing a JSON
record to two fields.

## Executable original oracle

`tests/rust_state_reference.rs` constructs or parses the original serde Value/State,
calls original public `trnm_mvcc_fee::pon_executor::root`, and serializes using
the original serde_json. It never copies the canonical validation algorithm.
For a singleton Value under an empty State key, original root LIMIT means the
grammar pass succeeded and only that value's wire extent was rejected; the
fixture reports grammar OK and root LIMIT separately. Tape decoding is a bridge
to original Value/Map constructors, with actual Map insertion for last-wins.

Commands are documented at the top of the fixture. They build the retained
locked M06 crate into a fresh Cargo target, then link the fixture to its rlib and
the one exact serde_json rlib in that fresh target. Both original differential tests use
`TRNM_HIA_RUST_STATE_REFERENCE` only when explicitly configured. Local
native controls have executed; original Rust differential remains NOT_RUN until
that actual binary is built and invoked. No local Rust compilation is claimed.

The fixture also accepts original JSON text and complete State JSON for future
cross-checks, including unsorted keys, duplicate keys, -0/floating syntax and
late semantic errors after oversized State dimensions. JSON text parsing itself
is not implemented by either HIA source: lexical errors, exact serde error
messages, parser recursion limits, JSON escapes/Unicode surrogate construction,
and float parsing remain a separately qualified layer.

## Minimal path still required to a typed Node owner

1. Admit a complete, explicitly owned State representation with real UTF-8 keys
   and ordered winning Values; retain every row and original semantic order.
2. Complete all Value semantic validation before count/key/value wire limits,
   using caller-provided extents or streaming state for large rejected inputs.
   The fixed local tape profile cannot supply this global guarantee by itself.
3. Produce canonical value bytes and compose the existing HIA state-root leaf,
   sort and sparse-tree helpers. The current state_root f0 accepts SRV1 bytes and
   rejects wire limits early; it must be called only after the complete typed
   pass or refactored into explicit reusable helpers. No Rust prevalidation.
4. Preserve Node's distinct snapshot/row/delta decode, root/continuity, undo,
   before/after comparison, cancellation and local-integrity boundaries.
5. Publish those complete typed transactions through StoreOwner, extending its
   16 MiB/4096-commit finite profile for original State and history requirements.
   Then integrate replay/outbox/reorganization/external witness semantics.

Neither String nor JVT1 success closes State, CheckedCommitment, Node, SQLite
retirement, continuation budgets, or the durable owner's complete typed reducer.
No Rust Vec capacity equivalence is claimed: M06's unescaped-string optimization
preserves three writes and initial capacity 128 for existing workspace
accounting; HIA arenas will need an explicit replacement accounting contract.

## Tests and integration

`tests/state_value_cases.py` is an independent Python test-data model.
`tests/test_state_string.py` executes 1047 native cases, including all ASCII
bytes, exact and short capacities, canonical-inverse refusals and the exact
1 MiB input boundary. `tests/test_state_value.py` executes 471 native cases,
including iterative depths 1500 and 7280, 1000 reverse object keys, 2000 discarded earlier
float values, exact 8192-node/65536-byte admission, last-wins/error ordering,
UTF-8 admission boundaries and intact output/scratch tails. Every native case
requires a returned ABI status and verifies the read-only input is unchanged.

Both classes also invoke the original Rust fixture when the explicit environment
variable is present and compare its canonical bytes/errors to fresh native HIA
calls. String inverse comparison requires the original parsed value to be a
String and original reserialization to equal the complete supplied JSON string;
it does not replace serde parsing with the Python model. Value comparison uses
original Value/Map constructors and the actual M06 `root`. Constructor FRAME and
CAPACITY are reported as test-bridge/local ABI results, never as original M06
errors. The one insufficient-scratch case is not sent to the Rust fixture,
which has no borrowed-scratch ABI.

The original test fixture evaluates inputs in an explicitly allocated 64 MiB
thread stack. This supports original recursive Value construction, original
root/serialization and destruction for the finite tape's maximum array depth
7280, without narrowing the HIA input domain to a default host thread stack.
It is a test resource profile, not Node workspace or continuation-budget
equivalence; a panic, abort, missing output or timeout still fails the fixture.

The local development report records native observations and separately records
original Rust as NOT_RUN when no compiler/binary is available. Missing Rust
must not qualify an integration that requires the retained-original oracle.
The CI integration must require `TRNM_HIA_RUST_STATE_REFERENCE` alongside the
other original-crate references and bind M06 source/Cargo inputs plus these
new sources/tests/ABI to its exact source inventory.

Candidate test commands, after setting the existing pinned HIA environment:

```sh
python3 -B -m unittest -v hia.tests.test_state_string hia.tests.test_state_value
```

This document and `state-value-abi.json` describe the same current implementation;
`qualification/state-value-development.json` is the sole retained local report.
No source-author generator, compiled ELF/shared object, former process version
or transient per-case output belongs to this component's retained source set.
