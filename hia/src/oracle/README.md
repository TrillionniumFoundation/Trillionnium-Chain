# Native Oracle values and concrete JSON surface

[values.hepta](values.hepta) implements all 22 explicit public methods and
functions in the current, unchanged
[trnm-oracle library](../../../trillionnium/crates/trnm-oracle/src/lib.rs).
[serde_json.hepta](serde_json.hepta) implements the six public data types'
concrete `serde_json 1.0.149` `from_slice` / `to_vec` surface in both its
default and workspace `arbitrary_precision` feature configurations. Both units
are compiled to actual x86-64 machine code by the pinned native HIA compiler.
The Python files only author test inputs, build artifacts and record execution;
there is no host implementation or fallback inside a native call.

The actual original module graph is the inline `src/lib.rs`. The adjacent
`snapshot.rs`, `validation/policy.rs` and external `src/tests/` files are not
referenced by this library. Qualification compiles the complete original inline
crate and runs all 118 retained tests in each of the four combinations of
release/checked arithmetic and default/workspace JSON features (472 executions). No original source is extracted,
rewritten, patched or substituted by an algorithmic comparison model.

## Public behavior

| Original public surface | Native behavior |
| --- | --- |
| `OracleSourceId::parse`, `as_str` | Full UTF-8 String domain; Unicode White_Space trim, ASCII-only lowercase, and the original Unicode control-character refusal. The raw `as_str` path preserves values constructed through the original Deserialize implementation. |
| `OracleSnapshot::new` | Feed, window, every original-order source, sorted duplicate, then sample-accounting checks in original order. Successful construction sorts the sources and computes the original digest. |
| `compute_hash`, `validate_hash` | Exact original SHA-256 byte framing, order, option tags and full signed/unsigned 128-bit values. Hash validation preserves trim/lowercase, canonical format and mismatch precedence. |
| `OraclePolicy::validate`, `validate_snapshot` | All five policy checks and all snapshot checks in original order, inclusive timestamp boundaries, exact u128 saturating deviation arithmetic and the original nonzero deviation threshold equality rejection. |
| Observation and Metrics, three methods each | Original u32 sums, outcome totals and sample-count conservation, including the difference between wrapping and checked arithmetic. |
| Report, eight methods | Separate metrics/observation methods, exact matching, explicit unclassified failures, original error-label trimming and original short-circuit evaluation. |
| `validate_snapshot_observed` | Complete report fields, original labels and detailed hash mismatch or invalid-policy errors. Canonical source cardinality is computed independently of the first validation failure, and each call represents one observed snapshot. |

The original crate contains no binary64 field or arithmetic. Snapshot value and
median are `i128`; MAD is `u128`; counters are `u32`; timestamps are `u64`.
Deviation uses a saturating u128 numerator before division. This can produce a
small quotient at extreme magnitudes; the native code preserves that original
behavior rather than replacing it with floating-point or unlimited arithmetic.

The original hash has **no namespace prefix**. It hashes the feed bytes, `ff`,
16 little-endian value bytes, `ff`, a little-endian u32 source count, each source
followed by `ff`, the u32 sample count, `ff`, median and MAD presence bytes with
optional 16-byte values, then three little-endian u64 timestamps. Constructor
sorting does not change `compute_hash` on an independently supplied unsorted
snapshot. None and Some(0) remain distinct.

Source processing uses an in-place heap sort and binary searches over source
indices, giving O(n log n) String comparisons for n sources. Validation still
reports the first invalid or repeated source in original input order; sorting
the index does not change that error order. Observed canonical cardinality uses
the same heap sort over normalized Strings followed by adjacent deduplication.
No source-count limit is added. Large reversed, ordered, repeated and normalized
alias inputs are compared against actual original executions.

All 20 original error variants are represented with their full typed fields and
original Display text. Oracle acceptance remains data admissibility. These
values do not authorize settlement, establish source-chain finality, deduplicate
bridge replay or authenticate a network source.

## Arithmetic profiles

The workspace has no Oracle-specific development, test or release override.
Cargo's normal development/test checked u32 addition can panic; normal release
addition wraps. The native adapter exposes an explicit qualification profile
selector: 0 uses u32 wrapping; 1 executes a real HIA checked u32 addition and
traps on overflow. This selector is part of the native typed adapter, not an
added field in any original Oracle value or stored hash.

The reference compiles the complete original crate with `opt-level=3`,
`overflow-checks=off`, `debug-assertions=off` for release, and `opt-level=0`,
`overflow-checks=on`, `debug-assertions=on` for development/test. It uses two actual locked Cargo dependency graphs, records their identities
and runs the full retained inventory in all four combinations. The reference catches an actual
original arithmetic panic solely at its test transport boundary and records
status 250 plus the original panic stderr. The corresponding native invocation
must trap in an isolated process; it cannot return an Oracle error or success.

For `bridge_contract_consistent`, the original eagerly computes outcome
conservation before the final conjunction. A zero sample count cannot suppress
an arithmetic panic that would occur in that local computation. Observation
arithmetic is still skipped when the preceding metrics conservation is false.
A separately supplied report whose mathematical counter sum exceeds u32 can
therefore satisfy the original release wrapping check. This migration preserves
that original behavior; it does not promote report consistency to authenticated
bridge evidence. The generated observed-validation reports use only 0/1 counts.

## JSON behavior

The current workspace data-availability dev-dependency enables
`serde_json/arbitrary_precision`; workspace-wide test commands can unify that
feature into Oracle tests. An isolated Oracle build uses serde_json default
features. The suite retains both actual Cargo configurations. They have explicit
JSON profile selectors and independent original adapters. The six typed APIs
currently share the native integer/String paths; generic serde_json Value
number behavior is not silently substituted for these typed APIs.

The concrete JSON unit preserves declaration-order serialization, full decimal
integer ranges, original JSON String escaping, UTF-8, map and sequence forms,
missing optional values and recognized-field duplicate rejection. Observation
and Metrics reject unknown fields. Snapshot, Policy and Report ignore unknown
fields; the ignored-value grammar matches the original `IgnoredAny` behavior,
including its treatment of raw bytes or unpaired escaped surrogates inside
ignored strings and oversized number lexemes. The ignored container stack is
sized from the input rather than a new 128-element protocol bound.

A missing or null `median`/`mad` becomes None. A missing or null report error
becomes None and is omitted when serialized; Some("") remains present. A known
String still requires valid Unicode and proper surrogate pairing. An ignored
value does not become an accepted value in a known field. No validation or
canonicalization is silently invoked by deserialization or serialization.

JSON admission failures are exposed as a separate adapter result with code 1
and no payload. The independent original adapter retains serde_json's actual
error text in stderr. This native wrapper does not claim to reproduce external
serde_json error wording, line/column diagnostics, every possible generic Serde
deserializer, or unrelated serde_json Value behavior.

## Native adapter contract

Each unit exports `f0(readbuf, mutbuf, mutbuf) -> u32`: immutable typed input,
caller-owned output, and caller-owned mutable workspace. All Oracle operations
are stateless values. There is no authorization state supplied by a caller and
no hidden registry, allocator, filesystem or network consumer in these units.
Output publication is atomic: the implementation stages a complete reply and
checks output capacity before copying. Workspace may change during any admitted
call; input bytes and output tails are preserved.

The values header is `ORAC0001`, an operation u64, and arithmetic-profile u64.
Operations 0–10 select source parse, snapshot construction, hash, hash validation,
policy validation, snapshot validation, observed validation, an Observation
method, a Metrics method, a Report method, and raw source text respectively.
The JSON header is `ORJS0001`, type u64 (SourceId, Snapshot, Policy, Observation,
Metrics, Report), direction u64 (decode/encode), and combined-profile u64. Bit 0 selects checked arithmetic and bit 1 selects
the workspace `arbitrary_precision` JSON configuration (values 0–3).
All frame words are little-endian. u32 fields must fit u32, flags must be 0 or 1,
Strings have exact u64 byte lengths and valid UTF-8, and trailing bytes fail.
Empty reserved storage for a None option must be zero. The qualification adapter
constructs raw SourceIds through actual original serde_json Deserialize, so
noncanonical but typed source strings remain expressible.

Transport return codes are 100 for malformed typed framing, 101 for insufficient
workspace, and 102 for insufficient output. A complete returned reply uses
return code 0 and contains business-code u64, payload-length u64, then payload.
Values business codes 1–20 correspond to the original OracleError declaration
order; JSON code 1 denotes actual concrete deserialization rejection. Typed
response structures and the exact adapter parser are documented in the
[original comparison adapter](../../tests/oracle_original.rs).

Values workspace requires `32768 + 10 * input_bytes`; JSON workspace requires
`32768 + 16 * input_bytes`. These are checked allocation extents, not artificial
limits on an original String, source count or numeric domain. The existing
native-support test runner limits each borrowed test argument to 1 MiB; that
runner constraint is not an Oracle protocol limit.

## Evidence and remaining integration

Run the [complete suite](../../tests/test_oracle.py) with the pinned HIA toolchain
and compiler environment, `HIA_ORACLE_OUTPUT` naming a **new** output directory,
and `HIA_ORACLE_DEPS` naming the actual default Cargo dependency directory.
`HIA_ORACLE_WORKSPACE_DEPS` supplies the independent graph with
`serde_json/arbitrary_precision`. Build these with the complete original
`cargo test --locked -p trnm-oracle --lib --no-run`, adding
`--features serde_json/arbitrary_precision` for the second target directory.
Alternatively, `HIA_ORACLE_DEPENDENCIES_JSON` and
`HIA_ORACLE_WORKSPACE_DEPENDENCIES_JSON` name maps from the five exact dependency
crate names to their actual rlib paths. The suite rejects ambiguous versions or
a feature artifact that does not match its declared configuration; it never skips a missing original
reference. `HIA_ORACLE_RUSTC` may select the installed rustc executable.

The evidence directory retains actual native and original executables, all four
retained-test binaries, native compiler/object/linker streams, composed source,
source snapshots, exact original/native requests and raw process outputs,
observed buffers, comparisons, test roster and failures. PASS requires the full
expected test roster, zero unsuccessful methods, and identical source and
artifact identities before and after execution. Real timeout, missing-executable,
class-setup failure, actual class-teardown artifact failure and changed-artifact
controls verify failure reporting. A successful class-finalization gate is
required in addition to successful test methods; class errors cannot become PASS.
Historical development failures remain outside the final implementation.

Production Node ownership, network ingestion, bridge replay/finality, deployment
activation and cross-request consumer wiring are separate work. This delivery
alone does not authorize retirement of the original package or claim whole-chain
native completion.
