# Native default Settings construction

`settings_development.hepta` implements the complete default public
`trnm_pon_node::Settings::development(Option<u64>)` construction relation. It
builds the default `Config`, the entire initial `State`, the network and
parameter identities, and genesis. It returns a complete local representation
of those fields. It does not open a Node database, load operator configuration,
select a deployment key, or grant a transport or persistence capability.

## Exact original boundary

The original constructor delegates to legacy evaluation, the legacy task
profile, the `linear-expert-dev-v1` model, no task windows, and no funded-actor
extension. Its compile-time inputs are these four original files:

| Input | SHA-256 |
| --- | --- |
| `config/pon/devnet-v1.json` | `4491b96ead11a020e8d71f27713368b65e663eef5cfc6fd0800a166b0c2a20d4` |
| `config/pon/ledger-v1.json` | `6755e36aab0ab9f4743da331a8dcd3374d657ff80f027ecf28db922e6d5ea39a` |
| `config/pon/work-profile-v1.json` | `03f7537b2fc3fa0c2f7036dd73d7088ba1ce50eafe6f2c907087d30385320880` |
| `config/pon/model-family-v1.json` | `30b250db074e7fbb5776c1474371258a6110cc1742e0e9970232a799ab790ca1` |

The HIA source contains typed literal representations of those complete
compile-time Values. Long literal data uses a small native LZ expansion to fit
the unchanged compiler instruction and assembly limits. This representation
contains no precomputed network, parameter, public key, task, State root or
genesis result. The shared full Value encoder constructs the canonical JSON
bytes at runtime. Signed integer values in the model are preserved.

Native execution performs all of the following:

- Original Config revision and development-scope checks; canonical encoding of
  all four Values; network, parameters, family and plan hashes.
- All 12 original ledger fee tags with duplicate/range/count checks, followed
  by the original explicit fee assignments through tag 24; fee slot 0 is zero.
- All three evaluator public keys from the original domain-separated
  `DEV-ONLY-KEY` seeds, with sorted public-key order.
- Both 4,096-cell maintenance matrices, their original little-endian task
  transcript, and its domain-separated task hash.
- Four development account public keys, their balances and zero nonces,
  `meta:issued`, the zero `model:current`, and the maintenance work entry.
- Canonical bytes for every initial value, the complete 256-level sparse State
  root, and the original genesis transcript.

`None` uses the original fixed genesis timestamp `1800000000` and original
`trnm-pon-invariant-contract-devnet-3` chain label. It does not read a clock.
`Some(t)` requires `1 <= t <= 9223372036854775807`, sets the timestamp and the
label `trnm-pon-native-wall-devnet-3-{t}`, and recomputes network and parameters.
Consequently `None` and `Some(1800000000)` have different chain identities.
The complete default Config is constructed before the original `GENESIS_TIME`
check, preserving that public constructor's observable error order.
The `GENESIS_TIME` result preserves the original diagnostic, unclassified kind,
absent typed code and source, and `requires_owner_stop == false`; the original
gate observes these public error facts as well as the message.

The operator bootstrap, operator material, checkpoint paths, task windows and
native PQ owner fields are all absent in this exact constructor. The emitted
absence bits are observations of construction, never caller-supplied authority.

## Borrowed ABI

The only public export is `f0(readbuf, mutbuf, mutbuf) -> u32`. The foreign owner
must supply three live, exclusively owned, nonoverlapping regions. Sequential
reuse after return is supported. The component does not authenticate arbitrary
foreign pointers or manufacture private owner capabilities.

Input is exactly `SDV1 || option:u8`: option 0 ends the input and represents
`None`; option 1 is followed by one little-endian `u64`. Other tags, versions,
truncations and trailing bytes are refused.

Output requires at least **16,384 bytes**; scratch requires at least
**300,000 bytes**. These are constructor workspace requirements. They do not
replace original block, transaction, State or file limits. Success returns the
number of output bytes. A normal refusal preserves the entire output. Success
writes only the returned prefix; output and scratch tails are preserved.

Construction temporarily uses output for literal Values while a read loan
allows the canonical encoder to consume them. The first 16,384 caller bytes
are saved in private scratch and restored before either the final commit or a
normal refusal. A signal or process failure is not a returned result and must
not be treated as successful construction. The visible low 141,568-byte crypto
arena is wiped at every normal post-construction return. This is not a claim
about compiler stack erasure or general deployment-key custody.

### Result layout

All integers are little endian. Bytes not assigned below are zero.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | `SDO1` |
| 4 | 4 | Complete result length |
| 8 | 4 | Option-presence flags, all zero for this constructor |
| 12 | 4 | Reserved |
| 16 | 8 | Genesis timestamp |
| 24 | 32 | Config network |
| 56 | 32 | Config parameters |
| 88 | 32 | Config family |
| 120 | 32 | Config plan |
| 152 | 32 | Settings genesis |
| 184 | 32 | Initial State root |
| 216 | 32 | Maintenance task hash |
| 248 | 200 | All 25 Config fees as `u64` |
| 448 | 4 | Evaluator count, 3 |
| 452 | 4 | Initial State row count, 7 |
| 456 | 4 | Canonical params byte length |
| 460 | 4 | Canonical model-registry byte length |
| 464 | 4 | Complete `SRV1` initial State byte length |
| 468 | 12 | Reserved |
| 480 | 96 | Three evaluator public keys in BTreeSet order |
| 576 | Variable | Params JSON, model-registry JSON, then complete State |

Presence bits 0 through 5 correspond to task windows, native PQ v2, operator
bootstrap, operator material, checkpoint paths, and the optional OpenSSL PQ
account owner. The last field exists only under its original Rust feature; it
is absent for this default construction in either case.

The State suffix uses `SRV1 || count:u32 || rows`, where each row is
`key_length:u32 || value_length:u32 || key || canonical_value`. Rows are in
original BTreeMap key order. The result for `None` is 4,061 bytes.

| Return value | Meaning |
| --- | --- |
| Below `0xfffffff0` | Successful result length |
| `0xfffffff0` | Malformed constructor ABI input |
| `0xfffffff1` | Output or scratch capacity refusal, before construction |
| `0xfffffff2` | Config construction/internal immutable-input check failed |
| `0xfffffff3` | Original `GENESIS_TIME` refusal |
| `0xfffffff4` | Maintenance task construction failed |
| `0xfffffff5` | Initial account/public-key/State construction failed |
| `0xfffffff6` | Initial State-root construction failed |
| `0xfffffff7` | Genesis hash construction failed |

With the pinned valid compile-time inputs, invalid `Some` timestamps are the
only original public-constructor semantic errors exposed by this API. The
remaining codes preserve internal failures; they are not replacement versions
of every error from the broader configurable Settings family.

## Compact complete sparse root

`../protocol/state_root_compact.hepta` provides the complete byte State-root
relation with a compact shared SHA-256 composition. It accepts actual keys and
values, never claimed leaf/path/root hashes. It validates the entire `SRV1`
grammar, applies count 65,536/key 160/value 4,096 bounds, rejects duplicate hash
paths, heap-sorts the leaf table and combines all 256 levels from the leaves
upward. Empty trees and present empty keys/values remain different.

Its public `f0` requires 32 output bytes and
`132288 + 64 * count + input_length` scratch bytes. Complete grammar, limits
and trailing-input checks precede workspace writes. Return codes are length 1,
version 2, limit 4, collision 5, capacity 100, internal 101, and success 0.
Success changes only the first 32 output bytes. The private `csr_arena_root`
entry accepts a source range already in the exclusive scratch arena; it checks
that this range is disjoint from its low hash/row/empty workspace before work.

Settings uses this same generic helper on its actual seven encoded rows. The
helper does not contain a seven-row root or fixed sorting outcome. The existing
large-State optimized component and its qualification are retained. Local
compact-helper controls cover multiple counts through 65, full key/value
limits, malformed count 65,536 and excessive counts, collisions, ordering and
capacity. They do not claim a successful 65,536-row compact-helper timing run
or transfer the optimized component's performance qualification to this one.

## Original comparison and remaining owners

The original differential gate copies the real source tree and appends only a
new `cfg(test)` child to the Node library. It invokes the unchanged public
`Settings::development` method and observes its complete fields. Public original
PQ predicates are used only after asserting the default selectors are absent;
production field visibility is not changed. Original errors use their actual
`Display` text. Cargo JSON must identify exactly one fresh original lib-test
executable. Compilation and runtime stdout/stderr remain separate receipts.

Run the native tests with the locked toolchain environment:

```sh
python3 -B -m unittest hia.tests.test_node_settings hia.tests.test_node_settings_memory hia.tests.test_settings_original_gate -v
python3 -B hia/tools/qualify_settings_original.py --output /absolute/fresh/settings-original --require-rust
```

The original gate has 30 cases, including unsigned values above `i64::MAX`,
decimal boundaries and deterministic random valid times. Rust build budget is
600 seconds, original test execution 60 seconds, and each native invocation
60 seconds. Local absence of Cargo/rustc is `NOT_RUN` and a nonzero required-gate
exit. None of these development budgets certifies the original four-second
service budget, whole-Node operation or production activation.

Still open are alternate Settings constructors and profiles, CLI/environment
and file-owner inputs, actual deployment-key custody, immutable runtime
parameter-owner registration, Node/SQLite initialization markers and recovery,
and live transport owner integration. The original JSON/source inputs remain
necessary comparison contracts while those paths are open.

A complete Node cannot fit a single locked 128-function/8,192-instruction
compilation. The intended integration is multiple native HIA modules advanced
by an HIA command owner. A thin native dispatcher may pass exclusively owned
borrowed regions; it must not contain business algorithms or accept caller
booleans as authority. This constructor establishes its complete pure call
boundary; it does not claim that the larger owner composition is implemented.
