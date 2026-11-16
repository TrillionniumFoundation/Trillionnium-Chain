# HIA native implementation

This directory contains the HIA migration of Trillionnium-Chain. Its target is
one complete HIA-native implementation. The current candidate contains **41
kernel units and eight native foundations**, accounting for all **59 HIA source
files**. The 26 existing Rust packages remain until their complete replacement
is qualified. The authoritative sequence remains the
[repository development plan](../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
[The migration inventory](../config/hia-migration-v1.json) accounts for every
original package and every new HIA source file.
The [audit report](AUDIT.md) records complete ownership, observed CI failures
and the exact limits of the current replacement.

## Fixed sources and audit

| Input | Exact identity |
| --- | --- |
| Consolidated Chain baseline | `59bd6ae4223caff6695dc9cf2ee2cdcdc6df5e88` |
| HIA toolchain | `TrillionniumFoundation/Hepta` at `f33d8da316de8fdf27b504371f1a5310997ff548` |
| Assembly / Core | `hia-asm.v1` / `hepta.hia.program.v8` |
| Executed target | Linux x86-64 |
| Qualified native compiler SHA-256 | `87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54` |

The baseline audit counted 41,834 tracked files and 3,999,565,648 bytes.
`evidence/` accounted for 36,222 files and 3,804,721,963 bytes. The active Cargo
workspace contains 26 packages, with 1,621 Rust files and 702,001 physical lines
including tests. Repository history had already been consolidated into `main`;
these counts do not describe 26 independent final implementations.

The ownership audit covers the entire tracked tree, the Cargo graph and all
18 long-lived modules. Semantic work in this increment concentrates on exact
wire parsing, integer work, hashing, replay, complete classical response codecs,
Settings construction, typed Delta semantics and native persistence. Existing
service, model-use, consensus-security and cross-architecture failures retain
their original status. Rewriting a deterministic function does not establish a
new proof of work hardness or satisfy an unexecuted service campaign.

## Observed qualification and current scope

The preceding `453326b335af` source completed all eight HIA jobs in both
[push](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43828760883)
and [PR](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43828945597)
qualification. Both ran 257 component tests, zero skips and 92,509 shared native
calls, including actual original-Rust consensus, mempool, AuditEvent and
RawBindings comparison. Its 52 physical storage controls passed with actual
syscall tracing; all 197 initialization recovery controls passed. These results
belong to that source; the new Host increment requires its own exact-source run.

The [original service campaign on the same head](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43828945620/job/133169304908)
still failed in the original four-second/16-attacker window: original and fresh
pressure phases both confirmed zero transactions. Their attack-free baselines
confirmed one request in 2.374779837 and 2.308299376 seconds. Fresh pressure Host
checks occupied 104,102,970 of 108,451,909 work-thread CPU nanoseconds; those are
nested intervals, not additive costs. This is the retained original Rust Node,
not a measurement of an integrated HIA Node. No service or identity guard was
relaxed. Earlier historical budget comparisons also refused before native
execution because their Cargo.lock differed; those failures remain recorded.

## Fresh native Host checkpoint owner

The [Host checkpoint owner](platform/host_checkpoint/README.md) performs actual
Linux reads for fixed-parent acquisition and every subsequent complete check.
Boot identity, the calling thread's membership, directory identity and all five
limits are reread; no prior descriptor, file content or verdict is reused.
Its HIA-emitted adapter confines data pointers and can grow only its own private
state mapping. The final rebuilt source passed 151 physical controls and 26
hostile-adapter controls, with four independent CLI/evidence tests.

The [development record](qualification/host-checkpoint-development.json) retains
the actual local tracing denial and failed mandatory-trace run. Separately,
145 real native cases matched actual original private Rust primitives and
fixture sequences; the original Host production file remained byte-identical.
The retained original tests passed 44 cases, with their original child probe
still default-ignored and explicitly called by its parent test. The initial
adapter compilation failure is preserved.

An independent 20-minute Host CI job now requires all physical controls with
real syscall tracing, the actual original Rust comparison, and a production
fixed-parent check inside the unchanged original resource limits. It binds the
whole exact committed source and permits provisioning only a previously absent
parent on an ephemeral hosted runner. Its production controller passed eight
refusal/evidence tests. A real early-exit race that lost 283 stderr bytes was
reproduced and fixed; primary and cleanup failures are retained separately.
The first two hosted production services failed, and a fixture-permission error also blocked their artifact upload. The [retained logs](qualification/host-production-ci-failure.json) record both failures; the inner production cause is unobserved. Explicit artifact selection and bounded real child diagnostics are now wired for the next exact-source execution. Resource
sampling, same-worker embedding, the complete Node and original four-second/
16-worker service acceptance remain open.

## Native AuditEvent values and exact RawBindings

The [AuditEvent component](src/audit/README.md) implements the original public
constructor, all six consuming builders, Clone and Eq. Its ten native tests
passed 2,847 calls, including every optional mask, field-local Unicode bounds,
all 128 amount bits, long middle-field replacement, and atomic refusal. The
unchanged original crate passed its three original unit tests and the same
1,849 semantic cases in an actual separate Rust execution. Its source-bound
[qualification record](qualification/audit-event-development.json) retains the
initial Rust adapter compilation failure, corrected run and native evidence.
AuditEvent is descriptive data; it does not prove that an event occurred.

The [RawBindings owner](src/mempool/RAW_BINDINGS.md) stores full digest/body
bytes in its own native private context. Seven tests passed 16,597 native
calls; 1,220 histories containing 16,471 operations match the complete actual
original Rust methods. A known digest is consumed before rejecting a mismatched
body, exactly as in the original. The [bound observations](qualification/raw-bindings-development.json)
retain actual input and output hashes. Signature checking, signer nonce state,
durable local-pool transactions and Node integration remain open.

These two sources were rebuilt and re-executed after an interrupted development
environment lost its temporary volume. Earlier native passes do not qualify
the replacement bytes. Mandatory final-source CI compares native results with
the actual original Rust implementations again; missing tools cannot skip it.

## Complete M02 arithmetic and physical initialization recovery

The [M02 Work and time-policy module](src/consensus/README.md) now implements the
complete original pure `consensus.rs` closure: 512-bit checked arithmetic, work
credit, target adjustment, parent-window selection and median-time checks.
The native source passed 6,308 emitted-machine calls. A real independent Rust
compiler executed the unchanged original module on the same 5,344 semantic
inputs, with every result matching the mathematical oracle also checked by HIA.
The mandatory hosted suite repeats a direct original/native comparison.

The [native StoreOwner](storage/README.md) adds explicit context-bound genesis
initialization recovery. It validates the exact genesis and any existing FORMAT
prefix, completes durable initialization, and reads the physical records back
before acknowledging success. The 197 physical controls include genuine process
interruptions, partial writes, cold reopen and concurrent object insertion. The
previously reproduced changed-prefix false acknowledgement is retained as a
regression and now refuses with no opened receipt. This closes the stated
initialization unit; full typed Node publication remains a separate integration.

## M05 lane policy and queue ownership

The [lane quota/fairness kernel](src/mempool/lane_quota.hepta) implements original
capacity, critical reserve, borrowing, dequeue and QoS decisions. The separate
[lane owner](src/mempool/OWNER.md) retains two actual private FIFO rings, exact
ID membership and fairness across native calls. The [policy contract](MEMPOOL.md)
and owner tests require the real original Rust crate. Signed admission, nonce
ownership and the Node's durable local pool need their own complete integration.

## Implemented native components

The [M05 native lane owner](src/mempool/OWNER.md) now retains both physical
FIFO rings, exact ID membership and fairness across calls in one private
allocation. Its local native controls passed 41,365 owner calls and 2,042
canonical-policy regression calls. A separate real Rust compiler built the
complete unchanged original mempool crate and matched all 41,248 public
operations across 1,862 histories. The exact hosted test additionally compares
original Rust and native replies directly and cannot skip a missing oracle.
The [bound development record](qualification/mempool-owner-development.json)
retains both observations. Typed signed admission, nonce ownership, durable
local-pool handoff and Node integration still require their own native owners.

| Source | Implemented behavior | Native tests |
| --- | --- | --- |
| [AuditEvent](src/audit/README.md) | Complete public value constructor, six builders, Clone and Eq | 2,847 native calls; 1,849 actual original Rust cases and three original unit tests |
| [RawBindings](src/mempool/RAW_BINDINGS.md) | Actual private digest/body ownership and consume-before-mismatch semantics | 16,597 native calls; 16,471 actual original Rust operations across 1,220 histories |
| [ID](src/protocol/id.hepta), [hash text](src/protocol/hash.hepta) | Exact identifier alphabet/length and lowercase hash grammar | Complete byte alphabet and boundary controls |
| [PNH1](src/protocol/pnh1.hepta), [PGH2](src/protocol/pgh2.hepta) | Fixed header grammar and original error order | Original independent header oracle and byte mutations |
| [ILF2](src/protocol/ilf2.hepta), [ILF3](src/protocol/ilf3.hepta) | Complete bounded factor/evolution witness grammar | Original vectors, every coefficient position, truncation and error precedence |
| [PNX1](src/protocol/pnx1.hepta) | Complete current envelope grammar, all 24 tags, funded contracts and nested witness validation | Independent byte specification, refusal precedence and original-Rust CI |
| [Sparse state root](src/protocol/state_root.hepta) | Original 256-level sparse root, exact domain framing, bounded heapsort and duplicate-path refusal | Independent bottom-up oracle, 65,536 actual rows, arena reuse and original-Rust CI adapter |
| [SHA-256](src/crypto/sha256.hepta) | Hash inputs through 1 MiB | Known vectors, `hashlib`, padding, real unaligned pointers and canaries |
| [SHA arena](src/crypto/sha256_arena.hepta) | One shared mutable arena for W1 hash input/output/work | Exact ranges, maximum length and no-write refusal |
| [SHA-512](src/crypto/sha512_arena.hepta) | Full SHA-512 and shared arena helper for Ed25519 | Independent hash oracle, padding, large messages, real unaligned pointers and canaries |
| [Ed25519 group](src/crypto/ed25519_group.hepta), [strict verifier](src/crypto/ed25519_verify.hepta) | Public field/group operations and strict signature verification through 128 KiB messages | Big-integer arithmetic, RFC vectors, all torsion/scalar boundaries and original-Rust CI |
| [PoN hash](src/crypto/pon_hash.hepta) | Original tag and per-part length framing | Original wire oracle, task/noise/header domains and ambiguous concatenations |
| [W1 encoding](src/work/encoding.hepta) | Fixed PNW1 size, magic and all canonical field words | All matrix rows and boundary words |
| [W1 field](src/work/field.hepta), [matrix](src/work/matrix.hepta) | Exact modular multiplication, addition, denoising and bounded matrices | Independent arbitrary-precision arithmetic, maximum values and dense products |
| [W1 verification](src/work/verify.hepta) | Complete deterministic non-cancelling PNW1 relation | Independent scalar transcript and direct `AB` product, target/trace/product attacks |
| [Replay](src/transport/replay.hepta) | Session/nonce/pending checks, ACK and pure successor proposals | Two native backends, original boundary vectors and Rust-reference CI |
| [Closed round](src/verification/closed_round.hepta) | Exact evaluator policy over canonical UTF-8 containers | Full-width scores, all arrival orders, Unicode, 1 MiB and Rust-reference CI |
| [Checkpoint V2](src/checkpoint/value_v2.hepta) | Canonical value construction/decoding, watermark, SHA binding and successor relation | Every record byte, truncation, field/error identity, full-width counters and original-Rust CI |
| [Binary64](src/math/README.md) | Shared exact finite binary64 arithmetic | Subnormal/exponent boundaries and 11,706 native arithmetic controls |
| [Executor](src/executor/README.md) | All seven scheduling strategies with explicit configuration and corrected maximum reader dependency | Independent conflict graph, 5,928 native calls, real 8,192-transaction arena and mandatory original-Rust comparison |
| [State String and Value](STATE_VALUE.md) | ASCII string codec and iterative typed Value construction, sorted last-wins objects, M06 grammar and canonical serialization | 1,518 native controls including a 7,280-level array; finite constructor profile and complete-State gate remain distinct |
| [Incremental SHA256](src/crypto/sha256_stream.hepta) | One continuous context, all compression blocks and one final padding | Fourteen controls through 2 MiB + 1,024 bytes |
| [Authenticated request](platform/transport_request/README.md) | All five classical request variants, complete 2 MiB frame and strict authentication equation | 178 native controls, complete payload mutation, original-default serde behavior and mandatory private original-Node oracle |
| [Shared JSON primitives](src/codec/json_primitives.hepta) | Single UTF-8, string and integer primitive closure, independently admitted before selection | 1,518 extraction controls; caller dependencies remain explicit |
| [JSON number](src/codec/json_number.hepta), [Value wire](src/codec/json_value_wire.hepta), [Value encoder](src/codec/json_value_encode.hepta) | Exact original-default serde number parsing/formatting, Unicode, complete Value construction and response serialization | 6,955 number, 3,546 Value parse and 372 Value encode controls; original Rust required in dedicated CI |
| [Ed25519 signing](src/crypto/ed25519_sign.hepta), [response verification](src/transport/authenticated_response.hepta), [signed response](src/transport/signed_response.hepta) | Complete classical response domains, signature production and strict verification | 73 signing, 33 producer and 125 verifier controls; producer uses a guarded private stack |
| [Settings development](src/node/README.md), [compact state root](src/protocol/state_root_compact.hepta) | Actual default configuration, four development keys, seven genesis rows and dynamically computed roots | 16 integrated tests, 102 shared-runner and 14 raw-pointer calls; 30 original-Rust cases required in CI |

The [cryptography guide](CRYPTO.md) specifies the SHA-512 and Ed25519 ABIs,
error order, arithmetic bounds and remaining key-ownership limitations. The
[state-root guide](STATE.md) defines the byte descriptor, scratch extent and
complete count/key/value limits. Its actual 65,536-row execution matched the
independent oracle in 299.705821145 seconds in exact `96a0846` CI; the prior
353.568397442-second local observation remains retained. These used small keys/values;
simultaneously maximal rows and values were not executed. The original service
time budget remains open. [Development observations](qualification/state-root-development.json)
retain the rejected over-capacity compiler optimization, the maximum-count run
and later controls with their distinct source and driver bindings.

The byte entries use `f0(readbuf, mutbuf, mutbuf) -> u32`. The scalar field
module uses explicit scalar exports. All tested algorithms execute emitted
machine code. Python supplies build orchestration and independent test inputs;
the Rust reference executable is a test oracle and is not a runtime dependency.

SHA-256 derives from Hepta's
`examples/hia_bootstrap/sha256.hepta` at the locked revision, original SHA-256
`93e97ac37f91fea4e0fa927f1af3b197bff31fb5f8edd2bfd4e70566fdc23c80`.
The public form changes the input bound to 1 MiB. The arena form combines the
views and moves only the digest/work offsets. No upstream license grant is
inferred from this repository's package metadata.

## Build and reproduce

Use a clean checkout of the exact Hepta revision in `toolchain.lock.json`.
Keep it outside this repository. The build driver refuses a different revision,
tracked modifications, an unsupported target or an unbound compiler executable.

```bash
export HIA_TOOLCHAIN_ROOT=/absolute/path/to/the/pinned/Hepta
python3 -B hia/tools/bootstrap.py --output /absolute/new/path/hia-bootstrap
```

Read `compiler` and `compiler_sha256` from the resulting `bootstrap.json` and
set `HIA_NATIVE_COMPILER` and `HIA_NATIVE_COMPILER_SHA256` to those exact values.
The bootstrap uses the official direct emitter for B0. Every successor and the
standalone compiler are emitted by HIA machine code. B1/B2/B3 must be identical;
the changed-source M1/M2/M3 witness must propagate and stabilize independently.

```bash
python3 -B hia/tools/build.py hia/src/work/verify.hepta \
  --backend selfhost --byte-export f0 --kind object \
  --compiler "$HIA_NATIVE_COMPILER" \
  --compiler-sha256 "$HIA_NATIVE_COMPILER_SHA256" \
  --output /absolute/new/path/work.o --receipt /absolute/new/path/work-build.json

python3 -B hia/tools/qualify.py --output /absolute/new/path/native-results.json
```

`selfhost` executes a sealed copy of the pinned native compiler with an empty
PATH. `direct` is a separately selected Python-hosted machine emitter used in
some differential controls. A refusal never switches between these routes.
GNU `ld` links generated objects for tests; it does not compile the algorithms
from another language. Calls execute in separate bounded processes. A signal,
timeout or missing report remains an execution failure.

### Shared HIA source

[components.json](components.json) selects named functions from single canonical
SHA, Ed25519, binary64, JSON and state-root sources. Storage v2 selects the existing
state-root SHA compression functions through its independently verified framing
component. There are no copied crypto or JSON helper implementations.
PNX1 explicitly includes the shared ILF2/ILF3 validators and coefficient scans. Their
entry files therefore require package composition before admission. The driver
checks each included source, joins only the named HIA functions and submits the
complete program to the official Core verifier and native compiler. It refuses
unknown names, duplicate symbols, traversal, symlinks and dependency cycles.
An included component may declare its own explicit dependencies. Core must
validate that entire component independently, even functions the caller does
not select. Only functions defined in the component's own source can be
selected; its imported helpers are not re-exported. The caller must still name
every helper in its own flat closure. Every source used for either independent
validation or final emission is captured and rechecked after compilation.
Sources are restricted to the explicit `src/`, `platform/` and `storage/` roots.
The separate migration inventory rejects any unaccounted HIA source, duplicate
owner, missing source or premature foundation-retirement claim.
Receipts bind every input, the composed assembly and the resulting Core. There
is no second copied SHA helper in the W1 or PoN source files.

### Original Rust differential

The first test adapter directly imports the retained `trnm-transport` and
`closed_round` modules. Four additional adapters link the unchanged original
`trnm-protocol`, `trnm-checkpoint-types`, `trnm-crypto-primitives` and
`trnm-mvcc-fee` crates with their locked dependencies. The State adapter calls
actual `serde_json::Value` construction/serialization and M06 root grammar.
The protocol adapter compares both PNX1 and the original
`state_root_from_entries` function. These adapters do not reimplement the
policies they compare.

```bash
rustc --edition=2021 -O hia/tests/rust_reference.rs -o /absolute/new/path/rust-reference
export TRNM_HIA_RUST_REFERENCE=/absolute/new/path/rust-reference
RUST_VALUE_TARGET=/absolute/new/path/rust-values
cargo build --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-protocol -p trnm-checkpoint-types -p trnm-crypto-primitives -p trnm-mvcc-fee \
  --target-dir "$RUST_VALUE_TARGET" --message-format=json > /absolute/new/path/rust-build.jsonl
rustc --edition=2021 -O hia/tests/rust_protocol_reference.rs \
  --extern trnm_protocol="$RUST_VALUE_TARGET/debug/libtrnm_protocol.rlib" \
  -L dependency="$RUST_VALUE_TARGET/debug/deps" -o /absolute/new/path/rust-protocol
rustc --edition=2021 -O hia/tests/rust_checkpoint_reference.rs \
  --extern trnm_checkpoint_types="$RUST_VALUE_TARGET/debug/libtrnm_checkpoint_types.rlib" \
  -L dependency="$RUST_VALUE_TARGET/debug/deps" -o /absolute/new/path/rust-checkpoint
rustc --edition=2021 -O hia/tests/rust_crypto_reference.rs \
  --extern trnm_crypto_primitives="$RUST_VALUE_TARGET/debug/libtrnm_crypto_primitives.rlib" \
  -L dependency="$RUST_VALUE_TARGET/debug/deps" -o /absolute/new/path/rust-crypto
export TRNM_HIA_RUST_PROTOCOL_REFERENCE=/absolute/new/path/rust-protocol
export TRNM_HIA_RUST_CHECKPOINT_REFERENCE=/absolute/new/path/rust-checkpoint
export TRNM_HIA_RUST_CRYPTO_REFERENCE=/absolute/new/path/rust-crypto
python3 - /absolute/new/path/rust-build.jsonl "$RUST_VALUE_TARGET" /absolute/new/path/rust-state <<'PYCODE'
import json, pathlib, subprocess, sys
rows = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
serde = [row for row in rows if row.get('reason') == 'compiler-artifact' and row['target']['name'] == 'serde_json']
assert len(serde) == 1 and serde[0]['package_id'].endswith('serde_json@1.0.149')
assert set(serde[0]['features']) == {'default', 'std'}
rlibs = [name for name in serde[0]['filenames'] if name.endswith('.rlib')]
assert len(rlibs) == 1
base = pathlib.Path(sys.argv[2]) / 'debug'
subprocess.run(['rustc', '--edition=2021', '-O', 'hia/tests/rust_state_reference.rs', '--extern', 'trnm_mvcc_fee=' + str(base / 'libtrnm_mvcc_fee.rlib'), '--extern', 'serde_json=' + rlibs[0], '-L', 'dependency=' + str(base / 'deps'), '-o', sys.argv[3]], check=True)
PYCODE
export TRNM_HIA_RUST_STATE_REFERENCE=/absolute/new/path/rust-state
python3 -B hia/tools/qualify.py --require-rust-oracle \
  --output /absolute/new/path/native-and-rust-results.json
```

Without a corresponding environment variable, the local report explicitly
records that original Rust differential as not run. CI requires all five, compiles the actual
original modules and preserves the exact head's observations. The fixed
`SourceOk` in the test fixture only exposes pure transport boundaries; source
authentication is an independent integration obligation.

## Transaction and checkpoint value contracts

`pnx1.hepta` accepts the exact existing `PNX1` signed wire, including its opaque
64-byte signature. It preserves outer Limit/Length/Version order, exact payload
length, the complete 24-tag dispatch, nested ILF errors, then nonce and fee checks.
Fixed payloads stay opaque wherever the original decoder only checks their size;
decoding does not introduce signature or account authority. Codes 0–4 are the
original wire results. Output remains unchanged. For tags 23/24, scratch must
hold the payload; code 100 reports insufficient scratch before mutation. The
validator copies exactly that payload prefix and uses explicit shared loans to
the common ILF routines. The remainder of scratch stays unchanged.

`checkpoint/value_v2.hepta` accepts a local request header
`CPV2, version:u8(1), operation:u8, reserved:u16(0)` followed by the original
record or fields. Operations 0–3 decode a 672-byte record, construct from its
624 field bytes, check a predecessor/target pair, and construct a 104-byte
watermark. All original integers and hash length prefixes use big-endian order.
The HIA code builds the original 713-byte domain-separated SHA input itself.
Success writes the canonical result and preserves output suffixes; all failure
paths preserve output. Hash operations require 132,256 scratch bytes. The
watermark-only operation requires no scratch. Codes 1–28 preserve original error
and field identity; 100–103 report local envelope or capacity errors. The complete
mapping and independent constructors are in [test_checkpoint.py](tests/test_checkpoint.py).
No store trait, durable CAS, external freshness or actual node root is certified
by successful value validation.

## W1 contracts

`encoding.hepta` has the original wire-only precheck order: length, version,
field words. Codes 0/1/2/3 mean success/Length/Version/Field.

`matrix.hepta` takes the local descriptor
`rows:u8, inner:u8, cols:u8, version:u8(1), A:u32LE[], B:u32LE[]`.
Dimensions are 1–64. Input/output extents must be exact and every word canonical.
Output is the row-major product modulo `Q = 2^32 - 5`. Failure leaves output
and scratch unchanged. This descriptor is not a blockchain wire schema.

`verify.hepta` takes 49,284 bytes:
`challenge[32] + expected_task[32] + target[32] + PNW1[49188]`.
Output must contain exactly 16,384 bytes; scratch must contain at least 259,232
bytes. It preserves the original full-verifier order, including zero-target
rejection before C/A/B field checks and transcript verification before product
comparison. Codes 1–8 are Length, Version, Field, Task, Transcript, Product,
Target and NoiseBudget. Code 9 is an internal SHA-contract refusal. Only complete
success writes the external product. Scratch is private working memory and may
change on a late refusal; bytes beyond its declared working extent stay intact.

For canonical operands, every product is below `2^64`. Reducing each product
before adding keeps each sum below `2Q`, so the native u64 path equals the
original wider-integer sum modulo Q. Denoising computes
`C' - AF - E(B+F) mod Q`; the independent test oracle computes `AB` directly.
The exact 32,768 transcript updates and their hash order are preserved.

This entry implements the complete deterministic relation with cancellation
disabled. Original progress callbacks, receiver cache/owner integration, resource
admission and the private `VerifiedWork` construction remain with the retained
runtime. These interfaces need their own HIA implementations and service tests.

## Sixth candidate integration evidence

The current source increment has separate local evidence and requires its own
exact committed CI. [Complete response observations](qualification/transport-response-observations.json)
record 11,420 passing native controls. The full response producer uses the
[private stack](platform/private_stack/README.md); a real seccomp-denied `munmap`
after signing caused exit 70 and zero stdout. Its 11 standalone controls retain
the actual bare signer erasure failure: scalar secret bytes remained in compiler
stack spill slots even after the explicit work arena was cleared. Guarded normal
returns wipe the complete 1 MiB private stack and unmap it. Neither this repair
nor conservative SSA analysis establishes whole-key custody or machine-code
constant-time behavior.

[Settings observations](qualification/settings-development.json) retain the
16 integrated tests and two rejected compiler attempts. The
[typed Delta caller](platform/node_delta/README.md) passed 8,551 controls,
including a 65,536-row State and a 131,072-key Delta union. Its typed tape
constructor finishes validation before the first progress call; physical stored
row materialization and cancellation remain separate owner obligations.

The response, Settings and Delta jobs require actual original Rust execution
(10,990 response comparisons plus six original tests, 30 Settings cases and
423 Delta cases). These were NOT_RUN locally because Rust is unavailable; the
workflow refuses to substitute a host-side reimplementation. Earlier CI below
qualifies only its recorded source set.

## Retained compiler qualification

[compiler-binding.json](qualification/compiler-binding.json) binds the original
full cold report and its losslessly compressed nested report. The original gate
ran with 180 seconds for qualification and 3 seconds for cleanup. It completed
in 154.807339324 seconds, with 916 source inputs, 11 outer checks, 5,049 nested
checks and 38 phases. The generated standalone ELF is byte-identical to the
compiler used for these Chain components. The reports preserve the target,
trusted dependencies and precise qualification scope.

The fifth repaired candidate `4cc0464ff9632f2a493cb76d5b8b51eaad332dac`
passed all three HIA jobs in [run 43751782144](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43751782144):
189 tests, 56,884 shared-runner native calls, no failures, errors or skips.
All five original Rust adapters actually executed. The [exact CI report](qualification/native-ci.json)
binds source set `fe94efedc30dba67e3c89cf95b17a7135d29f7b6dc9bd29ffa290dd519ba337c`;
its SHA-256 is `d665e6ac67d8613e89d62045dfcbaa497b2525df0114f3c22e8081eabb511400`.
Native artifact `14176927252` has ZIP SHA-256
`71191d0e6458d00c442b4effa29a4697f78deb7caf03f051228f8d17f2fe331a`.
The run also passed 25 finite OS controls, 49 reactor controls with 13 native
contracts, and 48 storage controls with 14 native entry contracts. Actual syscall
traces were captured. These finite results do not close whole-Node integration.

The [original executor report](qualification/executor-original-ci.json) records
5,274 actual original-Rust/native comparisons, with status
`PASS_WITH_EXPLICIT_ORIGINAL_SAFETY_DEFECT`. The unchanged original implementation
produced 131 unsafe schedules; all 181 intentional differences and 27 expected
version-skew panics remain explicit. The separate 122 differences in the earlier
source-derived model corpus remain labeled as model observations. The HIA
correction retains the maximum reader dependency and every native result must
satisfy the independent conflict graph. This executor belongs to the full
26-package repository scope and is outside the normal Node dependency closure.

The complete request job passed 178 native request controls, 14 incremental SHA
controls, 170 actual original-Node differential cases and six original tests.
Eight new owner-container cases are explicitly excluded from the Rust oracle.
The source job passed historical readers and all 113 PQ negative tests in
419.167 seconds. PQ remains `HOLD_NO_GO`. Neither source consistency nor a
request fixture's 30-second outer budget qualifies original service acceptance.
The earlier full 2 MiB submit and dense 69,878-query ConfirmMany observations
remain 5.171449401 and 6.773873071 seconds; their original service gates are open.

The fifth initial candidate passed its main 177-test suite but failed the later
executor adapter link with E0463 before original executor execution. The
[repair report](qualification/executor-original-linking-fix.json) retains the
actual Cargo JSON and failure. Dependency directories now come from that
successful invocation's library artifacts, and required externs must be unique.
Twelve controls and the exact repaired-head real Rust comparison verify the fix.
The prior storage CLI import failure and three missing retained stderr logs
remain in [development observations](qualification/development-observations.json).
None of these repairs changed original algorithm sources, corpus or service budgets.

All sixth-batch sources have distinct local source bindings. The exact published
fifth-head CI results above do not qualify these later edits. Their original Rust
and owner-integration results remain separately reported until actually executed.

## Tree cleanup and remaining integration

607 obsolete checkout-repair files were removed from the active tree. Their
128,438,729 original bytes remain addressable by the baseline Git objects and
the [archive index](../evidence/pon-learning-outcome-composition-20261111/CHECKOUT_VISIBILITY_ARCHIVE.json).
The original failure summaries and qualification are unchanged. The archive
checker validates every original object and can return an indexed original
without executing its historical helper scripts.

A further 14 historical CI ZIPs (275,505,994 bytes) are indexed in the
[sealed archive](../evidence/pon-business-gates-819309-final-20261107/ci-819/ORIGINAL_ZIP_ARCHIVE.json).
Its reader preserves and validates all 810 original checksum entries, the
original seal and all HOLD/FAIL counts. Both cleanup sets remove 621 current-tree
copies totaling 403,944,723 original bytes; metadata and validation additions
make the net reduction smaller.

The [joint-resource index](../evidence/pon-joint-resource-contract-20261109/ORIGINAL_ARCHIVE_INDEX.json)
removes another 13 archive copies (125,934,468 bytes), while checking all 74
original checksums and the complete original archive-member denominator.
The [PQ triage index](../evidence/pq-authority-preflight-20261108-9d315/NATIVE_TRIAGE_ARCHIVE.json)
removes four large streams (189,121,668 bytes) from one historical capture and
retains its other 29 records byte-for-byte. Its checker verifies every one of
1,050 original stored hashes, 147 gzip bindings and 543 followup bindings.
The [public-readiness index](../evidence/pon-public-readiness-v1/PRE_CORRECTION_ARCHIVE.json)
removes 885 pre-correction payloads (413,594,755 bytes). Its reader reconstructs
the exact historical view and executes the original checker against its actual
measured source, verifying all 1,334 manifest entries, 793 source SHA-256 values
and 2,588 original source blobs. Current and historical tracking are checked;
no network retrieval substitutes for missing objects. [The retained observation](qualification/public-readiness-cleanup.json)
records the successful original semantic gate without promoting historical
engineering results to current native or public readiness.
The [hosted-cost archive](../evidence/pon-work-security-eight-samples-20261101/HOSTED_COST_ARCHIVE.json)
removes 32 more containers/shards (180,351,232 bytes), preserving five small
records byte-for-byte. Its private exact 210-file historical view executes the
original verifier: all 208 top-level entries, 12 archives, 32 parts and 808 members
(3,762,781,104 uncompressed bytes) are read and verified. Sixteen negative tests
include the real missing-index and dangling-symlink CLI paths. A prepublication
fallback bug that could overwrite a copied historical receipt was reproduced and
fixed by unconditional read-only dispatch; the retained repository receipt was
unchanged. [The observation](qualification/hosted-cost-cleanup.json) preserves
that failure and the final complete PASS. Original ZIP bytes and current native
work/service acceptance are not inferred from this historical byte verification.
The [D26 SQLite archive](../evidence/pon-business-gates-readback-20261107/D26_SQLITE_ARCHIVE.json)
removes eight compressed snapshots (176,597,049 bytes). Its reader checks the
complete 617-file original package, all 614 prepared files, 232 gzip streams and
their 1,992,917,425 decoded bytes, the exact preparation plan and original seal.
All 609 other original files remain unchanged. This is byte preservation;
neither SQLite nor the historical Node is started by the reader.
The [W1 complete-work archive](../evidence/pon-w1-complete-work-20261101/W1_COMPLETE_ARCHIVE.json)
removes 59 containers (138,750,512 bytes) and retains 91 small records with their
exact original blobs, including ten explicitly tracked logs. Its private
172-file original view executes the unchanged verifier over all 170 FILE_INDEX
entries, 171 SHA256SUMS entries and 60 archives containing 4,960 members
(4,463,919,709 decoded bytes). The root validation archive remains. The original
and archived views produce the same original observation; 15 negative controls
include an actual original-verifier member failure and missing-index CLI cases.
The [D26](qualification/d26-sqlite-cleanup.json) and
[W1](qualification/w1-complete-cleanup.json) reports retain all failure/HOLD
observations and the independent integration replays.
All eight sets remove **1,622 payload copies / 1,628,294,407 original bytes**;
new metadata, code and retained receipts make the net tree reduction smaller.
No original startup UNKNOWN, failure, or qualification HOLD is rewritten.

```bash
python3 scripts/ci/check_historical_archive.py --manifest \
  evidence/pon-learning-outcome-composition-20261111/CHECKOUT_VISIBILITY_ARCHIVE.json
python3 hia/tools/check_migration.py
```

The pinned HIA Core has a closed opcode/effect set and internal calls. Its
standard selfhost executable provides bounded stdin/stdout, mmap and exit.
Hepta's artifact publisher and release installer have real openat/fsync/rename
adapters, authored as fixed ISA and packed into native ELF; those specialized
adapters do not expose a general node filesystem/network/transaction API.
The locked [opcode catalog](https://github.com/TrillionniumFoundation/Hepta/blob/f33d8da316de8fdf27b504371f1a5310997ff548/hepta/hia_opcodes.py),
[support declaration](https://github.com/TrillionniumFoundation/Hepta/blob/f33d8da316de8fdf27b504371f1a5310997ff548/docs/HIA_SELFHOST_CORE_SUPPORT.json),
and [artifact publication boundary](https://github.com/TrillionniumFoundation/Hepta/blob/f33d8da316de8fdf27b504371f1a5310997ff548/docs/HIA_ARTIFACT_PUBLICATION_NATIVE.md)
define that distinction. The compiler cold gate did not execute every specialized
file application gate and gives no socket, SQLite or node-lifecycle guarantee.

The eight native foundations have separate contracts and qualification:

| Foundation | Native behavior | Remaining integration |
| --- | --- | --- |
| [Linux OS fixture](platform/README.md) | Real file publication, fsync, loopback TCP, epoll, clock and random operations through an HIA-emitted adapter | Finite fixture; its blocking-call deadline failure remains |
| [Stream reactor](platform/reactor/README.md) | Connected FIFO/stream capabilities, generations, readiness, absolute deadline, partial-progress cursors and cancellation with explicit caller entrypoints | Node framing, admission, ownership and full transport integration; regular-file/fsync deadlines are outside its admitted descriptor class |
| [Transaction owner](storage/README.md) | Fresh-v2 private directory FD, lock, immutable hash-linked transactions, atomic HEAD, fsync and streamed exact readback through the complete original State byte extent | Typed Node reducers, replay/outbox/reorg, original initialization recovery, external anti-rollback witness and service qualification |
| [Request qualification caller](platform/transport_request/README.md) | Native framing and incremental-hash fixture around the complete classical request kernel | Private Settings/session owner, socket/reactor connection, replay/outbox, signing-key custody and PQ |
| [Typed Delta](platform/node_delta/README.md) | Complete typed collection, exact Option/byte comparisons, ordered writes and original progress/error sequencing | Real stored-row decoding, transaction authority, durable Node commit and peer ACK |
| [Private stack](platform/private_stack/README.md) | Two guard pages, dedicated native call stack, full ordinary-return wipe, unmap and explicit cleanup failure | Caller seed lifetime, asynchronous termination, complete key owner and machine-code timing proof |
| [Response qualification caller](platform/transport_response/README.md) | Variable-length output, redzones, complete signed response and actual cleanup-error publication refusal | Private connection, replay commit and terminal response authority |
| [Fresh Host checkpoint](platform/host_checkpoint/README.md) | Actual fixed-parent acquisition and fresh boot, calling-thread, identity and five-limit checks, with bounded read-only syscall profiles | Production positive, resource sampling, same-worker embedding and original service qualification |

The reactor and transaction owner are actual native implementations generated
through the pinned HIA compiler. The literal ISA adapters remain separately
trusted boundaries; Core verifies their HIA emitters rather than proving every
emitted syscall effect. Hosted builders and independent test oracles are
explicitly retained. The fresh-v2 storage format removes the former 16 MiB and
4,096-commit limits. It checks the actual signed file-offset bound and refuses
sequence exhaustion. The 52 physical controls include a 279,445,512-byte State
extent with commit/close/reopen/full readback and 4,105 real retained commits;
170 function controls and two fresh CLI starts also passed. The parent rebuild
produced the exact same ELF as that physical run. These observations do not
qualify typed State grammar, original service latency or physical power loss.
The initial slow capacity run remains FAIL; shared native compression passed
under the same 180-second test controller. Its current local syscall trace is
UNKNOWN because ptrace was denied. A missing COMMIT ACK never proves rollback: the
caller must reopen and compare HEAD, including after a durable commit whose
ACK encountered EPIPE.

```bash
python3 -B hia/tools/qualify_platform.py --reactor --output /absolute/new/path/reactor-results
python3 -B hia/tools/qualify_storage.py --output /absolute/new/path/storage-results
```

The next integration obligations are general system I/O and capabilities,
durable storage/recovery, complete PQ identity and transport, whole node/model
flows, the original service budget, cross-target coverage and the existing
consensus research obligations. `check_migration.py --require-retirement`
currently refuses retirement of all 26 legacy packages. That result records the
actual migration state and prevents cleanup from hiding missing behavior.
