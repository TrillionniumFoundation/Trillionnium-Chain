# HIA native implementation

This is the in-progress native HIA replacement of Trillionnium-Chain. The current
inventory contains **41 kernel units, 20 native foundations and 119 HIA source
files**. Each component has one implementation directory. All 26 original Rust
packages remain, zero package retirements are accepted, and all nine whole-project
gates remain OPEN.

The [sole development plan](../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
sets the complete migration sequence. The [migration inventory](../config/hia-migration-v1.json)
accounts for every old package and new HIA source.
[The audit](AUDIT.md) retains source-specific findings, failures and remaining obligations.

## Current source and qualification

Published parent
[`876eb577dac61854c535a91ab1480f312d1d6173`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/876eb577dac61854c535a91ab1480f312d1d6173)
completed all **33 HIA jobs** in
[run 44000856130](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44000856130).
Its complete Application and Work/Host artifacts were independently reopened.
The current integration adds nine Batch/Prefix jobs and repairs M05 evidence
admission. It requires fresh execution on its own committed source.

| Owner | Actual source-specific results | Remaining boundary |
| --- | --- | --- |
| [Batch and TransactionPrefix](platform/execution_batch/README.md) | Frozen 146-input source: 102 Batch methods / 2,133 progress records; 186 Prefix histories / 936 executed methods / 4,419 progress records; 30 physical controls and six scoped lifecycles / 69 methods. Actual original: 102 Batch methods plus nine retained tests and 186 Prefix histories plus six retained tests. | Default Config, AccountPointAccess=None and workers 1/2/4/8 only. Custom Config, PQ/growth, Paid/Host lifetime, authenticated Node, durable COMMIT and original service acceptance remain open. |
| [Typed M05](platform/mempool_typed/README.md) | Repaired 26-input source: 323 native processes / 9,332 commands and actual original comparison / 153 retained tests; 38 physical processes, 26 guarded calls, 21 source controls, five byte and 12 coherent-witness refusals / 22 actual public CLI calls. | Signature/replay/nonce traits are fixture adapters. Production PNX/signature/State adapters, persistent pool, Node lifetime and original service acceptance remain open. |
| [Default M06 Application](platform/execution_application/README.md) | Exact 876: 328 native and original histories, 335 transactions, 8,784 State commands, nine native processes, 32 physical controls, 186 integrity controls, 16 CLI refusals and eight retained original tests. | The integrated original graph changed. All configurations/PQ, authenticated block acceptance, expected-root checks and durable Node COMMIT remain open. |
| [Same-worker Work/Host](platform/work_owner/README.md) | Exact 876: 61 native histories / 27,843 progress records; 175 primitive controls, three traces, 27 trace controls, 14 signal controls and 18 native CLOCK1 faults. Actual original: 57 histories / 27,841 progress records, 56 joined workers and 44 retained tests. | Those 175 historical controls lack full raw guard arenas. Original CLOCK1 faults, production fixed-parent authority, shared Paid account/request deadline and original service acceptance remain open. |

The Prefix corpus declares 1,011 fixture methods; **936 actually ran** and
75 were unexecuted paths after the observed fixture outcome. Those 75 are not
passed methods or skipped original tests. The observed 256-transaction Batch
case took 24.3928 seconds and the largest Prefix history took 140.676 seconds.
These development results do not satisfy the original four-second service gate.

### Exact source transitions

| Source graph | Frozen execution identity | Integrated identity and obligation |
| --- | --- | --- |
| Batch native | 146 inputs, `408d35eec10d0818ebbde4639459753c270ec7e7445156c59d4178418aa6681d` | 151 inputs, `63576c082aa16d4768ab0bc461eb604ded5905e77334b4e0655123a592e7849f`; all 60 composed runtime inputs are byte-identical, but the complete graph needs fresh CI. |
| M05 native | Old 876: `7461a680b29d4d36a7a8b9770281eb9ead681fe7d29f4cb48a8d051592c4724b` | Repaired and locally reexecuted: `455c7e43897744cc6f22cf88f859f6f0e96d8bd6d4836e4aee379ba97b65fef7`; fresh hosted qualification remains required. |
| Application native | 109 inputs, `b4f1121ba5545bbdf1fccc317e9bc8be21918b1215a83518cfb7be411432bb70` | Native inputs unchanged; inventory and sole-plan pin change the original graph. |
| Work/Host native | 126 inputs, `e56d53654a6168df96cddf23c5f079f2a0ea188d45dd55d9f15f71015c823a91` | Native inputs unchanged; the original graph requires fresh committed-source execution. |

The M05 audit reproduced four false accepts against the actual old public CLI:
integer zero replaced by boolean false in scalar and nested observations, an
integer callback count replaced by a float, and an observation index replaced
by a boolean. Altered original stdout, receipt and summary stayed mutually
consistent. Recursive strict type checks now reject all four; full native,
actual original and public-control qualification reran on the repaired source.
Three additional float count substitutions were reproduced and refused at the
CI summary helper. Those helper checks are not public CLI executions.

The [M05 record](qualification/mempool-typed-development.json),
[Batch record](qualification/execution-batch-development.json),
[Application development record](qualification/execution-application-development.json),
[exact 876 Application record](qualification/execution-application-ci.json),
[Work/Host development record](qualification/work-owner-development.json) and
[exact 876 Work/Host record](qualification/work-owner-ci.json) retain separate
source maps and evidence scopes.

## CI and retained evidence

The integrated workflow has **42 jobs and 35 independent native bootstrap gates**.
Seven new Batch native jobs require explicit transport-test scope; the two
actual-original jobs require full original-test scope. Missing or conflicting
scope arguments are refused. Actual local suites passed six transport groups /
70 controls and, for each original profile, nine groups / 102 controls. Every
scope recorded zero skipped tests. Original 20-minute job limits and
240-second process / three-second cleanup bounds remain.

Integration checks passed all 89 existing CI/evidence tests, six transport
groups, 173 Batch source-integrity controls / 18 CLI calls and four bootstrap
guard groups. The [CI development record](qualification/application-mempool-ci-development.json)
keeps those checks separate from runtime execution and hosted qualification.

The [archive manifests and restoration instructions](qualification/ARCHIVES.md)
describe five final volume sets. Every member was reopened, every part hashed
and every archive physically reconstructed. Application CI preserves complete
c61 and 876 ZIPs. Work/Host CI preserves complete producer/consumer ZIPs,
including the 611,199,752-byte original executable. Batch's two original
executables remain separately preserved with explicit identities and locations;
they are not embedded archive members.

Failed executions, unknown outcomes and original source identities remain
evidence. Archive verification does not execute a runtime again or qualify a
later commit.

## Foundations and whole-project gates

Earlier owners have separate contracts and records:
[OS](platform/README.md), [reactor](platform/reactor/README.md),
[transactions](storage/README.md), [requests](platform/transport_request/README.md),
[Delta](platform/node_delta/README.md), [private stacks](platform/private_stack/README.md),
[responses](platform/transport_response/README.md),
[Host checks](platform/host_checkpoint/README.md), [typed staging](platform/typed_store/README.md),
[Host resources](platform/host_resource/README.md),
[continuity](platform/continuity_store/README.md),
[Thread CPU](platform/thread_cpu/README.md), [Genesis](platform/genesis_store/README.md),
[Paid CPU](platform/paid_cpu/README.md), [State](platform/execution_state/README.md)
and [private Prepare](platform/execution_prepare/README.md).
The native syscall emitters and compiler are explicit trusted boundaries.
Core admission alone does not prove every emitted system-call effect.

| Whole-project gate | Outstanding acceptance |
| --- | --- |
| System I/O | Full filesystem, network, process and capability ownership in the actual Node. |
| Persistent Node | One durable transaction owner, original SQLite semantics, crash cuts, rollback floor and reorganization. |
| Cryptography | Complete PQ signatures, authenticated identity/TLS and every signature domain. |
| Node integration | Full transaction/application/mempool lifecycle, cancellation and private authority. |
| Service budget | Original 0.25 CPU, 2 GiB, zero swap, 256 PIDs, four-second and 16-attacker acceptance. |
| Cross-target | Original architectures/operating systems and exact artifact qualification. |
| Model loop | Actual train, independent evaluation, Adopt/NoUpdate, subsequent task and cold recovery. |
| Consensus research | Original work cost, public consensus, STARK/QROM and economic obligations. |
| Retirement | Complete equivalent replacement of all 26 packages and indispensable tools. |

Original service and history failures remain in the
[whole-project findings](qualification/whole-project-ci-findings.json),
[326 diagnosis](qualification/ci-326-observed-failures.json) and
[protocol supplement](qualification/ci-326-protocol-contract-failures.json).
A successful HIA workflow does not close those gates.

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

## Implemented native components

The [M05 native lane owner](src/mempool/OWNER.md) now retains both physical
FIFO rings, exact ID membership and fairness across calls in one private
allocation. Its local native controls passed 41,365 owner calls and 2,042
canonical-policy regression calls. A separate real Rust compiler built the
complete unchanged original mempool crate and matched all 41,248 public
operations across 1,862 histories. The exact hosted test additionally compares
original Rust and native replies directly and cannot skip a missing oracle.
The [bound development record](qualification/mempool-owner-development.json)
retains both observations. Typed signed fixture admission is covered above; production signature/State adapters,
persistent local-pool handoff and Node integration remain open.

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

## Retained compiler qualification

[compiler-binding.json](qualification/compiler-binding.json) binds the original
full cold report and its losslessly compressed nested report. The original gate
ran with 180 seconds for qualification and 3 seconds for cleanup. It completed
in 154.807339324 seconds, with 916 source inputs, 11 outer checks, 5,049 nested
checks and 38 phases. The generated standalone ELF is byte-identical to the
compiler used for these Chain components. The reports preserve the target,
trusted dependencies and precise qualification scope.

## Repository consolidation

The historical cleanup index records 1,622 redundant payload copies and
1,628,294,407 original bytes removed from the active tree. Original Git blobs,
source-bound archive readers, failed observations and qualification limits remain.
Current HIA components have one final implementation tree; authoring trees
and intermediate builds remain external.

Run the source inventory and complete retirement gate separately:

```bash
python3 -B hia/tools/check_migration.py
python3 -B hia/tools/check_migration.py --require-retirement
```

The retirement command currently refuses all 26 retained packages. The audit
trail and historical source-specific observations remain in [AUDIT.md](AUDIT.md)
and the [sole development plan](../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The [published 876 overview](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/876eb577dac61854c535a91ab1480f312d1d6173/hia/README.md)
preserves the previous complete narrative.
