# HIA native implementation

This directory contains the HIA migration of Trillionnium-Chain. Its target is
one complete HIA-native implementation. The current candidate contains **27
kernel units and four native foundations**, accounting for all **36 HIA source
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
wire parsing, integer work, hashing, replay and evaluator decisions. Existing
service, model-use, consensus-security and cross-architecture failures retain
their original status. Rewriting a deterministic function does not establish a
new proof of work hardness or satisfy an unexecuted service campaign.

## Implemented native components

| Source | Implemented behavior | Native tests |
| --- | --- | --- |
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

[components.json](components.json) explicitly selects five functions from the
single `sha256_arena.hepta` source for the PoN hash, W1, checkpoint, state-root
and storage-owner components.
PNX1 explicitly includes the shared ILF2/ILF3 validators and coefficient scans. Their
entry files therefore require package composition before admission. The driver
checks each included source, joins only the named HIA functions and submits the
complete program to the official Core verifier and native compiler. It refuses
unknown names, duplicate symbols, traversal, symlinks and recursive includes.
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

The fourth repaired candidate `96a0846e383745f88e033c7db2abc0611f1dae63`
passed both jobs in [run 43746877132](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43746877132):
160 tests, 36,222 shared-runner native calls, no failures, errors or skips.
All four then-existing original Rust adapters and 17 original unit tests ran.
The [exact CI report](qualification/native-ci.json) binds source set
`b4a657cc76c97a022ae31742c98ad573a45b94edb8fea00c36b527891c708d3b`;
its SHA-256 is `adcef71fe36e416df0f467adb01679f0a2d1e567bd49e07f12ae03051d9d9214`.
Artifact `14175470420` has ZIP SHA-256
`8a851c22165189224c00b00fea2fa7ee8279323ef6de26d56712dc0a96d9fb03`.
That run also passed 25 finite OS controls, 49 reactor controls with 13 native
contracts, and 48 storage controls with 14 native entry contracts. Actual syscall
traces were captured. The separate state-root maximum-count child made 86 raw
ABI calls, outside the shared-runner count. The source job passed the original
historical readers and all 113 PQ negative tests in 546.161 seconds.

The earlier fourth candidate failed at the direct storage script import before
storage, Rust or kernel execution. Both CLI entrypoints now bind their repository
root and are tested from a fresh directory without ambient Python path variables.
The third candidate's three ignored stderr logs and the fixed import failure
remain recorded in [development observations](qualification/development-observations.json).
Neither repair altered the native storage ELF or an original service budget.

The current scheduler, String/Value and authenticated-request additions are
later sources. Their local reports explicitly mark original Rust execution as
NOT_RUN. CI now requires five shared-suite original Rust adapters, a separate
real executor comparison, and a separate complete-request/original-Node job.
The request's 30-second outer test budget does not qualify the original request
read deadline or service response budget. Full 2 MiB submit and dense 69,878-query
ConfirmMany took 5.171449401 and 6.773873071 seconds locally.

The scheduler's source-derived old model can place a later reader and writer in
one conflicting group because it overwrites a higher reader dependency with a
lower group. HIA retains the maximum dependency. The report preserves 122
intentional old-model differences and requires every native result to satisfy an
independent conflict graph. The unchanged original Rust library is the mandatory
CI oracle; source analysis alone is not described as an executed Rust failure.
This executor belongs to the full 26-package repository scope and is outside the
normal Node dependency closure.

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
All six sets remove **1,555 payload copies / 1,312,946,846 original bytes**;
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

The four native foundations have separate contracts and qualification:

| Foundation | Native behavior | Remaining integration |
| --- | --- | --- |
| [Linux OS fixture](platform/README.md) | Real file publication, fsync, loopback TCP, epoll, clock and random operations through an HIA-emitted adapter | Finite fixture; its blocking-call deadline failure remains |
| [Stream reactor](platform/reactor/README.md) | Connected FIFO/stream capabilities, generations, readiness, absolute deadline, partial-progress cursors and cancellation with explicit caller entrypoints | Node framing, admission, ownership and full transport integration; regular-file/fsync deadlines are outside its admitted descriptor class |
| [Transaction owner](storage/README.md) | Private directory FD, process lock, immutable hash-linked transactions, atomic HEAD, fsync, reopen validation and exact payload readback | Typed Node reducers, replay/outbox/reorg, original initialization recovery, external anti-rollback witness, complete payload/lifetime limits and service qualification |
| [Request qualification caller](platform/transport_request/README.md) | Native framing and incremental-hash fixture around the complete classical request kernel | Private Settings/session owner, socket/reactor connection, replay/outbox, response codec, signing-key custody and PQ |

The reactor and transaction owner are actual native implementations generated
through the pinned HIA compiler. The literal ISA adapters remain separately
trusted boundaries; Core verifies their HIA emitters rather than proving every
emitted syscall effect. Hosted builders and independent test oracles are
explicitly retained. The storage profile currently accepts 16 MiB per atomic
payload and 4,096 retained commits; those bounds do not cover the original full
State or a long-lived node. A missing COMMIT ACK never proves rollback: the
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
