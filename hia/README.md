# HIA native implementation

This directory contains the HIA migration of Trillionnium-Chain. Its target is
one complete HIA-native implementation. The current candidate contains **15
native source units**; the 26 existing Rust packages remain until their complete
replacement is qualified. The authoritative sequence remains the
[repository development plan](../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
[The migration inventory](../config/hia-migration-v1.json) accounts for every
original package and every new HIA source file.

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
| [SHA-256](src/crypto/sha256.hepta) | Hash inputs through 1 MiB | Known vectors, `hashlib`, padding, real unaligned pointers and canaries |
| [SHA arena](src/crypto/sha256_arena.hepta) | One shared mutable arena for W1 hash input/output/work | Exact ranges, maximum length and no-write refusal |
| [PoN hash](src/crypto/pon_hash.hepta) | Original tag and per-part length framing | Original wire oracle, task/noise/header domains and ambiguous concatenations |
| [W1 encoding](src/work/encoding.hepta) | Fixed PNW1 size, magic and all canonical field words | All matrix rows and boundary words |
| [W1 field](src/work/field.hepta), [matrix](src/work/matrix.hepta) | Exact modular multiplication, addition, denoising and bounded matrices | Independent arbitrary-precision arithmetic, maximum values and dense products |
| [W1 verification](src/work/verify.hepta) | Complete deterministic non-cancelling PNW1 relation | Independent scalar transcript and direct `AB` product, target/trace/product attacks |
| [Replay](src/transport/replay.hepta) | Session/nonce/pending checks, ACK and pure successor proposals | Two native backends, original boundary vectors and Rust-reference CI |
| [Closed round](src/verification/closed_round.hepta) | Exact evaluator policy over canonical UTF-8 containers | Full-width scores, all arrival orders, Unicode, 1 MiB and Rust-reference CI |

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
single `sha256_arena.hepta` source for the PoN hash and W1 components. Their
entry files therefore require package composition before admission. The driver
checks each included source, joins only the named HIA functions and submits the
complete program to the official Core verifier and native compiler. It refuses
unknown names, duplicate symbols, traversal, symlinks and recursive includes.
Receipts bind every input, the composed assembly and the resulting Core. There
is no second copied SHA helper in the W1 or PoN source files.

### Original Rust differential

The test adapter directly imports the retained `trnm-transport` and
`closed_round` modules. It does not reimplement their policies.

```bash
rustc --edition=2021 -O hia/tests/rust_reference.rs -o /absolute/new/path/rust-reference
export TRNM_HIA_RUST_REFERENCE=/absolute/new/path/rust-reference
python3 -B hia/tools/qualify.py --require-rust-oracle \
  --output /absolute/new/path/native-and-rust-results.json
```

Without that environment variable, the local report explicitly records that
the original Rust differential was not run. CI requires it, compiles the actual
original modules and preserves the exact head's observations. The fixed
`SourceOk` in the test fixture only exposes pure transport boundaries; source
authentication is an independent integration obligation.

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

## Tree cleanup and remaining integration

607 obsolete checkout-repair files were removed from the active tree. Their
128,438,729 original bytes remain addressable by the baseline Git objects and
the [archive index](../evidence/pon-learning-outcome-composition-20261111/CHECKOUT_VISIBILITY_ARCHIVE.json).
The original failure summaries and qualification are unchanged. The archive
checker validates every original object and can return an indexed original
without executing its historical helper scripts.

```bash
python3 scripts/ci/check_historical_archive.py --manifest \
  evidence/pon-learning-outcome-composition-20261111/CHECKOUT_VISIBILITY_ARCHIVE.json
python3 hia/tools/check_migration.py
```

The next integration obligations are general system I/O and capabilities,
durable storage/recovery, complete PQ identity and transport, whole node/model
flows, the original service budget, cross-target coverage and the existing
consensus research obligations. `check_migration.py --require-retirement`
currently refuses retirement of all 26 legacy packages. That result records the
actual migration state and prevents cleanup from hiding missing behavior.
