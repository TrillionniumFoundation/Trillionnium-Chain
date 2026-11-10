# Current-source W1 mapping V2

Status: **HOLD**. This is an explicit source-compatibility continuation under the
sole [development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It does not replace the historical implementation contract, its test roster,
its failed workflow results or its unknown cryptographic obligations.

## Reviewed source change

The current reviewed source is Chain
`39336622c63df1ae746d83a76bb53202cd01ba17`. The preceding dependency mapping
reviewed `189b9b5959d836ef6ae96e14fb285948e4920aa9`; its observations remain
historical. The retained V1 implementation contract is based on
`cb114b13bf848a77634e40a08b31b30c7c758e7b`.
Comparing its entire project-file roster with the current source gives two
changed files:

| File | Historical bytes | Current bytes | Reviewed difference |
| --- | ---: | ---: | --- |
| `formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs` | 9,233 | 11,172 | Adds the explicit `--native-once` command and dispatch branch. It performs one native replay with an independently supplied header. Existing receipt-verification dispatch is retained. |
| `trillionnium/crates/trnm-protocol/src/pon_wire.rs` | 32,354 | 32,654 | Adds exact funded-service reservation and decision decoding for additional forms of tags 2 and 5. The previously accepted fixed-length forms retain their branches. |

Changing those two source pins alone would leave new local dependencies outside
the selected mapping. The new contract therefore fixes all Rust source files
under the six reachable local path crates, their manifests and existing lock
files, workspace inputs and eight literal include materials. This includes
`funded_service_task_v1.rs`, the state-root arithmetic module, the remaining
protocol modules, the crypto crate and the relation/guest/verifier sources.
The preceding current-source mapping, at
`e8e2fcb8d811638eb5fa757d28590fbe8e408e61`, recorded 134 files. Relative to #827,
that combined #824/#825/#827 source
also changes the grouped factored-producer library and its example. Their
reviewed additions implement exact B(Ax) preparation/execution and a separate
example selector; they do not change or call W1. The remaining 132 closure
files were byte-identical to #827, including manifests, locks and include inputs.

The earlier #835/#836/#837 integration recorded **137** files, bound by exact blobs
from commit `44e96b1a841a50613d0b93484c5e576caec9f81f`, tree
`c297ebb14fcbeeb5f8acf13b3143a66b8b3b6db8`. Of the preceding 134 files, only
`trillionnium/Cargo.lock` and `trnm-crypto-primitives/src/lib.rs` change: the lock
retains both the storage `getrandom` and optional release OpenSSL dependency
edges, while the crypto export adds the independent root module. Three files
are newly inventoried: `trnm-crypto-primitives/src/pq_root_v3.rs`, its
`src/pq_root_v3/tests.rs`, and `tests/pq_root_v3_native.rs`. All 16 selected
project files, saved proof materials, helper scripts, upstream snapshot,
proof parameters and 15 unresolved obligations remain byte-identical to the
prior current mapping. No root native test or new proof execution is implied.

The preceding integration contract SHA-256 was
`e2c5377ac02c0ed47e7f69125fbcabe61072d42597b3208264abaa5be2961c78`.
Its pre-update checker refused the changed lockfile; that failure remains
retained. Ten missing tracked evidence inputs, totaling 1,430,534 bytes, were
materialized individually from the frozen commit and checked against both Git
blob and index identities. No original fixture bytes were changed.

The dependency-security continuation binds the same 137-file roster to
commit `189b9b5959d836ef6ae96e14fb285948e4920aa9`, tree
`35c9394cc41d4c8c5e555ba421311f0d5c1b1126`. Only `trillionnium/Cargo.lock`
changes within that local closure: the reviewed graph selects bundled
`rusqlite 0.41.0` / `libsqlite3-sys 0.39.0` and their required
hashlink/hashbrown resolution. The 16 selected project inputs, saved proof
materials, historical V1 reader/contract, helpers, proof parameters and all 15
unresolved obligations retain their exact bytes. The other upgraded application
manifests and locks are outside this selected mapping and require their own
complete dependency and native checks.

That dependency continuation used contract SHA-256
`846efa5cedfb811ae8255a5b3d5c0223e6e89180a89c9670e7bcb9204cbbed30`.

The 2026-11-10 continuation preserves all **137** existing closure records and
adds exactly `trnm-crypto-primitives/examples/pon_from_zero_filter_cost_v1.rs`,
for **138** inputs. Its 15,343 bytes have SHA-256
`78665546a09da49bc100da9357743781eae282379a6eae40f0e286d7cbbc8cde`,
read from source `39336622c63df1ae746d83a76bb53202cd01ba17`, tree
`42fbd7d5a7f00b75000cb4aa242e578a8f941d59`. The example measures finite existing
native PNW1 components. It does not change the selected RISC Zero proof relation.
All 16 selected project records, saved proof materials, helper scripts, historical
reader/contract, parameters, eight literal includes and 15 unresolved obligations
retain their bytes. The original 14 control methods remain; their existing
closure-count assertion now includes the added example.

The 138-input count retains the original crate-root and literal-data inventory
scope. This reader does not enumerate Rust `#[path]` imports outside those roots.
The new example, like the older expensive-verifier example, imports
`trnm-pon-node/examples/support/w1_from_zero.rs`; that helper remains outside this
selected inventory. The separate native experiment guards the whole tracked
source. This mapping does not establish a complete Rust include/build graph.

The actual pre-update current reader on evidence child
`42d6ab45598cbba3d476a3c558b7fce562f13877` exited 2 with
`local Rust source inventory differs`. Retain that failure independently of the
historical V1 refusal. The active current contract SHA-256 is now
`272275f202b896b74b7f7499695fa3f50b28a36465806c60b8c369e2e76db5b9`.
This source rebinding supplies no native execution or new security conclusion.
Native observations on `39336622` retain that identity; the binding successor
requires its own consistency checks and inherits no execution qualification.

The current checker verifies the local Cargo path graph,
exact Rust-file inventory, literal include set and declared absence of build
inputs. Newly added Rust files or previously absent build scripts require an
explicit review and new contract; they are not silently included.

The two entry manifests are the V2 verifier and the V2 guest. This source
inventory includes local test sources and their literal fixtures. It is not
a claim that those tests ran, that every source is reachable in a production
build, or that registry dependencies and toolchain inputs are completely
reviewed. Existing Cargo locks remain byte-pinned, but this reader does not
run Cargo or recompute its complete resolution graph.

## Separate entry and preserved historical result

The explicit contract is
[w1-qrom-implementation-current-v2.json](../../config/pon/w1-qrom-implementation-current-v2.json).
Run:

```sh
python3 scripts/ci/test_w1_qrom_current_implementation_audit.py
python3 scripts/w1_qrom_current_implementation_audit.py --repo-root . --output /absolute/new-current-map.json
```

The output file is create-only. A previous receipt is never overwritten.
The original V1 contract, original implementation reader and original workflow
remain unchanged. The new reader first verifies their byte identities and
retains the expected V1 source-contract refusal. It then uses the retained
pure mapping functions with the separately pinned current inputs. It does not
rewrite old constants, weaken old checks or claim that the historical named
roster or workflow passed.

The new mapping reaches the same saved V2 fixture, independently reconstructed
control root, image constant, parameter digest, locked selected packages and
FRI transcript. Actual local source files and the local path graph are checked
before and after mapping. Source fingerprints describe consistency with a
reviewed inventory. They do not authenticate the executor or establish Git
ancestry, whole-checkout atomicity, third-party implementation review, the
loaded native executable or a provider build.

## Interpretation

Successful execution emits
`CURRENT_MAPPING_REPRODUCED_SECURITY_HOLD`. All existing qualification flags
remain false; security bits and lifetime budgets remain null/unadopted. Every
existing proof obligation remains unresolved. A saved-artifact metadata mapping
does not generate a new proof or perform fresh cryptographic verification.
This continuation does not establish a QROM theorem, extraction/state-restoration
assumptions, recursive soundness, whole-chain composition, quantum work cost,
DAA security, positive honest service or production admission.

The first development execution used a minimal, explicit input projection of
the reviewed source after an attempted full worktree checkout failed from
ENOSPC. The complete original checkout was not edited. Git automatically
removed the incomplete new worktree. The reader and 14 controls passed first on the #827 projection and were
rerun on the explicitly reviewed combined-source projection; those results are source/mapping observations only. The combined-source projection was moved to a task-owned in-memory filesystem
after a further ENOSPC refusal. This is not an independent executor. No native Rust
test or new native executable was produced by this continuation. Applying the
patch to another combined candidate requires checking all fixed inputs again;
another branch's passing record cannot substitute for that execution.
