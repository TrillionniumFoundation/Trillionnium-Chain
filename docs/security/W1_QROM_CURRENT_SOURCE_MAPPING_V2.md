# Current-source W1 mapping V2

Status: **HOLD**. This is an explicit source-compatibility continuation under the
sole [development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It does not replace the historical implementation contract, its test roster,
its failed workflow results or its unknown cryptographic obligations.

## Reviewed source change

The reviewed source is Chain
`e8e2fcb8d811638eb5fa757d28590fbe8e408e61`. The retained V1 implementation
contract is based on `cb114b13bf848a77634e40a08b31b30c7c758e7b`.
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
It records 134 files. Relative to #827, the combined #824/#825/#827 source
also changes the grouped factored-producer library and its example. Their
reviewed additions implement exact B(Ax) preparation/execution and a separate
example selector; they do not change or call W1. The remaining 132 closure
files are byte-identical to #827, including manifests, locks and include inputs. The current checker verifies the local Cargo path graph,
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
