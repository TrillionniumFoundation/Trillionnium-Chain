# Focused independent source review — Node adapter R4 v4

## Disposition

**No remaining blocking finding in the reviewed research-adapter scope after the corrections below.** This is a source-level review of the real P3-plus-native conjunction, its authority boundaries and its result semantics. It is not a PCS/Fiat–Shamir soundness certificate, a production Node qualification, an audit of every Node entry point, or a global resource/service bound.

The reviewer was the independent physical-work subtask. The reviewer did not edit these adapter files, run new adapter tests, rerun proofs, or run pressure experiments during this review. The coordinator separately reported the formatted v4 source passing 12 integration tests, strict Clippy and a release build. Those execution claims belong to the coordinator's retained logs, not to a new execution by this reviewer.

## Exact reviewed source

The following hashes were independently read back from the final formatted local files and matched the coordinator's supplied v4 hashes:

| File under `node_adapter_r4/` | SHA-256 |
|---|---|
| `src/lib.rs` | `69457c74801b2ac7b42d5a95edb4a17c32d1664bc00d14d7235415863e891ec6` |
| `src/main.rs` | `ec8fc3116c4e5a17f134c1c9c61a0cfaa84a51de7306f9ce46fef9b358494c92` |
| `tests/node_bridge.rs` | `9035dead75db8b2f66bfd8ce629ef78721647f096bc4d7c85e12fcb9a5ab9d66` |

The scope wording in `README.md` was also read, at SHA-256 `a2cb1e9e3925662767759ac9977d592ee5729b1aaf8d3e8e5cc6e6ab0defed1e`. This is the observed documentation snapshot, not an assertion that later editorial changes retain that hash.

For the underlying behavior, the reviewer read the actual `trillionnium/crates/trnm-pon-node/src/store.rs` in the independent checkout derived from published baseline `cc836dfc13ef0006eb0878abd8cb5eca9a76bec0`. Its SHA-256 was `07de31f9bece7ea41b0a608a04fc01cec33409bfc610094fc38294257bb1dbf1`. The reviewed methods include `open`/`open_inner`, admission context checks, `admit`, the native SQL commit boundary, `recover`, and `exact_packet_observation`.

Any change to the three adapter source hashes requires a new source-binding record; this review must not be copied onto different bytes without checking the change.

## Findings resolved during review

### R1 — The exercise command opened Node before checking the proofs

The initial `exercise` implementation created the receiver Node before calling `verify_bundle`. Although it used a new output directory, this contradicted a blanket proof-before-Node-open claim. Opening a Node is significant because native initialization/recovery can mutate durable state.

The final implementation obtains a successful `VerifiedBundle` first and only then calls `Node::open`. Proof failure or `BeforeProof` cancellation follows the error branch with `node_opened=false`, null native observation and no receiver Node directory. The final test source invokes the actual CLI in two distinct controls: cancellation at `BeforeProof`, and a false public arithmetic value with unchanged real proof inputs. It checks the diagnostic error, spent local work start and absence of `receiver-node`.

`reopen` also performs fresh proof verification before `Node::open`. The stronger order applies to these receiver CLI paths. The fixture command deliberately opens a proposer Node to generate its input packet; the convenience library `observe(&Node, ...)` receives an already-open owner. Neither is mislabeled here as an all-callers proof-before-every-open enforcement mechanism.

**Disposition: resolved in the pinned v4 source.**

### R2 — The initial receipt incorrectly implied a new FullLimb replay for duplicates

The original Node's `admit` first checks admission context. An already stored exact packet can return successfully before `WorkCheckedPacket::verify`. The shortcut still compares complete packet bytes and rechecks the observation-time condition; it reuses original admitted state instead of doing fresh W1 work.

Therefore the initial per-call `native_full_replay_required:true` label was inaccurate for duplicates. The final receipt uses the fresh namespace `trnm-w1-node-adapter-admission-v2`, reports `native_admission_path_invoked:true`, and states the native policy: fresh packets execute native W1; exact duplicates reuse original admitted state. It does not invent a measured replay counter or perform redundant work merely to justify an old label. The final duplicate test asserts the new fields, absence of the old field, and unchanged active generation/state.

**Disposition: resolved in the pinned v4 source.**

### R3 — Archive entry enumeration now refuses I/O errors

The final archive-limit loop propagates an entry error before counting that entry. It does not silently count an unreadable iterator result as a successfully inspected directory entry. The caller-exclusive archive and fixed finite entry limit remain explicit assumptions, rather than a claim of a race-free global quota.

**Disposition: the coordinator's correction was independently read and is consistent with the stated scope.**

## Authority and lifecycle conclusions

**Trusted expectations are a caller boundary.** `OperatorPlan` checks the exact research profile and canonical context/header/artifact encodings. The bundle binds the packet's canonical bytes and exact header to those expectations, and binds header-plus-native-proof bytes to the raw public statement. Reload requires a freshly supplied plan again; stored metadata does not choose the trusted plan. The type does not authenticate the human or filesystem provenance of arbitrary caller-supplied plan bytes. The README correctly assigns that responsibility to the independent trusted caller and excludes hostile same-UID filesystem isolation.

**A real checked capability precedes this adapter's admission.** `PreparedBundle` owns private immutable byte buffers. Both proof frames undergo fixed-profile scans before allocating decode. Actual SHA and packed-arithmetic proof verification use preprocessing reconstructed from the expected statement and fixed component configuration. Only successful completion of both checks constructs the private, non-serializable borrowed `VerifiedBundle`. No caller boolean or proof-supplied verification key creates that capability. This traces a genuine implementation conjunction; it does not prove the underlying P3 construction's security.

**The native owner retains live state authority.** Before admission, the adapter rechecks the live network, parameters, genesis, parent height and expected target. It then calls the original `Node::admit`. The native packet body remains subject to the Node's original transaction/state/clock checks. The adapter never fabricates the Node's private verified-work capability or replaces fresh native work checks with the P3 result. Other original Node entry points remain original native paths; this research adapter is not a global production dispatch policy requiring P3 everywhere.

**Late cancellation preserves a successful native fact.** The underlying native persistence path returns `Ok(id)` after successful SQL commit and has no cancellation fence after that commit. The adapter's `NodeCommitted` callback therefore records a late error without changing `native_admitted:true`. Requested adapter activation is skipped on that late cancellation. An activation or later observation error is retained as a separate field instead of turning the successful native admission into a cryptographic rejection. Duplicate success similarly reports the truthful original admitted state; it is not a new commit count.

**Cold open may activate a committed packet.** The reviewer traced `open_inner` calling `recover`, and `recover` selecting the best stored packet and calling `activate`. The adapter cannot promise that a postcommit cancellation keeps that packet inactive across restart. The final test explicitly observes storage without activation before close, then the committed packet becoming active after cold open with a higher generation. The README states this boundary. `observe_verified` does not itself call admission or activation, while CLI `reopen` includes the original Node's recovery side effect.

**Reorganization observations use current native state.** `exact_packet_observation` compares retained complete packet bytes and queries current active-chain membership. The reorganization test changes the actual Node to a native sibling/child branch, then checks that the original packet remains stored but is no longer active; observation does not reactivate the historical receipt. Those sibling and child are native packets, not additional newly proved P3 inputs. This is correctly distinguished in the README.

## Boundaries that remain material

The input/archive readers are bounded research filesystem operations under an exclusively owned path assumption. Their byte checks and completion marker are useful integrity conditions, but they do not establish production-owned VFS qualification, adversarial same-UID path-race isolation, whole-system disk quotas or power-loss guarantees for all filesystem ancestry. The README excludes these stronger claims.

`WorkStartBudget` is an in-memory limit on starts in one owner instance. It charges a failed start and cannot be replenished by a caller's success claim, but process restart/new output directories do not make it a persistent global adversarial-work ledger. The archive entry count likewise is not a global admission service. Checkpoints occur between substantial proof phases and do not interrupt an ongoing PCS/preprocessing call. No hard CPU, memory, wall-time or benign-service guarantee follows from these APIs.

The fixture has an explicitly controlled development genesis and observation time. Its retained P3 proofs and replay tests do not establish production wall-clock eligibility, support for other profiles, new proving executions on each replay, or a general security-strength claim. The README retains the shared-permutation PCS/Fiat–Shamir gap, all five open production gates and the native build's I/O qualification warning.

A minor nonblocking documentation naming issue remains in the reviewed README snapshot: the source calls the free function `trnm_pon_node::maintenance()`, while one sentence spells it `Node::maintenance()`. This does not alter the reviewed input-binding or admission semantics and needs no new execution if corrected editorially.

## Final scope statement

The two substantive review findings were corrected, the coordinator's archive-enumeration correction is present, and the final source/test design has no further blocking issue identified within this focused read-only review. The exact source hashes above are the binding for that conclusion. Runtime results must continue to cite their own retained command logs, source/binary/fixture pins and actual exit observations. **HOLD_NO_GO and the remaining production gates are unchanged.**
