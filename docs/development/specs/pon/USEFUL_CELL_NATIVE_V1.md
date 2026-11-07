# Native bounded Cell verification V1

This increment follows the sole [development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
`pon-cell-stateful-native-int257-v1` is a native Rust computation profile with
real Node and CLI verification entry points. It is separately versioned from
the Python [V2](USEFUL_CELL_RELATION_V2.md) and
[multimodal V3](USEFUL_CELL_MULTIMODAL_V3.md) profiles. It neither accepts their
proof bytes nor changes `Node::admit`, consensus Packets, reward eligibility
or activation rules.

## Actual computation

The owner admits up to 64 UTF-8 snippets of at most 4096 bytes each. Rust
reexecutes ASCII whitespace normalization, bounded ASCII tokenization, the
declared token exclusions, signed SHA-256 hashing, clipping and the 257-value
feature tensor with bias. It then applies the actual boolean feature mask.
This is an owner-retained source-byte profile. It does not reconstruct the
V2 Git corpus or authenticate the origin and labels supplied by the owner.

The full model contains the base, router and three delta matrices, each 3×257.
All five W1 tiles undergo native complete-transcript, material, challenge,
target, padding and signed-product checks, with scalar product comparison.
Rust then reexecutes legal expert selection, tie rules, recurrent memory,
step/sequence transitions, STOP, abstention, tool proposals, sampling and the
optional masked/clipped momentum update. The integer training rule freezes
router parameters and stops gradients through discrete state, as explicitly
defined in V2. Native contract, model, segment and work identities use their
own namespace. The numerical sampler deliberately retains V2's defined RNG
domain for direct numerical comparison; this does not make the proof domains
interchangeable.

Actual intermediate inputs and outputs form a contract-bound ordered segment
chain. A hash-consistent but arithmetically wrong segment is rejected after
full replay. The verified return type cannot be deserialized from producer JSON.

## Who supplies expected context

`Node::cell_expected_from_owner` is the only constructor for
`ExpectedCellTask`. It accepts the owner's independently retained canonical
admission bytes and exact SHA-256 pin. It obtains network, parameters, parent
ID, state root, height and protocol time by replaying the Node's verified state
at the selected parent. Producer claim fields cannot construct the parent
context or become authoritative expected context.

The SHA-256 pin binds bytes; it does not authenticate a person or confer a
permission. The caller remains responsible for the owner channel. The CLI
requires a separate absolute owner-file path and independent SHA-256 argument.
That file must be regular, owned by the executing UID, singly linked and have
no group/other permissions; symlinks are refused. These checks are local input
discipline, not remote attestation of the host or a substitute for FinalUse.

## Historical and current time

Native Header timestamps are UNIX **seconds**. This profile uses that exact
unit and the verified parent Header time (or the protocol genesis time), not a
producer-provided timestamp. It does not silently convert the Python profiles'
UNIX milliseconds or Hepta's monotonic microseconds.

`verify_historical` consumes only the frozen expected task and claim. It never
reads wall time, current revocation or the active tip. The CLI dispatches this
command before its ordinary wall-clock initialization. Rechecking the same
historical proof remains valid after its current-use window expires.

`Node::verify_cell_live` additionally checks the current-use window before and
after verification, requires the expected parent to be active, and rechecks
active parent/generation and the verified parent state after expensive work.
Owner authorization and revocation are still external owner responsibilities.
Neither API consumes a request, commits a checkpoint, grants FinalUse or proves
that a production model was later used.

## CLI and validation boundary

The explicit commands are `cell-verify-historical`, `cell-verify-live` and
`cell-prove-reference`. Each requires an existing Node store, an actual parent,
the separate owner admission and its pin. The verifier additionally requires
the producer claim. `--logical-now` is rejected. Reference proving performs
real W1 work under a bounded search budget and writes its output create-only;
it does not submit or install it.

The retained numerical oracle is generated from unchanged Python V2 execution
and covers seven different bounded cases. Native integration controls compare
preprocessing, all products, decisions, backward values, clipping, moments,
updated models and states; they also exercise real CLI refusals and cold Node
replay. An additional native next-task control consumes the actually verified
after-model and state, while continuing to report that no owner checkpoint was
committed. These are finite correctness controls, not independent quality or
real production adoption observations.

The [retained native record](../../../../evidence/pon-native-cell-v1-20261107/README.md)
contains the 12-test run and complete owner/claim/packet materials: 11 distinct
claim byte strings and 55 distinct W1 proofs. Its cold subset makes six fresh
historical-verifier invocations across three new stores, over two distinct
claims containing ten distinct W1 proofs. Legacy and authenticated history
share one claim; repeated verification creates no new proof.
The [recovered acc2 concurrent record](../../../../evidence/pon-cell-concurrent-revalidation-20261107/README.md)
retains the subsequent native gates and cold subset on the combined source with
identical case bytes. Earlier failed setup and Clippy observations remain
retained. Neither record combines the separate private Hepta owner path into a
public-proof-to-FinalUse claim.

Implementation and controls:

- [Native relation and Node entry](../../../../trillionnium/crates/trnm-pon-node/src/cell_native_v1.rs)
- [Source preprocessing](../../../../trillionnium/crates/trnm-pon-node/src/cell_native_v1/source.rs)
- [Complete W1 verification](../../../../trillionnium/crates/trnm-pon-node/src/cell_native_v1/work.rs)
- [Execution](../../../../trillionnium/crates/trnm-pon-node/src/cell_native_v1/execution.rs)
- [CLI](../../../../trillionnium/crates/trnm-pon-node/src/cell_native_cli.rs)
- [Integration controls](../../../../trillionnium/crates/trnm-pon-node/tests/cell_native_v1.rs)
- [Cross-language oracle generator](../../../../trillionnium/crates/trnm-pon-node/tests/cell_native_v1_fixture.py)

General multimodal encoder support in native Node, arbitrary model graphs,
ordinary Hepta proof-to-owner composition, actual external delivery, independent
model quality, production adoption and work-cost qualification remain open.
