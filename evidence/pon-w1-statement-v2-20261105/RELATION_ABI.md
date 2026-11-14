# W1 v2 public artifact statement and native authority boundary

This continuation closes the missing **public A/B artifact commitment** in a new
research statement. It preserves the complete existing PNH1/PNW1 work replay and
the original lottery identity. The guest does not claim Node admission authority.
The original Node remains responsible for current-parent task eligibility,
execution, current clock, storage epoch, and commit.

## Exact public format

The input remains exactly **49,506 bytes**: a 318-byte canonical PNH1 header and
the complete 49,188-byte PNW1 witness. `check_complete_relation` first calls the
unchanged v1 relation implementation, which calls the complete native verifier.
It then hashes the same original raw A/B byte slices used by Node parent
admission. No alternate field, hash, multiplication relation, or task encoding
is introduced.

The new journal is exactly **16,882 bytes**. Byte offsets are half-open.

| Offset | Length | Public field |
|---|---:|---|
| 0–20 | 20 | `TRNM-W1-ZK-JOURNAL2` followed by one NUL byte |
| 20–338 | 318 | Exact canonical PNH1 header |
| 338–370 | 32 | Complete transcript digest |
| 370–402 | 32 | Original ticket |
| 402–434 | 32 | Original `header.block_id(trace)` |
| 434–466 | 32 | Original model artifact commitment of raw A |
| 466–498 | 32 | Original qualified-task input commitment of raw B |
| 498–16,882 | 16,384 | All 4,096 canonical u32-LE product words |

The commitment expressions are exactly the pre-existing Node expressions:

```rust
hash(b"artifact", &[&proof[4..4 + CELLS * 4]])
hash(b"qualified-task-input-v1", &[&proof[4 + CELLS * 4..4 + 2 * CELLS * 4]])
```

They use the original `trnm_protocol::pon_wire::hash`, including its
`TRNM-PON1\0` prefix and length framing. The shared extraction helper checks
only PNW1 length and magic before hashing. It deliberately does not create
verified-work or eligibility authority, and does not move field validation in
front of the original Node parent checks.

The post-proof public checker requires an externally supplied expected header
and expected A/B commitments. Supplying those expected commitments from the
untrusted journal would defeat the artifact binding and is outside its contract.
The checker is not a receipt verifier. The host must first authenticate the
**distinct v2 guest image** and proof type. Original v1 journals have a different
domain and length and are rejected by the v2 checker. A v1 receipt must never be
advertised as proof of these new A/B fields.

## Original native eligibility is retained

`Node::check_admission_parent` still restores the actual parent State and calls
`eligible_work_task_from_state` before inspecting material commitments. That
function retains all its original profile dispatch and qualification checks:

| Existing branch | Authority still supplied by the original native path |
|---|---|
| Continuity maintenance | Exact maintenance task and current maintenance eligibility |
| PQ task v5 | `tasks_v5::eligible_task` against current State, height and app settings |
| Lifecycle / atomic / overlap / continuity / growth / checkpoint | `qualified_task_lifecycle::eligible_task` against the same current context |
| Legacy registration | Exact registered task Boolean in the original profile |
| Signed registration | Parent registration height, canonical signed manifest, task ID, current context, source statement verification, manifest ID, withdrawal head, demand and purpose, and source nonce |

For a branch with a manifest, only the old inline raw-A/B hashing is factored
into the shared helper. The original error order remains material shape,
`TASK_MODEL_BINDING`, then `TASK_INPUT_BINDING`. All other Node state, execution,
output-consumption, header, target, clock and SQL checks remain in their existing
paths. The receipt is not converted to the private `WorkCheckedPacket` capability;
there is no new production proof-only acceptance path.

A future composed backend would have to use the original freshly checked parent
manifest, verify the v2 proof and image, match the exposed artifact commitments,
and continue through the original execution/commit authority. This record does
not certify such a future integration. It supplies the missing public data and
retains the native validation control.

## Identity and comparison controls

The v2 projection preserves the complete header, trace, ticket, work ID and
product from the original v1 relation result. Neither the statement version,
artifact hashes, guest image, proof randomness, recursive wrapper nor proof
serialization is included in the lottery identity. Tests compare the v1 and v2
identity with `header.block_id(trace)` and compare the complete product and ticket
with the independent scalar reference verifier.

The original Node qualified-task integration test still constructs a correct
full W1 proof, correct task ID, execution result and state root while deliberately
registering an unrelated signed model or input commitment. It verifies the new
shared public hashes against the original raw artifact expressions, then checks
that actual Node admission accepts the matching control and rejects the two
mismatches without changing persisted state. Other retained integration tests
exercise registration, expiry, source nonce, withdrawal and branch changes.

## Evidence interpretation

`native-relation-tests.txt` records actual locked release tests of the relation
and its public-byte adversaries. Separate native logs record the shared hash
primitive and actual Node qualified-task controls. These are native tests, not
cryptographic receipt verifications and not an all-input equivalence proof.
The distinct v2 guest build/proof/receipt observations are recorded separately
by the host campaign. No result from the archived v1 receipt is counted as a v2
proof trial.

`module-environment-observations.json` retains the initial stale-lock and missing
pinned-SHA-checkout failures. The old guest source, journal namespace, guest lock,
and archived evidence are preserved. The new workspace and guest-v2 lockfiles
resolve the real current native dependency graph; their exact bytes belong to
the new source identity, not to the original archived proof identity.
