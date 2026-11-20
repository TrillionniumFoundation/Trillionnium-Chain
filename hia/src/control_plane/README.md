# Native control-plane values and observer registry

The two HIA compilation units implement the control-plane value methods and a
private observer-registry lifecycle from
`trillionnium/crates/trnm-control-plane/src/lib.rs`. The pinned native HIA
compiler emits both actual shared objects. Canonical hashing reuses the existing
HIA SHA-256 initialization and compression functions; HIA constructs every
preimage, sorts capabilities, checks bounds, compares full values and performs
registry updates.

## Implemented operations

| Unit | Original public behavior |
| --- | --- |
| `core.hepta` | `Digest32V0::hash`; descriptor canonical digest and validation; workload-measurement validation; all three action-variant digests; plan canonical digest and shape validation; parameter-bound validation; receipt canonical digest |
| `registry.hepta` | `ObserverRegistryV0::default`, `register`, `observe` and `descriptor` over complete sequential histories, with private source, state and output allocations |

The canonical digest methods retain their original domains on values that
subsequently fail validation: descriptor capability vectors above 256, action
parameters beyond 128 bytes, plans above 128 actions and receipt vectors above
128 results can still be hashed. Validation retains its own original limits
and error order. Local parameter names are arbitrary byte vectors, including
NUL and invalid UTF-8. Signed parameter values and bounds preserve all 128 bits.

The registry retains original capability order for equality. Reordering a
same-generation descriptor's capabilities preserves its canonical digest but
returns `DescriptorSubstitution` if the complete original value differs.
Increasing a module's generation preserves that module's earlier measurements.
An existing measurement key accepts an identical full value and rejects changed
facts. Unknown-module rejection precedes measurement business validation.

`LocalPlanGuardV0` construction/evaluation, the generic
`PlanSignatureVerifierV0` provider and actual application of an accepted plan
remain migration work. These units expose no caller-provided signature-result
flag and no successful stand-in for that provider. The original five retained
Rust tests include guard behavior; running those original tests does not credit
HIA with guard coverage. The package remains partially ported, with no accepted
retirement or whole-Node integration.

## Foreign entries and publication

Both units export exactly
`f0(input: readbuf, output: mutbuf, scratch: mutbuf) -> u32`.
The complete input remains unchanged. A successful value operation publishes
its exact result and preserves the output suffix. A refusal leaves the entire
output unchanged. Scratch is working memory and may change.

Scratch capacity must be at least `65536 + 3 * input_length` bytes. Extent
arithmetic is checked before use, including the SHA-256 bit-length bound. The
native entries have no separate 1 MiB protocol limit. The disposable comparison
drivers use their explicit 1 MiB borrowed-input/output profile; larger native
capacities require an independently bounded caller.

| Return code | Meaning |
| --- | --- |
| `0` | Complete operation or complete registry history |
| `1..26` | The original `ControlPlaneErrorV0` numeric discriminants, for value validation |
| `100` | Malformed local representation: type range, magic, truncation, count or trailing data |
| `101` | Insufficient output capacity |
| `102` | Insufficient scratch capacity or unrepresentable extent |
| `103` | Registry private allocation refused |

These byte representations are local migration ABIs. The original signed
hashing domains are unchanged.

## Value request: `NCPL0001`

The header contains the eight-byte magic followed by a little-endian `u64`
operation. The remainder is exactly one complete typed payload.

| Operation | Behavior | Successful result |
| --- | --- | --- |
| 0 | Descriptor canonical digest | 32 bytes |
| 1 | Descriptor validation | Verified 32-byte descriptor digest |
| 2 | Measurement validation | Empty |
| 3 | Action canonical digest | 32 bytes |
| 4 | Plan canonical digest | 32 bytes |
| 5 | Plan shape validation | Verified 32-byte plan digest |
| 6 | Parameter-bound validation | Empty |
| 7 | Receipt canonical digest | 32 bytes |
| 8 | Generic domain/parts digest | 32 bytes |

Every scalar field below uses little-endian `u64` unless explicitly stated.
Typed `u16`, `u32`, enum and Boolean fields must fit their original Rust types.
Digests are 32 raw bytes; signed `i128` values are exactly 16 two's-complement
little-endian bytes. Variable byte sequences have no terminator or padding.

- **Descriptor:** module ID, generation, capability count; digests in order
  contract, implementation, dependency graph, configuration, invariant,
  descriptor; then the capability digests in their original order.
- **Measurement:** workload, validity-region and evidence digests; then goodput,
  p50, p95, p99, CPU, memory, disk, network, queue pressure, errors, drops and
  recovery cost. Queue pressure must fit `u32`.
- **Set-bounded-integer action:** kind `0`, module ID, parameter class, signed
  `i128` value, parameter byte length and parameter bytes. Classes `0..2` retain
  the original operational, determinism-critical and consensus-critical order.
- **Place-worker action:** kind `1`, module ID, worker-profile digest and
  placement digest.
- **Forbidden action:** kind `2` followed by the original forbidden-action
  discriminant `0..9`.
- **Plan:** six digests in order plan ID, source graph, contract set, workload
  assumptions, expected effect and rollback plan; issued generation, first
  height and expiry height; signer, signature and canonical-plan digests;
  action count; then each action's byte length and complete action payload.
- **Parameter bound:** module ID, parameter class, minimum `i128`, maximum
  `i128`, parameter byte length and parameter bytes.
- **Receipt:** plan digest, accepted generation, source-graph digest,
  resulting-configuration digest and invariant-result digest; accepted Boolean,
  result count, receipt digest; then each result's action digest, decision
  discriminant and error discriminant. Accepted decision `0` has error `0`;
  rejected decision `1` has an original error `1..26`. The supplied receipt
  digest is excluded from its own canonical digest, as in the original.
- **Generic digest:** domain byte length, part count and domain bytes; then
  each part's byte length and bytes. Hashing uses the original big-endian length
  prefixes; the part count is local framing and does not enter the preimage.

The plan's signature digest is excluded from its canonical digest by the
original method. Shape validation still requires a nonzero signature digest;
it does not perform signature verification.

## Registry history: `NCPR0001`

The header is the eight-byte magic plus a command count. Each command contains
an operation, payload byte length and complete payload:

| Operation | Payload | Original method |
| --- | --- | --- |
| 0 | Descriptor payload above | `register` |
| 1 | Module ID followed by the measurement payload above | `observe` |
| 2 | Module ID | `descriptor` |

The entire typed history is admitted before allocation. HIA then allocates and
owns a full input copy, the registry index and a staged output buffer. Registry
state is private during the complete sequence. Each successful registration or
measurement becomes the state consumed by subsequent commands. Each business
rejection preserves state and is included in the result; execution proceeds to
the next command. All three owners are released on every terminal path.

The complete output begins with total output byte length and command count.
Each command contributes its original business status, payload byte length and
payload. Successful `register` and `observe` results have empty payloads. A
`descriptor` lookup returns the complete original-order descriptor payload, or
an empty payload for `None`. A history-level framing, capacity or allocation
failure publishes no output.

Each foreign invocation constructs one fresh registry and ends its lifetime
after publishing the sequence result. Retaining this owner across live Node
requests and coupling it to an authenticated plan-application owner require
further integration. The local registry grants no consensus, signature,
settlement, activation or persistence authority.

## Validation and evidence

`hia/tests/test_control_plane.py` compiles the complete unchanged original Rust
library, all five original unit tests and the separate
`control_plane_original.rs` adapter. The adapter constructs original typed
values and invokes their public APIs; it contains no copied hashing or policy
implementation. All original/native inputs and outputs are compared in full.
The C allocation observer instruments allocation success and lifetime only.
It calls the unmodified emitted HIA entry and implements no control-plane rule.

The suite exercises all digest bits, complete signed bounds, canonical domains,
original error precedence, empty/large vectors, invalid typed representations,
all 64 registry modules, same-generation substitution, retained measurement
keys, mixed stateful histories and every private-allocation denial. Full output
canaries survive refusal, and all successful/refused/OOM registry paths end
with zero live private allocations.

With `HIA_CONTROL_PLANE_OUTPUT` set to a new directory, evidence captures the
actual native and original binaries, the original retained-test executable,
composed HIA inputs, build identities, complete oracle process streams and all
native input/output/scratch bytes in a content-addressed blob store. Existing
output directories are refused. The final report checks the complete expected,
started and finished test roster against the finalized `unittest` result,
including failed subtests, errors, skips and expected/unexpected successes.
Deliberate reporter negative controls prevent failed executions from becoming a
successful evidence report.
