# Complete W1 relation and native differential controls

Status: research component under PN1 / M01. This module is not a succinct proof,
does not establish work-cost hardness or model improvement, and grants no new
consensus or public-admission authority. The sole development plan remains
[the existing plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Implemented relation

`trnm_crypto_primitives::pon_work::full_relation` is a deterministic, bounded,
independent implementation of the complete existing 64-by-64, rank-8 W1 relation.
It checks canonical field words, exact A/B task identity, header challenge,
target, all four bounded noise streams, every one of the 512 ordered cumulative
tiles, the entire SHA-256 trace and the complete product corrections. It does not
call the existing native `verify`, `evaluate` or producer kernels.

The guest arithmetic uses the exact identity `2^32 = 5 (mod q)` to reduce each
bounded accumulator with two folds and one subtraction. All dot products have
at most 64 canonical terms, so their sums are below `2^70`. This bound is an
assertion in release builds as well: an internal range regression cannot silently
truncate high words. Tests compare the result with integer `% q` at the maximum
legal dot product, the complete 70-bit boundary, 4,096 deterministic samples and
out-of-range controls. The original scalar native kernel retains its separate
integer remainder implementation as an oracle.

Each tile's 64 little-endian words are passed to SHA-256 as one 256-byte update,
in exactly the previous order. All 512 tiles and 131,072 intermediate-value bytes
remain in the trace. This changes API call boundaries, not the public relation,
header, ticket, trace format or any hashed byte.

`LocalExecution` records actual full local recomputation. Its fields are private
and there is no conversion to `VerifiedWork`. No node or transport entry point
uses this research module. Recomputing the relation alone does not repair the
cheap-forgery/expensive-rejection availability problem.

## Exact public statement

The `PWG1` statement is exactly 452 bytes:

| Byte interval, end exclusive | Content |
| --- | --- |
| 0–4 | `PWG1` |
| 4–6 | little-endian version 1 |
| 6–38 | fixed complete-relation profile identifier |
| 38–356 | exact existing 318-byte `PNH1` header |
| 356–388 | externally established expected task |
| 388–420 | externally established expected target |
| 420–452 | domain-separated commitment to all 49,188 PNW1 bytes |

The input is this statement followed by exactly 49,188 PNW1 bytes, totaling
49,640 bytes. Short, extended, unknown-profile and unknown-version encodings are
rejected. The header's task and target must equal the expected public values.
All twelve existing header fields bind the challenge: network, parameters,
parent, height, timestamp, target, miner, transactions, state, receipts, work task
and nonce. The caller still establishes the authorized network/parameters,
parent-derived target and task eligibility in the actual parent state.

The deterministic `PWJ1` public journal contains statement ID, challenge, task,
ticket, trace, original block ID and product commitment. Proof randomness and
proof encoding cannot alter the lottery or the original
`H("block", canonical_header, trace)` block identity.

`unverified_claimed_journal` constructs only the expected public-output bytes,
without replaying W1. It deliberately accepts arithmetic falsehoods and must
never be used as a proof or admission verdict. Its purpose is to let the
standalone computation-proof verifier compare the authenticated journal with the
complete requested statement without reintroducing expensive W1 recomputation.
A commitment, signature, successful parsing or these claimed journal bytes do
not authenticate any computation.

The profile identifier pins a relation version, not an executable program.
A real proof adapter must additionally pin the actual guest image, proof-system
parameters and allowed hash/receipt type. A failed proof cannot fall back to the
original expensive full-W1 public path.

## Executable checks

Run from the repository root with the pinned Rust toolchain:

```sh
bash scripts/project-preflight.sh
cargo test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives full_relation
```

The native controls compare the complete relation against all three existing
W1 kernels on nineteen materials, including zero, one-zero, rank-one, sparse,
identity, near-modulus and deterministic dense matrices. They also construct
false first/middle/last intermediate traces with correct final products and
recomputed commitments, check every header field, reject incorrect task/target,
incorrect product and noncanonical words, and exercise exact statement/input
lengths. A test explicitly shows that a newly recomputed commitment and the
original cheap ticket can pass while complete trace verification fails.

The standalone example constructs a real W1 fixture and replays the relation:

```sh
cargo run --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --example pon_w1_complete_relation -- \
  fixture /new/path/w1-input.bin
cargo run --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --example pon_w1_complete_relation -- \
  execute /new/path/w1-input.bin
```

Fixture creation refuses to overwrite an existing file. Its all-`ff` target is
an explicitly loose research target. The JSON reports full local recomputation
and explicitly reports no succinct proof and no consensus authority. Neither a
passing finite test suite nor a local timing establishes production security,
worst-case invalid-proof service affordability, quantum security or permissionless
fairness. Actual backend proofs and their independent verification must be
reported separately from these native controls.

## Real proof-backend experiment

The [isolated RISC Zero guest and verifier](../../../../trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/README.md)
compile this complete relation into a hash-pinned real guest and accept only a
fixed transparent Composite proof profile. The
[2026-10-27 evidence](../evidence/w1-complete-risc0-20261027/README.md) distinguishes
actual execution, full native replay, proof attempts and independent proof
verification. The original bounded local proof attempt timed out after 1,800
seconds without a receipt. Neither that attempt nor the existing successful
execution turns `LocalExecution` into a proof or enables Node admission.

The [original two-thread hosted attempt](../evidence/w1-risc0-hosted-run-40482711995/README.md)
separately exhausted 5,400 seconds without a retained receipt. Its complete
artifact and failed process remain intact. Neither attempt supplies a completed
proof-generation latency or an actual proof-verification measurement.

## Proof economics and online latency are separate exits

Under an explicitly idealized independent-ticket model, let p be the chance
that a complete fresh W1 attempt meets the current target, C_W the fully charged
cost per attempt, and C_P the additional completed certificate cost for a winner.
Ignoring forks, preprocessing differences and failed certificate generation, the
expected charged cost per winning certified candidate is `C_W/p + C_P`.
The present timeout records do not provide a finite measured C_P.

This equation does not make a slow proof suitable for fast block propagation.
If certification begins after finding a winner, its wall latency remains on the
path before other nodes can independently accept that candidate. More miners or
a harder target cannot be assumed to reduce that latency. The single fixture's
guest execution time is neither C_P nor the network's inter-block interval.
Publishing an uncertified header early cannot grant it validated chainwork.

Measure three separate distributions on an exact new backend: complete winner
certification including failures; valid verification; and the last possible
rejection of each allowed adversarial proof shape. A certificate may avoid
native W1 replay yet still cost more verifier CPU or bytes than the current
native relation. Its bounded parser and private checked result must enter the
original global resource owner before it becomes an online admission path.
No STARK, sumcheck, proof aggregation, larger block or parallel ordering design
automatically clears these three obligations.

Batching needs a complete statement for every constituent header, task, target,
ordered trace and branch context. A proof of an aggregate final product cannot
replace those bindings. Aggregating already validated history may help bootstrap,
but that is a different experiment from reducing online hostile rejection cost.
Proof randomness or alternate certificate encodings must not create additional
winning tickets or additional cumulative-work credit for the same W1 statement.
