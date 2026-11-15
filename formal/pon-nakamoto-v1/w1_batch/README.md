# Full W1 receipt composition: research prototype

**Status: the complete batch guest and baseline host have compiled successfully.
The new staged conditional-receipt host is source-only and needs its own normal
build and qualification. No batch guest has executed, and no composition proof
has been generated.**
The existing complete single-work proof still fails the practical-benefit gate.
A future one-leaf composition is a functional/cost calibration, never evidence
of amortized benefit or of 31 independent works.

**Current gate: real conditional-receipt and resolve pilot pending.** Three bounded
Phase0 attempts failed and their complete records are retained. An MSRV-only
downgrade to `ruint 1.15.0` was subsequently rejected for two known advisories;
its proposed attempt4 was never authorized or started. The current guest lock
has been restored to the exact original graph, including `ruint 1.21.1`.
Official RISC Zero `r0.1.91.1` has now been downloaded once with its exact
official byte count and SHA-256, fully inspected and extracted into an isolated
home, and checked with real version/target metadata commands. A separately
declared attempt5 compiled the guest and host under the original limits;
all earlier failures remain retained. See the
[exact build artifacts and costs](../../../evidence/pon-w1-batch-build-20261028-r8/README.md),
[acquisition and resource evidence](../../../evidence/pon-w1-rust1911-acquisition-20261028-r8/README.md)
and the prior
[security correction and evidence](../../../evidence/pon-w1-batch-ruint-security-20261028-r8/README.md)
before preparing any new build declaration.

This new isolated workspace composes the **unchanged complete W1 relation**
using RISC Zero assumptions. It has no dependency edge into a Node crate,
changes no PoN ticket or chainwork rule, and supplies no alternative consensus.
The [frozen pure PoN security model](../../../docs/protocol/pon-nakamoto-v1/details/PURE_PON_WORK_SECURITY_MODEL_V1.md)
and [original complete proof evidence](../../../evidence/pon-w1-complete-succinct-20261028/README.md)
retain their existing authority and limitations.

## What the new statement means

For an ordered list of 1 through 64 entries, each entry contains the exact
318-byte expected header and the full 16,818-byte original public journal.
The guest requires a proof of each journal under the frozen original leaf
image. This proves every original W1 constraint: canonical decoding, task
commitment, challenge-bound noise rejection, all transcript prefixes, full
product reconstruction, ranges and the original ticket relation. No W1
constraint is replaced by public parsing or a sampled check.

The batch output binds its own new domain, the fixed original image, an exact
ordered count, and **every byte of every complete leaf journal**, including
all product words. Work identity is independently recomputed by the original
`TRNM-PON1` block hash of header and trace. A manifest cannot supply an identity.
Two entries with the same original identity are rejected even if the receipt
encoding, randomness, position or public product differs. Combining receipts
does not create another ticket, another mining attempt or extra chainwork.

Parent availability, branch-required target, task-window eligibility,
transaction/transport authorization, M06/state transitions, roots and receipts
are not proved by this W1 batch. Their required checks and costs remain in any
end-to-end comparison. The full block remains outside this experiment.

## Code boundaries

| Component | Responsibility | Explicit limitation |
| --- | --- | --- |
| [statement](statement/src/lib.rs) | Exact bytes, original identity derivation, ordered count, complete product, duplicate rejection | Public parsing is not W1 proof verification |
| [guest](methods/guest/src/main.rs) | Bounded reads, unconditional `env::verify` for every complete leaf, EOF, complete ordered output | Creates assumptions until the prover actually resolves them |
| [host](host/src/main.rs) and [staged resolver](host/src/staged.rs) | Hardened SDK 3.0.6 leaf/final verification, full `Receipt` assumptions, pinned local prover, durable observations | Baseline compiled; staged source and all runtime cryptographic controls remain unexecuted |
| [independent controls](contract_controls.py) | Independent Python public-byte parser, hostile structural cases, arithmetic cost screen | No STARK verification or proof; synthetic public controls have no receipts |
| [one-leaf manifest](examples/one-leaf.json) | Names the single existing complete original proof | Exactly one valid work denominator |

The host rejects Composite, Groth16 and Fake wire tags before deserialization.
It verifies every leaf with `Receipt::verify(FROZEN_LEAF_IMAGE_ID)` before
supplying the actual `Receipt` through `add_assumption`. It never supplies a
`ReceiptClaim` as if it were a proven assumption. The final gate calls
`Receipt::verify` on the compiled batch image, not merely `verify_integrity`.
The SDK expected claim enforces the exact image, journal, successful halt and
empty assumption list. A caller-selected image is not accepted from a manifest.

Independent whole-session W1 proofs cannot be merged with a continuation
`join`. This guest creates a new claim and the prover must perform real
recursive `resolve` operations. The [SDK verify API](https://docs.rs/risc0-zkvm/3.0.6/risc0_zkvm/guest/env/fn.verify.html)
and [RISC Zero terminology](https://dev.risczero.com/terminology) describe that
conditional/unconditional distinction. Local source review checked the pinned
SDK's `guest/env/verify.rs`, `host/client/env.rs`, `receipt.rs` and
`host/server/prove/mod.rs`; it does not replace an actual resolve trial.

Both host and guest pin SDK 3.0.6 and disable development mode. The new methods
builder also pins 3.0.6: an attempted 3.0.3 builder conflicted with the 3.0.6
client's dependency requirement. Both independent lockfiles are retained.
The pinned local `r0vm` remains the existing 3.0.3 binary; the SDK's normal
narrow version check permits patch differences, but actual batch prover compatibility
has **not been executed**. There is no version override or remote fallback.

## Review before execution

Run the source-only independent controls from the repository root:

```sh
python3 formal/pon-nakamoto-v1/w1_batch/contract_controls.py
```

They exercise domain/count/length/range/header/ticket/identity binding,
duplicate receipts, changed-product duplicates, order, the full cap and source
pins. Synthetic different headers are parser controls and are explicitly
unproven. Rust tests, Clippy, guest execution, negative cryptographic controls,
fresh verification and all real performance tests remain unexecuted here.

The exact later build/proof commands, resource envelope, source identities,
stop rules, comparison denominator and non-waivable controls are in the
[execution contract](EXPERIMENT_CONTRACT.md). The new
[staged pilot contract](STAGED_PILOT_CONTRACT.md) specifies a normal host rebuild,
preservation and rejection of a genuine unresolved conditional proof, and actual
resolution with the original complete leaf. It adds no production admission path.
The adjacent
[quantum and independent WAN review](EXTERNAL_GATES_REVIEW.md) records the
theory and external evidence that source changes cannot supply.

**No gate passes because these files exist or because the Python controls
pass.** The existing 2A single-work result is FAIL; aggregate benefit is
UNMEASURED; quantum hardness/soundness and independent WAN acceptance remain
open under their original criteria.
