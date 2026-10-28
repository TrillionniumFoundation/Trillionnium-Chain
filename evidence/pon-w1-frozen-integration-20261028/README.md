# Frozen W1 continuation integration on the concurrent original-trace repair

This candidate preserves both independently developed repairs. Its first parent
is the published #519 head `a54dc7355f58f40784b5a71fe7e73c4062a14951`.
Its second parent is the frozen helper/codec candidate
`1368c139dbb2d2f174acd849d6f3c38b68f8d93a`. The earlier freeze and its evidence
remain unchanged. This is an isolated research draft; no complete proof or
native helper verification has yet been observed at this integration freeze.

The concurrent original-trace policy, `segment_continue.py`,
`segment_continue_source.py` and all 45 continuation controls are retained
byte for byte. The [native helper/codec successor](../../trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/CONTINUATION_V2.md)
adds full witness parsing, receipt-claim checks using the fixed SDK, repeated
all-62 assembly verification and final input/assembly-byte report readback.
The new policy binds the exact concurrent policy hash
`8e1b8d1c8ece0fad8e8d6eb7dfe1d4918ec8029db5c8dd9fe2844dcf741b0897`.
The sole plan and backend documentation preserve both contributions.

## Actual checks on the integrated executable source

The workflow's exact `test_segment_continue.py` and `test_frozen_witness.py`
commands ran under separate original 60-second `measure_step.py` caps.
All 45 continuation controls and all 16 frozen-witness controls passed,
including actual original/fresh witness comparison and report substitutions.
The 34 source-integrity negatives passed. Project preflight, CI contract and
whole-backend Rust formatting passed. All 20 workflow backend paths exist.
All 30 original source pins, all 315 original ZIP members and the connected
62 original witnesses checked successfully. The native helper is byte-identical
to the frozen second parent. These controls do not produce a STARK or provide
whole-source hosted qualification.

The full repository checker still refuses the sparse local checkout because
`docs/README.md` references the absent historical `evidence/pon-v1/README.md`.
The result is retained as a failure. Changed Markdown links are separately
checked against the preserved repository tree; no repository gate is disabled.
One unchanged base Git blob was absent locally; exact content was obtained via
the repository's GitHub blob endpoint, its Git object identity was checked,
and it was restored only to this new checkout's object database. Other unchanged
historical evidence blobs are still absent from the sparse local object store.
The merge preserves their existing tree entries; every changed file is checked
against its actual Git blob. This does not claim full local source qualification.

## Native build and remaining proof gates

Local release build attempt 002 stopped after 2.116699716 seconds at the
unchanged 700 MiB free-space floor; exit status was -15. It started no prover
and produced no verified native helper result. This follows the first retained
451.179276302-second disk-floor stop. The earlier cargo check passed before
the final file-descriptor and zero-PoVW hardenings; it does not certify the
final helper. Actual native 26-receipt STARK verification, native negative
controls and strict Clippy remain NOT_RUN locally. No build/resource gate
has been reduced.

Hosted workflow gates must build the exact source and pass actual original-26
SDK STARK verification plus native negative controls before either 18-segment
continuation starts. It must then verify each new range and all 62 frozen
claims, complete original Composite verification, the real invalid-proof audit
and real loopback propagation. Until all those observations exist, complete
W1 proof, worst-case rejection and propagation exits remain open. The original
failed run remains failed and spent; continuation is not a from-zero proof
cost measurement. WAN, global worst-case invalid input and global cheapest
legal solver are not established by this integration.

The earlier evidence is retained in the [frozen helper candidate](../pon-w1-frozen-witness-v2-20261028/README.md)
and [concurrent original-trace repair](../pon-w1-original-trace-repair-20261027/README.md).
