# PoN arithmetic and state reference

This is a non-production Python example, not a neural miner, proof system, full formal
model checker, Rust runtime, filesystem durability test or security acceptance.
It checks exact target/work examples, conditional fork selection, proposed DAA/time
boundaries, finite contribution accounting and the separation of branch state from
non-reversible local effects. Abstract validity/availability booleans are test premises;
no production API may use them as verification authority.

Run `python3 formal/pon-nakamoto-v1/test_reference.py` from the repository root.
The selected design and all unqualified work obligations remain in
[the protocol suite](../../docs/protocol/pon-nakamoto-v1/README.md).
Independent work cryptography, real reorg crash tests and public-model benefit still
require their own implementations and executed evidence.
