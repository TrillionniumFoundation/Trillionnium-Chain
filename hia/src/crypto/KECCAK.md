# Native Keccak, SHA3 and SHAKE

`keccak_stream.hepta` implements Keccak-f[1600], SHA3-224/256/384/512 and
SHAKE128/256 directly in HIA. The algorithm follows
[NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf),
sections 3–6 and Appendix B.2. Python supplies independent test oracles and
observations; it does not supply the product permutation or digest.

## Private byte-buffer interface

The `f0(input, output, scratch)` entry accepts the 24-byte `TRNMK3Q1` header:
operation u8, mode u8, six reserved zero bytes and output count LE64, followed
by byte-aligned payload. Operations 0–6 are one-shot, initialize, update,
finalize, squeeze, clear and raw permutation. Modes 1–6 select the four SHA3
digests followed by SHAKE128 and SHAKE256. Each borrowed extent retains the
existing 1 MiB ABI limit; one update therefore carries at most 1 MiB − 24
payload bytes. Incremental hashing and squeezing can span multiple bounded calls.

Scratch `[0, 232)` is a private caller-owned context: `TRNMK3C1`, mode, phase,
six zero bytes, position LE64, remaining digest bytes LE64 and 200 state bytes
in little-endian `x + 5*y` lane order. Phase 0 absorbs and phase 1 squeezes.
Fixed digests cannot extend past their remaining output. Clear and successful
one-shot execution erase exactly the 232-byte context; trailing caller bytes
are preserved. This context is neither persisted nor authenticated.

Malformed public requests return `0xfffffffd` before writing caller buffers.
An unexpected internal one-shot helper result returns `0xfffffffc`; it cannot
be reported as success. Lifecycle, capacity, padding, alignment, immutable input,
scratch reuse and tail guards are checked by the native tests.

## Exact qualification surface

`hia/tests/test_keccak.py` has 11 methods. Its checked fixture contains all
3,442 vectors in the six official byte-oriented ShortMsg files and the two
VariableOut files. `hia/tests/vectors/keccak_fips202.json` binds the original
ZIP URLs, full archive identities and member identities. LongMsg, Monte Carlo
and bit-oriented vectors are outside this fixture; no CAVP or FIPS validation
is claimed. Independent permutation controls cover all 1,600 individual state
bits, with separate SHA3/SHAKE comparisons and real unaligned pointer histories.

The complete crypto-types shard must execute every selected method with the
pinned self-hosted compiler. `TRNM_HIA_KECCAK_EVIDENCE_DIR` retains its actual
library, source, build receipt, raw histories and observation summary. The
enclosing qualifier determines success from the complete test result, including
class setup and teardown; observation counters alone are not a pass witness.

This is a hash foundation. Complete PQ signatures, private-key custody,
constant-time qualification, authenticated identity, Node adoption and
retirement remain separate obligations.
