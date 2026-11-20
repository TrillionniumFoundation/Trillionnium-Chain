# Native ML-DSA polynomial arithmetic

`ml_dsa_poly.hepta` implements the arithmetic prerequisite for
[NIST FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf):
256-coefficient polynomials modulo `q = 8,380,417`, using `zeta = 1,753`.
Forward and inverse transforms follow Algorithms 41 and 42. The product uses
bounded u64 modular arithmetic and canonical residues, without Montgomery form.

## Private byte-buffer interface

The `f0(input, output, scratch)` entry takes a 16-byte `TRNMDPQ1` header with
operation u8 at offset 8 and seven reserved zero bytes. Each polynomial contains
256 canonical LE32 coefficients, occupying 1,024 bytes.

| Operation | Inputs | Result |
| --- | --- | --- |
| 0 | One polynomial | Forward NTT |
| 1 | One transform | Inverse NTT |
| 2 | Two transforms | Pointwise product |
| 3 | Two polynomials | Addition modulo q |
| 4 | Two polynomials | Subtraction modulo q |
| 5 | Two polynomials | Product modulo `x^256 + 1` |

Output has 1,024 bytes. Scratch requires at least 2,048 bytes; success clears
exactly that prefix. Input is immutable, and output/scratch tails remain
unchanged. Every borrowed extent keeps the existing 1 MiB ceiling. Malformed
public requests return `0xfffffffd` before any caller write. A trap after valid
request admission does not carry a transactional rollback claim.

## Independent observations and remaining work

The ten methods in `hia/tests/test_ml_dsa_poly.py` compare actual native output
with independent Horner evaluation at the transform roots, a full inverse
evaluation matrix and ordinary quadratic convolution with negacyclic reduction.
They cover every forward and inverse basis vector, dense and random inputs,
all coefficient positions, malformed headers, noncanonical coefficients,
unaligned pointers, complete ABI extents and refusal without writes.

`TRNM_HIA_MLDSA_POLY_EVIDENCE_DIR` retains the exact native library, source,
build receipt, raw histories and observation summary. Success requires the
complete enclosing crypto-types test result and unchanged source identities.
The recovered test comment no longer asserts unverified errata contents; its
behavior after the module docstring is byte-identical to the recovered source.

This module does not implement the complete ML-DSA key generator, signer or
verifier. Sampling, encoding, rejection loops, key ownership, secret-dependent
timing qualification, complete official signature vectors, authenticated Node
use and package retirement remain open. No CAVP/FIPS certification or
constant-time claim follows from these arithmetic tests.
