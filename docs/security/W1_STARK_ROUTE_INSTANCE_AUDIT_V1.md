# W1: separate proof instances and certify their fixed field parameters

Date: 2026-11-09. Status: **FIXED ALGEBRA CHECKED; COMPLETE SECURITY HOLD**.

This continuation starts from the complete #835 source at
`e2a02f9271b49f146e70806c8a66e161b5973971`. It adds an executable correspondence
check for three existing research proof profiles. It does not change their
cryptographic algorithms, accepted statements, wire formats or admission rules.
The [route registry](../../config/pon/w1-stark-route-registry-v1.json) is checked
against retained source bytes; it is not treated as evidence for its own values.

## Why the profiles require separate identities

| Profile | Base field | Challenge extension | Existing primitive |
|---|---|---|---|
| RISC Zero fixed v2 | BabyBear, `p = 2013265921` | `F_p[X]/(X^4 + 11)` | Fixed RISC Zero Poseidon2 and recursive receipt profile |
| Plonky3 W1 R1 | Goldilocks, `p = 18446744069414584321` | `F_p[X]/(X^2 - 7)` | Goldilocks Poseidon2, duplex challenger and two component proofs |
| Plonky3 tagged SHA3 R1 | The same Goldilocks field | The same quadratic extension | SHA3-512 framing and its own transcript and proof envelopes |

The two Goldilocks profiles may share finite field facts. They cannot inherit
each other's commitment, transcript, extraction or security assumptions. The
RISC Zero guest, final control ID, allowed control-tree root and verifier
parameter digest are distinct identities. A source inventory, a conditional
security estimator, and a complete non-interactive security theorem also have
different meanings.

## Exact finite algebra

The [field certificate reader](../../scripts/w1_stark_field_certificates.py)
reads the fixed RISC Zero snapshot and the actual retained `p3-goldilocks`
0.8.0 crate. It checks the latter against the current Cargo.lock checksum and
checks the selected archive members. No upstream source is executed.

The prime certificates use complete factorizations:

```text
2013265921 - 1 = 2^27 * 3 * 5
18446744069414584321 - 1 = 2^32 * 3 * 5 * 17 * 257 * 65537
```

For each prime factor `q` of `p - 1`, the reader verifies
`gcd(a^((p-1)/q) - 1, p) = 1`, as well as `a^(p-1) = 1 mod p`.
It independently checks the small prime factors by exact trial division.
The witnesses are 31 for BabyBear and 7 for Goldilocks. These are Lucas
primality certificates, not probabilistic primality tests.

Rabin's criterion checks both extension polynomials. For degrees 2 and 4,
the single prime divisor of the degree is 2. The reader checks
`X^(p^n) = X mod f` and `gcd(X^(p^(n/2)) - X, f) = 1`; it retains exact
Frobenius residues and a Bezout identity. Independent small-field polynomial
enumeration in the tests checks the implementation of this criterion.

The reader also checks all 28 BabyBear and 33 Goldilocks base-field root
entries for exact order and the successive squaring relation, plus all
BabyBear inverse-root entries. The source declarations for the tagged
components have trace logs 13 and 14 and blowup log 2, giving evaluation
logs 15 and 16. The ordinary Poseidon2 profile's complete accepted trace-size
set remains unproved. Root capacity is not trace reachability.

These results establish fixed parameter declarations and finite algebra. They
do not establish equivalence of compiled field arithmetic, full dependency
closure, AIR semantics, FRI/PCS soundness, round-by-round knowledge,
Fiat-Shamir, a quantum extractor, recursion or a lifetime error bound.

## Source-derived route checks

The [route reader](../../scripts/w1_stark_route_audit.py) derives the registry
again from fixed input snapshots, Rust declarations, dependency locks,
profile identities and retained evidence. Its source-set commitment is
independent of the registry's individual file pins. Different source bytes,
an unknown route, an additional qualification flag or a different
parameter tuple must be reviewed under a new explicit contract.

The checker keeps the ordinary P3 estimator's 127-bit field-size input and
128-bit hash-collision assumption in a conditional estimator section. Neither
is emitted as complete protocol security. A 512-bit digest and the tagged
profile's finite classical MMCS reduction similarly do not supply a quantum
extractor or a complete PCS/Fiat-Shamir result. The registry records the
reduction's conflict and common-context hypotheses.

All three routes retain unknown complete non-interactive, quantum and
lifetime security bits. Production, consensus admission, quantum extraction,
concrete primitive qualification and recursive composition remain false.
Exit zero means that the stated source and algebra checks passed with this
HOLD disposition. It is not an admission capability.

## Literature and historical progress

The [current literature review](../protocol/pon-nakamoto-v1/details/STARK_THREE_ROUTE_LITERATURE_20261109.md)
preserves the full prior manuscript-version comparison and the exact scope
of new access observations. The historical roster still contains 15 IDs;
one fixed-version correspondence sub-obligation was closed, 14 other
historical obligations remain, zero complete security obligations were
discharged, and all eight implementation interfaces remain open.

Both base fields have odd characteristic, and their extensions have the
same characteristic. This excludes the characteristic-two hypothesis of the
selected binary additive-domain results. It does not exclude other
Reed-Solomon results or establish soundness. In particular, the small-base-field
extension-code/list-size obligation remains explicitly open for every route.

## Required execution

The original `repository-truth` lane runs these checks exactly once, after
the retained current RISC Zero mapping. Its exact command-sequence checker
also requires the new commands; the original tests and refusal paths remain.

```bash
bash scripts/project-preflight.sh
python3 scripts/ci/test_w1_stark_field_certificates.py
python3 scripts/w1_stark_field_certificates.py
python3 scripts/ci/test_w1_stark_route_audit.py
python3 scripts/w1_stark_route_audit.py
```

The field reader accepts `--repo-root` and an optional create-only `--output`;
it never overwrites an existing output file. The route reader accepts
`--repository` and emits its report on standard output. Test results must be bound to
the exact source tested; earlier native proof or service measurements do not
transfer to this continuation. The remaining qualification work is the
actual relation/compiled semantics, concrete RBR and extraction hypotheses,
joint oracle and transcript reduction, recursion and lifetime composition,
and complete resource/service/production acceptance on each chosen profile.
