# RISC Zero: two named exceptional DEEP sets

This is a finite algebra result for the fixed RISC Zero upstream source at
`8c215e2f4ccdd935f0517bf05d90f1ae032840a9`. It does not close any complete
QROM, FRI, knowledge-soundness, recursive-composition or lifetime obligation.

Let `p = 2013265921`, `K = F_(p^4)`, `N = 2^k`, `0 <= k <= 24`, and let
`D <= F_p^*` be the subgroup of order `4N`. The fixed SDK verifier uses query
points `x` in `D`, the trace root `omega_N`, and these rational denominators:

- products of `x - z*omega_N^(-b)` for tap backs `b`;
- `x - z^4` for the quotient check.

It separately evaluates the trace zerofier `(3z)^N - 1`.

Define `E_pole` by existence of a zero denominator at any point `x in D`.
Every tap factor has a zero only when `z in D`, and, for every fixed tap back,
the union over all `x in D` is exactly `D`: multiplication by a power of
`omega_N` permutes `D`. The quotient-check event is `z^4 in D`, equivalently
`z^(16N) = 1`. Since `16N` divides `|K^*|`, this last set has exactly `16N`
elements. It contains `D`, hence `|E_pole| = 16N`.

Define the separate event `E_zero` by `(3z)^N = 1`. It is the coset
`3^(-1)*H_N` and has exactly `N` elements. A coset point satisfies
`z^(16N) = 3^(-16N)`, so this coset is entirely contained in `E_pole` if
`3^(16N) = 1`, and entirely disjoint otherwise. Exact modular exponentiation
checks the latter case for every displayed `k`. Therefore:

`|E_pole union E_zero| = 17N`.

If `z` is uniform on `K` conditional on the preceding transcript, the
probabilities are exactly `16N/p^4`, `N/p^4` and `17N/p^4`. The helper retains
these as rational numbers. This is a conditional field-sampling calculation;
the fixed stateful Poseidon2 sponge does not acquire that distributional
guarantee from this counting argument. In particular, it cannot simply be
added to a QROM budget without the missing oracle and transcript reduction.

The event is global over the evaluation domain and does not rely on the
distribution of the later fifty sampled query indices. It may over-cover the
event of a sampled denominator vanishing. The separate zerofier event is not
asserted to cause an actual verification error or soundness failure. An upper
bound on an exceptional set is not a lower bound on a forgery probability and
does not establish a security-bit ceiling.

The parser-log table does not establish that all those logs are reachable by
accepted recursion programs. The identity of the generated recursive verifier,
root-table and extension-field arithmetic equivalence, interpolation collisions,
other DEEP exceptions, bad-event coverage, and all remaining soundness events
need their own evidence. The separate fixed field certificate already checks
the declared root orders and extension irreducibility; the new helper does not
replace those checks or rerun native proof verification.

The tests independently enumerate the two events in `F_5[T]/(T^4-2)` and
`F_13[T]/(T^4-2)`, checking irreducibility by all monic degree-one and degree-two
divisors first. The enumeration includes both the disjoint-coset and contained-
coset cases. Other controls retain the exact source snapshot, reject mutated
bytes, missing or symlinked snapshots, nonexistent base domains and numeric
type aliases. No proof, binary or production entry is modified.
