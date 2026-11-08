# Independent review of the 516-column dot8 AIR

This is a reconstructed copy of the mathematical review after scratch loss. It describes the tested `arith_air.rs` with SHA-256 `58b449817db1b1f9575d9ce64651469ecfe6d6e4e165db26be2ecef5bada0882`. The reconstruction is not a new test run.

Let `q = 2^32 - 5` and `P = 2^64 - 2^32 + 1`. Public inputs `a_i`, `b_i`, `start` and `goal` are integers in `[0,q)`. For each of eight products the witness provides 32 Boolean bits for `k_i` and 32 Boolean bits for `r_i`; it also provides four Boolean bits for `K`. Reconstruct them with powers of two in Goldilocks. Enforce the following polynomial equations in Goldilocks:

`a_i b_i = q k_i + r_i` for every `i`;

`sum_i r_i + start = goal + q K`.

Every one of the 516 witness coordinates must satisfy `b(b-1)=0`. No host `% q` check substitutes for these constraints.

## Product equations lift to integer equations

The left side is at most `(q-1)^2 = 2^64 - 12*2^32 + 36 < P`.

The right side is at most

`q*(2^32-1) + (2^32-1) = 2^64 - 5*2^32 + 4 < P`.

Both sides are nonnegative integers strictly below P. Equality modulo P is therefore exact integer equality. Each `r_i` need only be a 32-bit residue; it need not be canonical modulo q. This is safe because the equation still implies `r_i = a_i b_i (mod q)`.

## Sum equation lifts to an integer equation

The left side is at most `8*(2^32-1) + (q-1) = 9*2^32 - 14 < P`.

The right side is at most `(q-1) + 15*q = 16*q - 1 < P`.

Again, equality modulo P implies exact integer equality. Reducing it modulo q establishes the intended dot8 relation. Since the public goal is canonical, its residue is unique.

This avoids a false whole-dot check in the proof field: the eight large native products are never added as one potentially wrapping Goldilocks integer. Each product is lifted separately, and only its bounded 32-bit residue enters the sum equation.

## Completeness and the sum quotient

The honest generator uses ordinary integer quotient/remainder for each product, so its residues are in `[0,q)` and its valid sum quotient is at most eight. Four bits therefore cover every honest witness.

However, the constraints intentionally admit noncanonical 32-bit intermediate residues. Such a valid witness can have `K = 9`. For all eight products take

`a = q-1, b = q-4, k = q-6, r = q+4 = 2^32-1`.

Then `a*b = q*k + r` exactly. Take `start = q-1` and `goal = 31`. The sum is `9*q + 31`, so `K = 9` is valid. The four-bit encoding is correct; stating that every admissible witness has `K <= 8` would be incorrect. No canonical-remainder constraint is required for soundness.

## Addition and padding

An addition row uses public multipliers one for the two addends, zeros elsewhere, start zero and the intended canonical goal. The same equations prove addition modulo q. All-zero public rows and all-zero witnesses provide valid padding. Arithmetic rows do not use next-row constraints; the public statement factory supplies predecessor values explicitly and consistently.

## Coverage reviewed

The canonical factory generates 8,192 E/F dot8 rows, 8,192 additions, 32,768 noisy prefix dot8 rows and 32,768 AB prefix dot8 rows: 81,920 real rows, padded to 131,072. For AB, the first seven groups end at public intermediate claims and the final group ends at raw C. For the noisy product, all eight groups use the original byte-ordered prefix cells. This source wiring was independently inspected, but still relies on the runner rebuilding the canonical preprocessing table from the shared public encoding and independent Expected.

The arithmetic AIR's local integer lifting is exact. The noninteractive soundness of its polynomial commitment proof remains a separate cryptographic obligation.
