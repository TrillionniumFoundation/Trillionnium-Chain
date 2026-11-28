# Private Int257 factor preparation arithmetic

This bounded diagnostic mirrors the arithmetic preconditions and two
observable rank and comparison-count accessors from original
`PreparedModel::prepare_factors`. It neither returns nor substitutes the
original immutable prepared factors. No clock, statement, work proof,
inference, model adoption, portable cost claim, or application admission.

`f0` has a 40,460-byte immutable input and an 11-byte result. The third ABI
loan is scratch of any size and is never accessed.
First comes the unchanged 15,452-byte typed model: 32-byte version and
five 3×257 LE32 matrices. Three fixed 8336-byte expert slots follow. Each
has LE32 down rank; LE32 length of each of its three up rows; 3×8 LE32
up coefficients row-major; and 8×257 LE32 down coefficients row-major.
Inactive slots are not part of the typed factors and are not accessed.

After checking model coefficient bounds as the original constructor,
each expert checks its rank (1–8), then three up lengths exactly that
rank, then every active coefficient, then every B×A cell against the
corresponding original delta. It does not use caller-supplied flags or
modify inputs. The mathematical maximum for the absolute value of any
partial sum is `8 × 32767² = 8,589,410,312`, so original i64 checked
multiplication and summation cannot overflow in this validated domain.
No dense result is allocated.

As applicable, refusal 3 is model-coefficient range, 9 rank, 10 up
shape, 8 active factor coefficient range, and 11 delta mismatch. Private
framing 100 and short result loan 102 are not Rust statuses. All refusals
preserve the entire result; success writes LE64 `771 × sum(ranks)` and
the three U8 ranks, leaving any tail unchanged. This count is the
original position count, not elapsed runtime or admission evidence.

The test builds the frozen locked public Rust comparator and verifies
both stock HIA emitters against unchanged typed observations including
late cell mismatches, rank saturation and signed cancellation larger than
i32. The comparator calls new/prepare_factors/accessors only. Older
candidate sources and machine contracts remain independent.
