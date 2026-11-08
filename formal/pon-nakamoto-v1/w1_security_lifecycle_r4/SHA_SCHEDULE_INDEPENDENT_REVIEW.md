# Independent static review of public SHA schedule projection

Reviewed source: `sha_schedule_air.rs`, SHA-256
`88557607225e402b6f16ec7edffb7c8b90ddfe14cc7e87a2640042a205011a64`.
This is the R4 backend proposal file, not an assertion about latest main.
This static review did not generate proofs or run the backend's Rust tests or
performance campaign. A later, separate lifecycle probe verified retained
complete proofs at the committed source; its scope and receipts are in README.
The review found no blocking mathematical or public-input binding defect in
this exact source. This conclusion concerns the relation transformation only.

## Checked argument

The public statement parser and SHA message planner differ from the baseline
only by one final blank line in this local review snapshot. The reviewed
`public.rs` hashes to `ae08f54eda74f1ffc7f3ae4c10185d101e10b511bf9ce32a0bc2fe65a3e9dd3d`
and `sha_plan.rs` to `5a629d7bcc630ebe3de2f86cb5c6877572d980e8563431ee9c0d128ce1477377`.
The independently constructed preprocessing obtains sixteen big-endian words
from each canonical padded block, expands the standard 64-word recurrence with
u32 wrapping addition, and stores each result as its low and high u16 limbs.
Thus the 128 schedule entries are constants in `[0, 65535]`. They are not
unconstrained field variables supplied by a prover.

Given a satisfying new row, insert the canonical Boolean decomposition of
these 64 words and canonical small-sigma / schedule-sum auxiliaries. These
inserted columns satisfy the removed official schedule and range constraints.
Their packed words equal the public operands used in all retained compression
rounds. This constructs a satisfying original row without changing any retained
witness entry. In particular, it does not assume the retained intermediate
limbs are uniquely represented: any representation permitted by their unchanged
original constraints remains permitted on both sides of the transformation.

The two large-sigma helpers use the same rotations, little-endian bit indices,
Boolean XOR3 expression and high-to-low Horner packing as the official helper
specialized to its two large-sigma cases. Nine remaining helpers were compared
after removing line comments and whitespace and normalizing the row type name:
initial-state binding, finalization, word packing, packed/bit equality, add3,
the two expression-output add helpers, Ch and Maj. All nine have identical
normalized tokens. The exact comparison receipt is in
[sha_schedule_static_review.json](artifacts/sha_schedule_static_review.json).

The new wrapper preserves the input-state bit binding, Boolean checks for all
state-chain and output bits, all 64 compression rounds, IV selector, selected
cross-block links and final digest equality. The next-row dependency is exactly
the first sixteen input-state limbs. Padding rows have a zero block, hence a
zero expanded schedule; their IV is fixed and their chain/output selectors are
zero, so they do not add a new message statement or feed a real message.

The resulting soundness direction is `new relation -> old relation`. Honest
original executions project into the new layout. This argument does not itself
prove the original SHA AIR, polynomial commitment, Merkle binding, Fiat–Shamir
compiler or their composition secure. The source declares component 5 and a
fresh envelope; the R3 lifecycle measurements for components 1 and 4 do not
automatically measure component 5.

## Upstream source pin

The official `p3-sha256-air` 0.8.0 archive was downloaded from
<https://static.crates.io/crates/p3-sha256-air/p3-sha256-air-0.8.0.crate>
and matched the retained Cargo.lock checksum
`84c0b9594dc05f5956b9dc64e43be04ee2a33b6dd531a51935303d963643018c`.
Its `src/air.rs`, `src/generation.rs` and `src/columns.rs` hashes respectively are
`42a079d9cc36a10162e42c73f6b816bb97ae67aa7f998be2a89f789d1882f88d`,
`b9bd18aa6325b39bf2b60511069f6373b5629f25f497c23da6adbdf3d7981c6f`, and
`1b9f9b24b420958497a5acf868fa7ab93df4de4996ab353f40dc9a0489f0ffbc`.

Qualification remains **HOLD_NO_GO**.

## Committed-source reconciliation

Backend commit `eb944645cc3e30af5955edf9dbbcb43488fa38c1` contains the same
`sha_schedule_air.rs` hash reviewed above. Its `public.rs` and `sha_plan.rs` are
byte-identical to the baseline, with hashes
`593d1f25a53959dd2b7155f0bd6b7199c3e77bb1796ff291badc4996444f4a29` and
`d1db8a58108702548ce801d6c8b558d49f975f72b6461d2d59be7d92c6b3c0d3`.
The extra terminal blank line belonged only to the local review snapshot; it
was not a committed parser or planner change. The source contract pins both
historical revisions independently.
