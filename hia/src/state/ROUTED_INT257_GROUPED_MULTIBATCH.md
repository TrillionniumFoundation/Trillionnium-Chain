# Private one-model Int257 Grouped multi-batch

One immutable input contains the unchanged [Grouped](ROUTED_INT257_GROUPED.md)
model/total-width/row layout followed by a 20-byte directory: LE32 child
count, then four LE32 child row counts with zero unused positions. Child
count is 1–4 and active lengths sum to the total. Every child must have a
row, and at most 64 rows may appear across the whole call. No clock, work
claim, tenancy policy, production routing or trust token is involved.

The kernel first validates complete wire extent, model, then child feature
values in input order. It routes once per real row, then uses the same
published expert-local feature-major gather and contraction on the shared
frame. There is no extra padded numerical work or Direct/Factored fallback.
Adapting the existing scatter only redirects row writes to a bounded private
scratch range; the already published one-batch source and ELF stay unchanged.

The scratch loan requires 67,536 + 50×total bytes, preserving the original
grouped workspace and adding the staged logit/route/prediction/router rows.
After the entire computation, publish four LE64 segment lengths (zero
unused) followed by each unchanged Grouped Product. The stable group indices
are child-relative. Output requires 32 + 48×children + 51×total bytes.
Maximum input/output/scratch are 81,236/3,488/70,736 bytes. All validation
and capacity refusals leave each loan unchanged, including a late invalid
child. The result and scratch tails beyond the active extents are untouched.

The exact differential runs the genuine frozen public Rust grouped function
sequentially with the same immutable model and ordinary synthetic rows per
child; Rust timings are ignored. Both stock HIA emitters compare each full
Product, actual shared scratch gather/accumulation and refusal atomicity.
