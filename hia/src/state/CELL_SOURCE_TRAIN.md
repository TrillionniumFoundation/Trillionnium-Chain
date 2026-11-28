# One-call held Cell source and numeric training

The private `CCT00001` call reduces synthetic held hex records directly
to frozen Cell numeric training. The caller supplies old model values,
the prior optimizer and memory, masks, labels, and raw hex. It cannot
supply computed features, dots, ActiveRows, gradients, loss, a workspace
offset, work proof, state commitment, or identity. This is not a Node
caller, source ingestion, action/inference route, proof, or adoption.

The first 74,128 bytes match the private CTRX field layout (new magic,
1–64 submitted rows, zero reserved word, optimizer presence/step,
learning/momentum/mask and coefficient planes, remaining steps, prior
memory). Three LE64 router rows of 257 signed coefficients extend to
80,296; the next 257 bytes are the shared canonical boolean mask (bias
true), then seven zero bytes. From 80,560 every row is exactly three LE64
words (even hex width 2–8,192, nonempty three-bit expert mask, label
0–2) followed immediately by its lower-hex bytes. No trailing bytes.
Each model coefficient is within ±32,767. Max immutable loan 606,384.

Each of the submitted rows, including the inactive suffix, goes
through the same exact raw UTF-8 validation, ASCII normalization,
signed token SHA-256 and clipping/mask semantics as CSP. One bounded
private parser holds only the actual source span; it never remaps a
mutable pointer as an immutable loan. After every submitted row is
decoded, the signed dot reads coefficients from the original immutable
loan and reads the true derived masked features through a typed mutable
argument. It fills all fifteen products in original base/router/delta
order; no grouped/padded tensor or caller partial product is accepted.
Per dot |sum| ≤ 257 × 8 × 32,767 = 67,368,952. The first 256 masked
features also retain the source-derived L1 bound 1,024 and bias 8.

Route ties, recurrence and active-prefix training use the existing
signed arithmetic over internally built row records. The row readers
use scratch loads instead of the public CTRW immutable-row accessors.
The held update reads model/moment/mask values only from their original
immutable loan offsets. The exact old `train_backward` reads active
rows only from its existing fixed high arena range; no caller-provided
offset can reach this decision. Old CSP, all-15, CTRW and CTRX published
entries remain independent and unchanged.

The public result is exactly the earlier CTRX report format and size
(154,280 + 104c bytes for c active; cap 160,936). The required private
arena is 933,376 bytes. Each consecutive interval has one owner:

- [0,19712) is each row's CSP workspace; it expires after all
  source rows complete. [0,160936) is then the numeric report including
  gradients, updates, and memory trace.
- [262144,396288) holds up to 64 complete 2,096-byte active rows,
  produced only by the native recurrence and consumed by backward.
- [396288,536576) holds the 64 possible 2,192-byte source/product
  records: expert mask/label, all 15 dots, masked features.
- [536576,798720) holds 4,096 normalized bytes per row at most, with
  each untouched tail. [798720,930304) holds 2,056 bytes of unmasked
  features per row. [930304,933376) holds 48 bytes of original raw
  SHA/count/length per row for exact intermediate readback.

Status 100 is an invalid private frame/domain, 101 invalid shared
mask or its padding; 10/11 correspond to original hex/UTF-8 refusal.
102 is inadequate scratch or public output, 103 an unexpected checked
hash failure, 201 step overflow, 202 defensive moment bound, and 203
the original trained weight bound. After structural fixed input guards
and scratch capacity, every source is validated before any product;
the computed all-row product stage comes before the active-step check.
With adequate scratch, arithmetic refusal precedes public capacity.
No invalid call writes public output. A late refusal may leave
previously validated private source/row/intermediate scratch bytes.
Each loan extent stays within the existing stock one-MiB bound.

The archived differential embeds the exact original full `source.rs`
and `execution.rs`, and the original `work.rs` weight ordering and
literal signed dot expression, using a bounded locked Rust crate.
It does not compile or invoke the surrounding work verification or
prove path. Both real stock machines compare every per-row source and
numeric observation plus the final numeric projection, including one
64-row case that simultaneously reaches 4,096 normalized bytes and
1,024 admitted tokens per row.

    python3 -B -m unittest -v hia.tests.test_cell_source_train

A separate test installs the unchanged, import- and relocation-free
stock Selfhost CCT object into the source-pinned x86-64 Linux Rust
fixture. The Rust caller borrows the very typed snippet strings, model,
policy and prior values used by the unchanged original computation.
It rebuilds the native byte loan from those held values and compares
the original source-stage, product, active-row and report bytes and
refusal statuses before publishing each observation. Only three
disjoint bounded byte spans reach the native symbol; no pointer to a
Rust model or source value is given to native code. The test verifies
the linked executable's exact unmodified .text at `f0` before and
after execution. This is a private static qualification, not a runtime
handoff or an additional production owner. The independent stock dual
tests remain unchanged.

    python3 -B -m unittest -v hia.tests.test_cell_source_train_held_link
