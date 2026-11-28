# Private held Cell row preparation

This bounded numeric projection begins at the held products/features
boundary of frozen Cell execute. It computes original expert selection,
selected logits, recurrent memory, and the remaining-step active
prefix. It cannot produce or verify the products, choose a user-visible
action, execute a task, sample, train, approve inputs, or mutate state.

One immutable input starts with CTRW0001, LE64 row count (1–64), LE64
remaining steps (any u64), and three LE i64 memory values in ±8,192.
Exactly that many 2,192-byte rows then follow, each containing:

- LE64 allowed-expert bit mask (bits 0 through 2; nonempty), and original
  input label (0–2);
- fifteen LE i64 product lanes: three class base products, three expert
  scores, and three consecutive three-class expert-delta groups;
- 257 LE i64 prepared features, with the first 256 each in ±8 and a
  maximum total absolute value of 1,024, and final fixed bias +8.

All products, including inactive rows and unselected lanes, are
bounded by the original ±67,368,952 before use. The minimum-score
sentinel for a disabled route is strictly less than this domain;
strict increases keep the lowest allowed route on a tie. Selected
logits add base, that expert's delta, and the three prior memory
values. Thus each is within ±134,746,096. Each memory update is
the exact Euclidean quotient in frozen Rust:
floor((3·memory + 8,192·sign(logit))/4). The unshifted numerator
is in ±32,768; shifting it by 32,768 before unsigned division and
then subtracting 8,192 preserves the original negative floor.

Only the initial min(row count, remaining steps) rows are projected.
The output prefix is LE64 active count, LE64 remaining steps, and
three LE i64 final memory values, followed by 2,096-byte trainer
records (selected route, input label, three logits, and all features).
The final section has 24 bytes of post-row memory per active row.
There is no trace for inactive rows. If initially stopped, the
40-byte prefix preserves memory and has zero active count.

The physical input stops at 140,336 bytes and output stops at 135,720.
The full shape and typed domain, including the suffix of inactive
rows, are checked before any output or capacity-dependent compute.
Status 100 is a private shape/domain refusal; 102 is short output;
both leave all output bytes untouched. In the bounded valid path the
remaining arithmetic cannot fail, so no secondary scratch is needed.
Any scratch supplied is left untouched. The output tail stays intact.

The offline comparator compiles the complete frozen execution.rs
module unchanged, with exact original declaration, canonical and
state-check functions, original protocol hash, and pinned tiny
Serde/SHA-256/Hex dependencies. It chooses inert deterministic
ArgmaxLowest, no tool names and no training. It observes the original
numeric decision source and output fields: route/logits, memory and
remaining steps, original typed label and original trace features.
The trainer record is a projection of those fields, not an externally
authorized observation or a claim of private ActiveRow access.
No live Node, owner, proof, data source, or storage is used.

    python3 -B -m unittest -v hia.tests.test_cell_held_rows
