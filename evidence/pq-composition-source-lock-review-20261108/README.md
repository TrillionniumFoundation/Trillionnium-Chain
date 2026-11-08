# PQ composition source-lock review evidence

Status: **HOLD**. The reviewed native source is `0f0592ace4b08a1d39e1ffad31beee76ddc4fd66`.

- [review.json](review.json) records the 15/44 exact path mappings, full diffs,
  original/current hashes and per-path internal review decisions.
- [Original lifetime lock](original-lifetime-source-lock.json),
  [original lifetime budget](original-lifetime-budget.json), and
  [original authority register](original-authority-effect-register.json) retain
  the pre-update declarations.
- [Lifetime refusal](before-update-lifetime.json) and
  [authority refusal](before-update-effect.json) record actual exit 2 before
  updating the locks; their same-prefix stdout/stderr files are retained.
- [Static references](static-owner-reference-observation.json) are limited
  literal-name observations, not a call graph or runtime reachability proof.
- [R1 full-source timeout](r1-prior-full-source-timeout.json) retains the
  independent administrative collection attempt that timed out with exit 124.
  Its collector text and incomplete raw source-check streams remain separate.
  It supplies no successful full-repository identity receipt.

The subsequent mapping review compares immutable Git blobs with actual
descriptor-bound reads of every declared path. It makes no claim of a completed
full-repository source scan or native tests. All original full-source and native
gates remain required in the final composition campaign. Historical evidence in
other directories is not edited. Current-source focused test logs are retained
outside the source tree so that their execution does not mutate their source.
