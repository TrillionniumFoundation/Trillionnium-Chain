# W1 actual reuse observation V3

This is an explicit observation under the existing development plan. It does not
replace the V2 cost matrix, its default reader, the original acceptance profile,
W1 verification, consensus difficulty, task eligibility or any resource budget.

## Native campaign

The `pon_w1_reused_cost_v3` example requires the exact selector
`--actual-reuse-v3`; omitted or additional selectors fail before a campaign.
Its schema is `pon-w1-reused-producers-cost-v3`.

The original 13 actual producer implementations share one constructor/search
support module with V2. All nine V2 diagnostic input classes are retained,
including both one-zero rank-one orientations. There are eight samples per
class, four independent searches per supported preparation, the original
`7f` followed by 31 `ff` bytes target, seed zero, and at most 4,096 attempts per
search. Producer order rotates by sample. Every unsupported constructor is
observed once and recorded explicitly; no generic fallback replaces it.

Each supported cohort invokes its constructor exactly once and retains that
same object across all four searches. The V3 challenge domain binds task,
sample, independent-search index and nonce. Every attempt records its nonce,
challenge, trace, ticket, target outcome and complete-proof SHA-256, including
target misses and exhaustion. Every supported arm must produce the same entire
attempt stream and complete winning bytes. A full canonical winner is retained
once per independent search; it is never replaced with only a summary hash.

Actual setup, each complete search, the inclusive setup/search cohort, and each
production/reference full verification have separate thread CPU and monotonic
wall observations. Verification order rotates. Both native verifiers inspect
every actual arm's winner without a fact cache. Search timing includes trial
hashing, hex conversion, allocation and retention. Cohort timing ends before
JSON serialization, cross-arm comparisons and verifier calls. The verifier
interval covers the native verification call; product equality and output
serialization occur afterward. Diagnostic material construction has its own
measurement and is not silently charged again to each producer.

The fixed complete grid has 936 constructor cohorts and 1,888 searches. For
the retained fixed inputs when all searches win, there are 288 complete
canonical candidates and 3,776 production/reference verification calls.
Exhausted searches retain all 4,096 misses and create no fictitious candidate or
verifier result. The reader still requires nonzero completed winner verification
to accept a complete observation.

## Reader and qualification boundary

`scripts/pon_w1_reused_cost_reader_v3.py` reuses the independent V2 material
recipes and reconstructs A, B, C, complete proof bytes, challenge/ticket hashes,
arm applicability, exact coverage and timing nesting. It rejects missing arms,
missing searches, shortened exhaustion, replayed search identities, missing
complete winners or either verifier, unknown/zero CPU observations, repeated
setup inside a search, and claims that modeled setup division was observed.
Its synthetic unit fixtures do not compute W1 transcripts and are not native
cost evidence.

There is no modeled division by 1, 8 or 64 winners. The comparison sums actual
measurements from eight cohorts of four searches and selects one supplied
algorithm across the entire class cohort. It does not select a different winner
for each sample, extrapolate to other reuse horizons, or lower-bound undisclosed
adversarial implementations or hardware.

The reader does not replay W1 transcripts or authenticate native verdicts,
clocks, source, binary provenance, hardware independence or model-input
provenance. Every hardness, work-profile, resource-fairness, independent-hardware,
public-network, public-service and production-activation flag remains false.
Service admission, task/lease checks, M06 execution, storage, response handling
and queue contention remain outside this microbenchmark.

## Explicit release execution

Run the original preflight first. Use a complete committed clean checkout, the
actual native Rust 1.95.0 toolchain, a fresh receipt directory outside the
checkout, and an explicit `CARGO_TARGET_DIR`. The wrapper reuses the original
cost command owner and its 30-second identity, 900-second build, 300-second
campaign and five-second termination-grace limits. It rejects release compiler
or target overrides. The original fixed campaign parameters have no CLI knobs.

```sh
bash scripts/project-preflight.sh
python3 scripts/ci/run_w1_reused_cost_v3.py --arch x64 --local
```

For ARM use the same command with `--arch arm64` on actual native ARM Linux.
`--local` remains a local preflight context and cannot satisfy a hosted
cross-architecture comparison. The wrapper verifies the actual compiler and
ELF, retains original stdout/stderr and failure status, hashes the measured
binary before and after, and checks complete source bytes before and after.
It does not install or change a toolchain, dependency lockfile or host budget.

An isolated direct-rustc or test-profile diagnostic can establish executable
correctness of a candidate, but must be labeled separately from this default
release command. Such a diagnostic cannot replace its source, build, retention
and native-architecture gates.
