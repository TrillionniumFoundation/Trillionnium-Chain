# Selected nonce banks and global input compilation — successor R4

**Two substantive additions are implemented and verified.** A lawful producer can retain previously paid nonce selectors and reorder their continuations; a finite counterexample proves that the old immediate-decision online lower certificate does not cover this action. Separately, the original real task inputs admit an exact global representation using 1,316 retained field bytes and no field multiplication for each acquired useful local product after fully charged recognition/compilation.

The starting published commit is `cc836dfc13ef0006eb0878abd8cb5eca9a76bec0`. The round-3 package is unchanged. This is a new research namespace, intended for `formal/pon-nakamoto-v1/selected_nonce_bank_research/`. No production implementation, admission setting, development plan, resource-pressure experiment, push, merge or qualification state is changed by this subtask.

The verifier is the **complete original selected-local-event native relation**. It is not the cumulative W1 verifier, a STARK, or production Node. The universal cheapest-lawful physical-work gate remains open.

## 1. A strictly larger legal strategy space

The unchanged relation binds a coordinate to each context/nonce seed, but does not require continuing immediately after inspecting that coordinate. A producer can therefore:

1. Pay for a finite set of seed and coordinate computations.
2. Retain their nonce records and group them by coordinate.
3. Compute a useful product once, process that bucket's candidates, then reuse the single useful-result slot for the next bucket.
4. Stop at a valid ticket, while still charging every prepaid gate and every failed attempt.

The [theorem](THEOREMS.md) gives an exact optimum for all scheduling, prefetch and eviction policies **within an explicitly priced, already purchased bank model** with independent Bernoulli tickets. Buckets are ordered by `u_i / (1-(1-p)^n_i)`. With equal acquisition prices, this means descending occupancy. One useful-result slot is sufficient; the separate nonce bank is charged and stored.

A strict finite example shows why the previous online result cannot be promoted to this larger class:

| Same auxiliary-model requirement | Cost |
|---|---:|
| Two coordinates, at most three draws, `p=1/2`, one result slot, prices gate 1 / continuation 1 / useful result 100 | All prices are positive |
| Any old-class policy with success at least `3/4` | Expected cost at least **109.625** |
| Prepay three selectors, attempt two in the most frequent bucket | Success exactly `3/4`, expected cost **104.5** |
| Strict separation | **5.125** |

The old-class bound uses the exact penalty value `V_202=1281/8` and weak duality. A separate identity-state Bellman implementation agrees; all selector/ticket outcomes of the bank construction are enumerated. The previous theorem remains valid for its original action set. No actual SHA probability is inferred from this example.

## 2. A smaller recognized-input representation

The original A and B bytes have a stronger property than separate affine blocks: their entries are affine in all four block/local indices. The compiler checks every canonical field element before accepting this structure. It also rejects a modification that preserves individual block affinity while breaking the global representation.

| Achieved useful-product implementation | Recognition/compile field work | Retained field payload | Work per acquired 8×8 useful result |
|---|---:|---:|---:|
| Round-3 arbitrary affine blocks | 448 M + 8,512 A; 8,192 equality checks | 2,048 B | 5 M + 71 A |
| New globally affine family | **26 M + 8,533 A; 8,192 equality checks** | **1,316 B** | **0 M + 73 A** |

M counts field multiplications and A counts field additions/subtractions; neither is a unit of physical time or energy. Canonical field checks, input scans, table access, source matrices, Merkle storage and interpreter memory are additional recorded categories. The new family is narrower. It does not silently substitute a cheap approximation for arbitrary task input.

The formula is checked against dense multiplication for all 512 coordinates on each of four input pairs: the actual original fixture, a nontrivial wrapping coefficient family, a zero-input case and a constant-input case. Thus the tests cover **2,048 complete local products**. Noncanonical values, a last-word corruption, invalid shapes and invalid coordinates are also refused.

This reduces the retained representation and setup cost without storing all 512 complete useful products. It does not make the nonce-dependent noisy part free: the implemented noisy continuation still uses `1536 M + 1472 A` per attempted nonce.

## 3. Fixed new nonce interval, actual SHA and complete witness bytes

[EXPERIMENT_PLAN.json](EXPERIMENT_PLAN.json) fixed nonce interval **512–1023 inclusive**, the original input/context/target bytes, bucket ordering, tie rules and first-success stop rule before any ticket in this run. Its SHA-256 is:

`d3b8f939533631e58d8b8bcf1fea8e9b7e167532c4d58325552e58f298aea2cf`

Each bank contains 512 real paid seed/selector records over **317 distinct coordinates**. The exact serialized bank and order were sealed before the first noisy continuation. The ordering function receives no event, noise, ticket or winner position.

### Whole mining-campaign observations

All field work below includes input recognition/compilation and all failing candidates. Every strategy found the same valid nonce **561**.

| Strategy | Paid gates | Attempted tickets | Useful-result acquisitions | Whole field M | Whole field A | Separate prefix-replay compressions |
|---|---:|---:|---:|---:|---:|---:|
| Dense, ascending nonce | 50 | 50 | 50 | 102,400 | 96,000 | 3,254 |
| Dense, ascending nonce, retain first result | 50 | 50 | 50 | 102,400 | 96,000 | 3,254 |
| Dense, prepaid bank, one result slot | **512** | **7** | **2** | **11,776** | **11,200** | **2,748** |
| Global compiler, ascending nonce | 50 | 50 | 50 | 76,826 | 85,783 | 3,254 |
| Global compiler, prepaid bank, one result slot | **512** | **7** | **2** | **10,778** | **18,983** | **2,748** |

The bank paid **505 selectors that it never continued**. Its seven attempts include six losses. The single result cache has five hits, two writes and one eviction. The complete bank account also records 512 dictionary accesses/appends, 2,215 bucket-order comparisons and 195 within-bucket nonce comparisons.

The logical selector records occupy **22,016 bytes**, and the explicit serialized order occupies **4,096 bytes**. These are separate from the 256-byte useful result, 3-byte coordinate key, source matrices, trees, compiled state and SHA-prefix cache. They are not claimed to equal total Python memory. The retained producer object graphs after bank construction measured 512,379 bytes for dense and 524,395 bytes for the global compiler on this interpreter; these are neither RSS nor peaks or production resource limits.

The live producer uses instrumented ordinary `hashlib`; it performs **7,878 whole-message compression blocks for the bank** and **5,946 for the sequential run**. The last table column comes from a **separate executable bounded-prefix replay** of exactly those messages, with every digest checked against `hashlib`. It uses the earlier five-prefix/two-output cache algorithm and 981 logical cache bytes. It does not relabel the live producer's code or observed timing as an optimized SHA implementation.

Every observed sampled row used one digest. The actual sampler call counts are retained, and its original 128-digest rejection limit remains unchanged. The conditional `904 + 3G + 44T` compression expression describes the observed one-digest schedule; it is not a universal sampler-tail or SHA lower bound. SHA block semantics are checked against the primary [NIST FIPS 180-4 specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

This is one fixed deterministic campaign. The independent-ticket theorem is not applied to concrete SHA, and no distributional confidence interval, broad performance gain, or physical lower bound follows from this table. The price tradeoffs remain visible: the bank stores and evaluates more selectors, and the global compiler spends extra recognition/addition work in exchange for fewer multiplications and a smaller compiled representation.

## 4. Independent audit and fresh full native acceptance

All **164 actually attempted strategy witnesses** match the complete unmodified producer bytes. The separately billed full-range audit evaluated all 512 nonces and also checked each against the frozen original producer by witness digest; its source records the additional complete-byte comparisons for every attempted strategy witness. This audit is recorded after the strategies and is not read as mining advice.

The 13 actual target-qualified nonces are:

`561, 605, 644, 654, 764, 770, 775, 790, 835, 863, 918, 946, 998`.

Fresh native verification produced **18 accepted invocations**: all 13 distinct accepted witness bytes and each of the five strategy winner files. Each native acceptance executed 2,048 scalar field multiplications, confirming that both the noisy and useful product checks were reached. Two new mutations of the actual winner were rejected with `SELECTED_COORD` and `MERKLE`, respectively. The exact stdout, stderr, witness files, exit codes, native counters and SHA-256 pins are retained in [native_acceptance](results/native_acceptance/result.json).

The native binary was rebuilt from the exact recovered original Rust relation/harness sources and original `Cargo.lock`, without edits. The executable SHA-256 is:

`0942ffba3591a20bd3822dc67a4755304aa8a017357ee74aaf559c676d2515ad`.

The observed Git HEAD is the published baseline; the new research directory was uncommitted at build/run time. The build-source binding is the explicit Rust/Cargo source hashes and compiler/dependency records, not a claim that the baseline commit already contained this new directory.

Native checks passed: locked/offline release build, **8 original Rust tests**, strict Clippy, formatting and exact dependency-tree capture. The new Python suite contains **17 passing tests**, including 243 independent scheduling/cache-state comparisons. The latter are research-model checks, not inherited production qualification.

## 5. Reproduction and evidence

Read the repository's `AGENTS.md` and run `bash scripts/project-preflight.sh` before builds or edits in a checkout. A detached-head preflight initially refused the isolated checkout; the authorized research branch passed before any edits/builds. That refusal is preserved in [preflight evidence](evidence/preflight.txt).

To check the delivered observations without rewriting them:

```sh
python3 -m unittest -v test_research.py
python3 verify_evidence.py
sha256sum -c SHA256SUMS
```

For a fresh campaign, use a separate copy or move the existing `results/` to a new evidence namespace first; `run_campaign.py` refuses to overwrite strategy directories. The same fixed plan is reproducible, but the present winner positions must not be treated as previously unknown after publication.

```sh
python3 run_campaign.py
python3 prepare_native_inputs.py
cd native_selected
cargo build --release --locked --offline
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
cargo fmt --check
cd ..
python3 run_native.py --expected-binary-sha256 ACTUAL_FRESH_BINARY_SHA256
```

A fresh build may have a different binary hash due to compiler/environment changes; it must record its own hash and source/build provenance. `run_native.py` refuses an unexpected binary or changed source pin. Its input list `results/native_expected_rows.json` is the target-qualified subset of the complete audit candidates; [verify_evidence.py](verify_evidence.py) checks that binding.

The copied `upstream/` modules are a byte-frozen dependency subset used by the listed entry points. Their historical standalone drivers are not this successor's reproduction commands.

Primary files:

| File | Role |
|---|---|
| [THEOREMS.md](THEOREMS.md) | Explicit class quantifiers, proof, strict separation, input/compiler derivation and limits |
| [research_core.py](research_core.py) | Exact input recognition, compiler, gated continuation and bank ordering |
| [bank_policy.py](bank_policy.py) | Exact rational optimum, independent interleaving/eviction search and old-class check |
| [run_campaign.py](run_campaign.py) | Predeclared SHA experiment and separately billed audit |
| [run_native.py](run_native.py) | Frozen full native relation execution and controls |
| [SOURCE_PINS.json](SOURCE_PINS.json) | Original-source and recovery pins |
| [campaign_result.json](results/campaign_result.json) | Whole setup/candidate counts, payload and phase observations |
| [policy_result.json](results/policy_result.json) | Exact rational counterexample and auxiliary example |
| [native result](results/native_acceptance/result.json) | Fresh native outcomes with source/binary binding |
| [checks_summary.json](checks_summary.json) | New test and artifact-integrity results |

## Remaining physical-work boundary

The new results remove two specific blind spots: deferred nonce records and a smaller global input representation. They do not close the class of all legal algorithms or all preprocessing/advice. The bank theorem prices complete acquisitions and continuations as fixed oracles; actual algorithms can share intermediate arithmetic, change representations, buy selectors adaptively, pipeline SHA, preprocess across contexts or exploit other lawful input structure. Concrete SHA ticket outcomes are deterministic, and a field-operation count is not a portable lower bound on seconds, energy, area or memory traffic. The complete universal physical-work claim therefore remains unproved.
