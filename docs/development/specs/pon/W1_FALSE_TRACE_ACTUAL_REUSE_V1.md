# W1 false-trace actual reuse observation V1

This is an explicit adversarial cost observation under the existing development
plan. The original V2 cost matrix, V3 legal-producer reuse campaign, acceptance
profile, difficulty, task eligibility and receiver budgets remain unchanged.
The default production verifier remains unchanged. A smaller observed CPU cost
is not an adversarial lower bound, a proof of work hardness or release approval.

## Missing comparison addressed

The V2 false-trace arm constructs a public PNW1 prefix for each search and obtains
its challenge from the canonical legal candidate used by that diagnostic. The
V3 actual-reuse campaign already measures 13 implemented **legal** strategies
with one preparation across four independent searches. It does not measure a
false-trace attacker actually retaining one public prefix across multiple fresh
challenges. Dividing a historical setup measurement by four would not establish
that execution occurred.

The new `pon_w1_false_trace_reuse_v1` example requires the exact selector
`--false-trace-actual-reuse-v1`. It never invokes a legal producer or acquires a
valid proof. Its challenge domain binds the public task, seed zero, sample and
independent-search index. This synthetic challenge is a primitive experiment;
it does not establish live parent, beneficiary, transaction, demand or lease
binding in the node admission path.

For each of the original nine diagnostic material classes and eight samples,
the campaign validates and serializes A and B exactly once into a public PNW1
prefix. The claimed product and trace are initially zero. That same immutable
prefix remains alive for four independent searches. Each search uses the
existing `public-v3-from-zero-v1` hash recipe to choose claimed traces until the
first ticket satisfies the original `7f` followed by 31 `ff` bytes target, or all
4,096 attempts have been made. A successful hash ticket is an **unverified
candidate**, never valid work. The winner clones the public prefix and inserts
the claimed trace. No product is computed by the attacker.

Every attempt, including each miss, retains its nonce, challenge, trace, ticket
and target outcome. Every successful search retains the complete 49,188-byte
proof. The original production, scalar reference, existing limb and experimental
column-limb verifiers each receive every candidate; their call order rotates by
sample and search. All native outcomes are emitted, even an unexpected acceptance
or an early rejection. The reader preserves those as semantic alerts.

The fixed grid contains 72 real prefix preparations and 288 independent
searches. If every fixed search finds a ticket, it contains 288 complete
candidates and 1,152 full native verification calls. There is no cache warmup,
verified-work cache, sampled transcript or shortened relation check.

## Cost boundaries

Thread CPU and monotonic wall time are observed for each actual prefix setup,
complete search, inclusive four-search cohort, and native verifier call. Search
time includes challenge derivation, **all** trace/ticket hash attempts, allocation
and hex retention of each attempt, plus the winning 49,188-byte buffer clone.
Cohort timing ends before JSON output, evidence hashing or verifier execution.
The separate material construction measurement is not silently charged once
per receiver call. Product comparison and verdict formatting are outside the
native verification-call interval. The attacker cohort interval also excludes
subsequent destruction of the retained buffers, JSONL evidence output and network
sending. The word full refers to the entire recorded setup/search interval, not
to the CPU of the complete process or a network transmission lifecycle.

For each class and each verifier path the reader reports:

\[
\frac{\sum \text{native rejection CPU across the observed candidates}}
     {\sum \text{inclusive actual prefix-setup-plus-four-search CPU}}.
\]

The denominator retains all eight cohorts, all failed hash attempts, real prefix
preparation and buffer construction. It is not the time for only the winning
hash attempt, a per-sample minimum across algorithms, or a modeled setup division.
If a verifier produces any unexpected outcome, its rejection ratio is null and
the actual outcome remains visible. An exhausted search retains all attempts
and costs, without inventing a candidate or verifier call.

This is the cost of the supplied evidence-producing attack implementation.
Hex conversion and trace retention are not necessary costs of an attacker.
SHA-256 prefix/midstate reuse, retaining a prefix across a longer horizon, avoiding
capture allocations, other algorithms and other hardware may cost less. The
campaign therefore cannot upper-bound public-network amplification or establish
the cheapest adversary's cost. It measures neither packet/signature parsing,
public eligibility, concurrency, queues, response bandwidth, fanout nor honest
business confirmation. These remain independent acceptance objects.

## Strict capture reader

`scripts/pon_w1_false_trace_reuse_reader_v1.py` requires the explicit schema
`pon-w1-false-trace-actual-reuse-v1`. It independently reconstructs the nine
material recipes, task/challenge/trace/ticket hashes, zero-product public prefix,
complete winning bytes, first-hit stopping rule, nonce coverage, fixed bounds,
actual setup count, four-search reuse, verifier rotation and timing nesting.
It rejects missing/duplicate cases, omitted misses, hidden extra setup,
shortened exhaustion, zero or unknown CPU, substituted products, missing complete
proofs or any omitted verifier. Input lines, bytes and record counts are bounded;
duplicate JSON keys and truncated records are rejected.

The reader does not execute W1, authenticate clocks or prove source/binary/host
identity. Its synthetic unit fixtures use invented CPU/wall observations and
claimed verdicts; they are reader tests, not native measurements. Exit zero
means complete internally consistent records. Exit one retains a native-verdict
semantic alert. Exit two means malformed/incomplete evidence. All work-hardness,
resource-fairness, independent-hardware, public-service, public-network and
production flags remain false for every exit.

## Exact native execution

Run preflight in a complete, committed, clean checkout. Use actual native Linux,
Rust 1.95.0, a fresh receipt directory outside the checkout and an explicit
`CARGO_TARGET_DIR`:

```sh
bash scripts/project-preflight.sh
python3 scripts/ci/test_pon_w1_false_trace_reuse_reader_v1.py
python3 scripts/ci/run_w1_false_trace_reuse_v1.py --arch x64 --local
```

On actual native ARM Linux, select `--arch arm64`. `--local` is never hosted
cross-architecture evidence. Hosted execution additionally requires an explicit
`TRNM_EXPECTED_SOURCE_SHA` containing exactly 40 lowercase hexadecimal characters;
the actual clean source commit must equal that requested SHA before any native
command. Local execution may omit the variable, but a supplied value must still
be canonical and match the actual commit. The source-after observation must
remain identical. A clean unrelated HEAD cannot replace the requested source.
The runner reuses the original cost command owner:
30 seconds for identity, 900 seconds for compilation, 300 seconds for the native
campaign and five seconds for termination grace. No original budget is relaxed.
It rejects compiler/target/release-profile overrides, observes Cargo configuration
before and after, checks actual compiler/ELF architecture, retains source and
binary identities before and after, and preserves original stdout/stderr and
failure status. A source-module harness with a different Cargo graph is only
local module validation and cannot satisfy this complete-workspace execution
contract. Hosted x64 and ARM observations still need inspection on the exact
same candidate source before making even an observational comparison.
