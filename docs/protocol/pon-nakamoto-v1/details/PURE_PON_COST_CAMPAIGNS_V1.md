# Finite pure PoN cost and ingress campaigns

These two native examples measure the unchanged W1 relation and the explicit
[pure public profile](PURE_PON_PUBLIC_BOOTSTRAP_V1.md). They have bounded inputs,
reports and deadlines, preserve failures, and cannot qualify hardness, useful
model work, public fairness or production operation. Run each in isolation from
other campaigns when interpreting timing; record any host contention.

The complete 2026-10-27 observation, its source/binary capture manifests, all
3,456 producer cohorts, both attacked cold-reopen phases and limitations are
retained in [the evidence report](../../../../evidence/pon-pure-cost-bootstrap-20261027/README.md).
That host was not exclusive. The fixed-cohort reduction includes every offered
strategy, unsupported setup, both targets and preparation modes; it does not
select a fastest observed arm or turn a benchmark into a hardness qualification.

## Fixed producer matrix

`pon_pure_cost_campaign` offers all twelve current concrete producer strategies
on every material: general, structured, tiled classical, one-level Strassen,
paired field products, blocked zero, integer paired zero, one-zero rank-one,
maintenance split limb, maintenance periodic, maintenance prefix, and maintenance
integer paired. Unsupported constructors produce explicit rows with their real
setup cost. There is no fallback arm and no selection of the best observed arm.

Nine input classes cover the periodic fixture, rank-checked full-field matrices,
both zero, identity, rank-one, sparse diagonal, each orientation of one-zero with
one nonzero rank-one operand, and the actual public genesis maintenance matrices.
Only maintenance with the native expected target is admitted by a native Node;
other classes and the harder target are primitive observations, not registered
neural jobs. Every winning proof passes the unchanged production verifier.

The default batch offers horizons 1, 8, 64 and 256, cold preparation for each
search versus one preparation reused through the batch, two targets, and two
rounds. Round order rotates the same fixed strategy list. A search retains every
actual trial, including exhausted searches and those preceding a winner. The
denominator is preparation plus all producer attempts; validation, native
admission, report I/O and harness stream hashing are separately identified.
Unknown CPU observations stay unknown. No warm-up or slow initial sample is
discarded. Nested horizons and paired arms share challenge streams and therefore
are not independent samples.

The experiment compares complete header/proof/ticket stream hashes across all
supported algorithms and preparation modes. It also compares 64 distinct late
product failures through the original verifier and exact-public-product filter,
alternating order and recording fact setup separately. This comparison does not
cover correct-product/false-transcript attacks.

```sh
cargo build --locked --profile test --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --example pon_pure_cost_campaign
target/debug/examples/pon_pure_cost_campaign \
  --searches 256 --attempts 8 --rounds 2 --seed 1 --seconds 900 > cost.jsonl
python3 scripts/ci/check_pure_pon_cost_campaign.py cost.jsonl --output cost-check.json
python3 scripts/ci/summarize_pure_pon_cost_campaign.py cost.jsonl \
  --output fixed-cohorts.json --csv fixed-cohorts.csv
```

Use the actual `CARGO_TARGET_DIR` path in place of `target`. The repository's
`test` profile optimizes the node and crypto packages at level 3, M06 at level 1;
the Cargo banner's overall `unoptimized` label does not override those package
settings. Record the toolchain, full profile settings, source commit, source-file
hashes, exact command and executable hash. The example writes a failed terminal
record on a bound or mismatch; an incomplete run must not become a passing
aggregate. The consistency reader rejects dropped unsuccessful trials, missing
offered cohorts, unpaired streams, forged CPU zeroes and native-scope promotion.
Its own tests use synthetic fixtures explicitly separate from measured evidence.

## Unique invalid trace ingress

`pon_pure_ingress_campaign` uses two independent native receivers by default,
each with two TCP listeners sharing that receiver's original CPU and intake
owner. A single host's receivers have independent budgets; this is not a claim
of one network-wide resource bucket. Cold initial credit is checked at every
reopen. The campaign fetches the public bundle, retains a genuinely produced W1
seed, and records acquisition cost once.

Each attacker changes the challenge and fabricates a new target-winning trace
without computing its required W1 relation. The exact original A/B/C are reused.
These are deliberately invalid proofs, with unique packet/body identities at each
receiver and new arbitrary caller keys. The attack's short hash search is the
construction of a fraudulent W1 claim; it is not a protocol admission gate.
The same prepared invalid packet is sent once to each independent receiver, so
sender preparation can be compared with repeated receiver work. A single honest
worker interleaves complete newly generated W1 proofs through the same queues.
Any invalid acceptance terminates as failure.

The default sequence is a 15-second honest cold baseline, a 45-second attacked
cold reopen and a second 45-second attacked cold reopen. All use actual TCP and
native admission, with unchanged global bounds. Per-request records include
failed calls, latency, transport CPU, zero transport trials, generation attempts
and preparation cost. Matched receiver observations record actual full-work and
dispatch thread CPU, including unknown/missing observations. Those CPU intervals
are nested and must not be added. Reactor CPU and physical network bytes are not
covered by those observations.

Summary records include all-call p50/p99, accepted-call p99, honest accepted
receiver calls per observed second, distinct honest packets accepted by all
receivers, refusal reasons, original budget flow and observation coverage.
The denominator includes client deadline tails. A packet-count bound ending a
phase early is explicit; it is not a completed duration claim. The source-fixed
trace/caller domains, observed genesis timestamp and seed header are retained.

```sh
cargo build --locked --profile test --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --example pon_pure_ingress_campaign
target/debug/examples/pon_pure_ingress_campaign \
  --baseline-seconds 15 --attack-seconds 45 --receivers 2 \
  --attack-workers 4 --max-groups 8192 > ingress.jsonl
python3 scripts/ci/check_pure_pon_ingress_campaign.py ingress.jsonl \
  --output ingress-check.json
```

Loopback success is not a WAN or Sybil-liveness proof. Bounded resource use can
coexist with zero honest goodput under attack; retain that outcome. Real model
tasks, accelerator kernels, task supply, non-amortization arguments, multiple
physical hosts and independently reproduced longer runs remain separate work.
