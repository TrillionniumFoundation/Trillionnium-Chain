# Fixed-success query frontier: frozen-source evidence

Date: 2026-11-09 UTC. Qualification: **HOLD_NO_GO**.

This packet records focused validation of code commit
`51683089c7ec75cca3e0bcfb2201c08aa5dab654`, tree
`c85745e3396723b07bda7c86a36618c7863e65a5`.
It is an evidence-only child on [PR #838](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/838),
stacked on #835 at `e2a02f9271b49f146e70806c8a66e161b5973971`.
The code and validation source identities do not include this subsequently added evidence packet.

## What was established

The [proof](../../formal/pon-nakamoto-v1/FIXED_SUCCESS_QUERY_FRONTIER_V1.md)
covers every classical adaptive policy in its declared independent Bernoulli
membership-query game. Its finite examples and decision-tree controls check
the implementation; they are not the coverage proof. Initial state and
program are independent of the entire oracle, exact private coins are free,
and final unchecked outputs have explicitly separate accounting.

At density `1/16` and success target `1/2`, the minimum expected paid query
count is `8` with no free outputs and sufficient data/cap. The minimum feasible
hard cap is `11`. One free unchecked output reduces the optimum to `112/15`;
eleven free outputs permit zero producer membership queries in the relaxed
game. No arithmetic, physical-time or actual W1 cost is inferred from that
zero. Virtual extraction checks cannot silently be charged to the producer.

All sixteen actual classical/quantum cost rows remain
`lower=null`, `upper=null`, `status=unproved`.
There is no native admission, credit, activation, quantum-cost or release qualification.

## Frozen-code observations

| Check | Actual observation |
| --- | --- |
| Project preflight | PASS; 26 packages |
| New query-frontier tests | 20 methods PASS |
| Retained fixed-probability tests | 16 methods PASS |
| New query-frontier `--check` | PASS; six declared fixtures |
| Retained cost-contract reader | PASS; 16 unknown cost points; HOLD_NO_GO |
| CI-contract static checker | PASS; its report does not claim to execute tests |
| Original repository checker | Exit 2: missing historical evidence link in the sparse checkout |
| Locked/offline Cargo metadata | Process not launched: Cargo unavailable after executor recovery |
| Cargo formatting | Process not launched: Cargo unavailable after executor recovery |

Read the [small summary](validation.json), [command records](command-summary.json),
[new-test raw log](new-query-frontier-tests.log),
[retained-test raw log](retained-fixed-probability-tests.log),
[unchanged cost-contract report](fixed-probability-contract.json),
and [original repository failure](repository-check.stderr).

The original repository check reported:

```text
Repository check failed: broken link docs/README.md -> ../evidence/pon-v1/README.md
```

This is an incomplete local source gate. No placeholder, source-check bypass or
replacement success result was used. Cargo launch failures have
`exit_code=null` and a `FileNotFoundError` in their records, not a fabricated
process exit code. This local command packet contains no native build, strict Clippy,
performance, physical-resource or full-repository PASS.

Before publication, the root agent observed 166 retained CI-contract test
methods PASS, and successful locked/offline Cargo metadata (176 packages,
26 workspace members) and formatting. Those earlier terminal observations
are distinct from the frozen-code receipts here. The complete 166-method raw
stdout/stderr was not retained and is not reconstructed. Repeated runs are
not added to test counts. See [prior observations](prior-observations.json).
A later hosted run on the exact code also passed the same 166 methods;
its complete log is retained separately below.

## Exact source and complete receipts

Every command has its own recorded argv, UTC start time, elapsed time, exit
or launch error, complete stdout/stderr, and before/after source observation.
All nine command records have the same canonical source-manifest digest:

```text
d29cfff0a587ceba6b83ae324e12fe8bfb09d8bd1355985a049f544fce8553ea
```

The recorder checked the actual bytes, Git blob identities and file modes of
5,146 materialized tracked files (172,829,574 bytes), finding zero mismatches.
It explicitly lists 21,020 tracked files absent from this sparse checkout.
Thus unchanged materialized source is established; complete checkout coverage
is not claimed. The pretty-printed manifest's file SHA-256 differs from the
canonical compact-JSON digest and is recorded separately.

[Download the complete frozen-code validation packet](frozen-code-validation.tar.gz).
The deterministic gzip archive contains all 50 original files under
`final_validation/`: the recording script, source manifest, all raw outputs,
per-command results, before/after observations, summaries and receipt index.
The original receipt index covers 49 files and excludes itself. Every listed
byte count and SHA-256 was checked before packaging.

Archive SHA-256:

```text
e95196697d41f45b809bcdd40578b5f6b881fe07076fc0179e85be3cd9ed773b
```

After extracting into an empty directory, check
`final_validation/receipt-index.json` against the extracted bytes.
The corresponding uncompressed source-manifest file SHA-256 is
`a32d295cd571d4722f5a31f19de59b836f5c892fb4139140d3af8c7d4cfb5c03`.
[Publication identities](publication.json) bind the archive and the nine
published code blobs.

An [independent mathematical review](independent-math-review.md) checked the
proof and 12,600 finite parameter comparisons against the same numerical
implementation hash. That comparison count is not a test-method count,
a mechanized all-program proof, or actual W1 coverage.

The [hosted CI review](hosted-ci-review.md) records its own observation time
and links. These hosted observations are separate from the local packet.
At the later 13:50:59 UTC observation, the exact code's repository-truth
head job had completed successfully, including source identity before and
after execution, the new 20 methods, the retained 16 methods and the 166
CI-contract methods. The [completion update](hosted-ci-update.json) and
[complete decoded hosted log](hosted-repository-truth-head.log) preserve
that separate result. The prospective-merge lane was still running at that
observation. The two inspected inherited QROM failures remain open;
this draft is not presented as fully green.

## Remaining research gate

For every real legal W1 strategy, a success-preserving simulation into a
proved model must bound simulated cost above by charged real cost, with
explicit multiplicative and additive overhead. It must cover the permitted
joint initial state, public assistance, preprocessing, sharing, caches,
low-rank and batched work, failed and unpublished attempts, old branch
inventory, proof generation, propagation, verification and recovery under
the same eligibility and deadline contract. The classical query theorem
does not supply that reduction or the quantum and physical-resource bounds.
