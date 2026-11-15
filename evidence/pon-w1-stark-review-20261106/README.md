# W1 STARK review and actual v2 verifier CI regression

Status: **component regression PASS; complete W1/QROM/chain qualification HOLD**.
This 2026-11-06 review continues PQ candidate
`5bb29d6ae39fa0c71f9151f3dce31fa1a3ab1800` on an isolated branch. It is a
same-operator code review and independent arithmetic reconstruction, not an
external cryptographic audit or approval. The
[sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [security review](../../docs/security/W1_STARK_REVIEW_20261106.md) retain
the open qualification obligations.

## Confirmed defect and minimal repair

The old independent v2 verifier had two tests, both of which passed after its
private `verify()` was changed in a disposable clone to always return `Err`.
The old suite therefore did not prove that the saved valid v2 receipt remained
acceptable. This is a test-coverage defect, not a discovered proof forgery.

The new named test reads the exact saved complete input, header, separate A/B
commitments and receipt; pins their bytes; replays the complete native relation;
compares its journal; and requires successful full receipt verification and the
fixed work ID. The same always-reject mutation now fails exactly that test,
while its two old tests still pass. The mutation is retained only as an audit
patch and never belongs to production code.

The workflow requires all three exact test names with no failed, ignored or
filtered tests. It also runs the unchanged 58-control script against the newly
built independent verifier and original saved proof. Acceptance checks preserve
the original ordered control plan, required rejection text/layers, common
120-second budget, process completion, identities and all unqualified flags.
Missing or skipped v2 verification/control steps cannot yield a passing finalizer.

## Actual accepted path and inputs

The hardened verifier constructs an empty context with Poseidon2 and its fixed
Succinct parameters. The v2 entry uses that full verifier with the fixed v2 image
and separately supplied public artifact expectations. Fake, Composite and
Groth16 receipts do not satisfy this profile. A transitive Groth16 crate in the
SDK dependency graph does not enable that receipt kind in this context.

The accepted default recursion root still covers 27 programs through `po2=22`;
the historical execution's `po2=18` does not narrow that accepted set. No root,
FRI query count, image, hash function, guest relation or production admission
rule changes in this repair. Parent eligibility and consensus admission remain
separate, explicitly unqualified checks.

The [original complete-v2 evidence](../pon-w1-full-v2-20261105/README.md) remains
unchanged. This run reuses its single proof; **zero new proofs were generated**.

| Input | Bytes | SHA-256 |
| --- | ---: | --- |
| `succinct.bin` | 257014 | `6c72828c9d05a62175e08fa3e7e1d0d5e85e785ad96b5beb5ec7a2e2490c26ee` |
| `header.bin` | 318 | `7b96038f228a1eedccf7b29ffc54802aba691be7259e33937846c6bf6126d78f` |
| `expected-artifacts.bin` | 64 | `802adcdd951cfb4cd7271df22c3bca6af66fee9f40454c74f8b5ff2c98a1b683` |
| `input.bin` | 49506 | `67b74fa2f417c0240d974e5ecea410d2b68d97d6dde667603aeb4d7ce59036cb` |

## Observed controls

| Observation | Result and scope |
| --- | --- |
| Old suite with always-reject mutation | Exit 0; both tests pass, demonstrating the gap |
| New suite with the same mutation | Exit 101; 2 pass, the new actual-proof test fails with the mutation's error |
| Repaired source, real saved proof | All 3 tests pass; full relation and full cryptographic verification execute |
| Actual receipt controls | 58/58: 1 accepted, 57 rejected; zero unexpected acceptance, panic or timeout; 4.176654993 s under the original 120 s budget |
| Rust source checks | Rust 1.95.0, frozen/offline release build and strict Clippy pass; the first format check failed on a line wrap, then formatting was corrected and the check passed |
| Independent formula reconstruction | 144/144 combinations and 24 fixed-term budget checks pass; arithmetic agreement only |
| Source-map preservation | 7 locked crate archives and 37 selected files verified; only generator/literature/unresolved-obligation annotations differ from the historical map |

The actual control binary is 20,050,016 bytes, SHA-256
`46552d3ed1c8742146dca687ab0a83713e668bb6b014652ff145b20deb7b7bda`.
The raw build record binds its selected native/verifier sources and unchanged
lockfiles. That selected scope is not a substitute for the later complete Git
source identity check. Reusing this binary for 58 cases is one proof trial,
not 58 independent proofs or an external reproduction.

## Reproduce the independent arithmetic

The source bundle contains seven original files at RISC Zero commit
`8c215e2f4ccdd935f0517bf05d90f1ae032840a9`, with immutable URLs, SHA-256 and
Git blob hashes. Original source notices and the [Apache license](RISC0-LICENSE)
are retained. The auditor independently parses individual taps and evaluates
the equations with Decimal precision 160. It compares against the project's
exact-fraction evaluator without validating the underlying conjectures.

From the repository root, use a fresh output directory:

```bash
mkdir /tmp/w1-stark-arithmetic-replay
gzip -dc evidence/pon-w1-stark-review-20261106/w1-independent-8c215e2-sources.json.gz > /tmp/w1-stark-arithmetic-replay/sources.json
python3 evidence/pon-w1-stark-review-20261106/w1_independent_calculator_audit.py --source-bundle /tmp/w1-stark-arithmetic-replay/sources.json --calculator scripts/w1_security_budget.py > /tmp/w1-stark-arithmetic-replay/audit.json
python3 evidence/pon-w1-stark-review-20261106/w1_smallfield_table_diagnostic.py > /tmp/w1-stark-arithmetic-replay/table.json
```

The [retained arithmetic report](w1-independent-calculator-candidate-audit.json.gz)
binds the exact calculator and audit-script hashes. The
[table diagnostic](w1-smallfield-table-diagnostic.json) reproduces approximately
92.4543301564 at the published parameters; it is not a certified global
optimizer, a practical attack or a complete W1/quantum security level.

The new [source-map snapshot](security-map.json) is compared byte-for-byte by
CI. The historical 2026-11-04 map is preserved, as is the old comparison's
expected failure after the literature annotation changed. No historical
timeout, performance failure or negative qualification flag is relabeled.

## Remaining qualification work

Pin the complete accepted recursive family and full statement/claim relation;
instantiate applicable soundness theorems and explicit quantum-query/reduction
losses; justify the actual hash/transcript interfaces and composition; and obtain
independent cryptographic review. Ordinary-node admission, original-resource
performance, public service and whole-chain PQ gates remain open. An optional
Groth16/BN254 outer layer requires a separate review and cannot inherit a PQ goal.
