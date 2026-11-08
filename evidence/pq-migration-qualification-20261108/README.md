# Historical-account migration qualification — 2026-11-08

Status: **HOLD_NO_GO**. Existing PR #723 continuation from
`12e510b211110d93d9ead07e02c07a1eecc28ae9`. No production activation, live
genesis, source retirement, asset migration or real wallet seed was used.

## Change and evidence scope

The offline migration journal now distinguishes the literal reserved SQLite
prefix from user-created lookalike names. A `LIKE` underscore had hidden some
foreign tables/triggers from both schema queries. The new regression methods
fail on the unchanged owner and pass after replacing that predicate with `GLOB`.
They use real SQLite transactions, cold open and readback; only the signature
verdict is mocked in the storage-isolation suite. Existing dual-signature tests
run real Ed25519 and ML-DSA-65 operations. Their key generation now uses the same
explicitly pinned backend as signing/verification instead of resolving a
different `openssl` from PATH.

The new seed relation component independently reproduces nineteen public
fixtures and preserves the original public-input V1 wire bytes. Its cleartext
arithmetic is not a ZK proof and its output grants no account permission.
The [relation review](../../docs/security/PQ_SEED_RELATION_REVIEW_V1.md) records
the 251-free-bit derivation analysis, wallet-format limits and the distinct
formal-relation, verifier and custody obligations.

## Recorded finite observations

| Scope | Observation | Limit |
| --- | --- | --- |
| Old journal with new regressions | 13 methods; 12 failed subtests | Original owner bytes; expected counterexample, not a passing result |
| Corrected SQLite owner | 13 methods pass | No independent rollback witness or chain authority |
| Real dual signatures | 7 methods pass on declared local OpenSSL 3.5.7 | CLI conformance; not the CI-pinned 3.5.9 provider qualification |
| Seed framing and relation suite | 40 methods pass: 19 existing parser, 21 new relation | Nineteen public vectors; no upstream circuit or proof execution |
| Public-vector CLI | 19 outputs, exit 0 | No secret input and no authority result |
| Original upstream sampling headers | Two different public seeds produce the same first 32 bytes and different second blocks | Negative component characterization; no full proof/ownership attack demonstrated |
| CI command contract | 107 methods pass | Complete original lane retained; added controls cannot move, disappear or swallow nonzero exits |
| CI execution/source-integrity suite | 77 methods pass | Synthetic execution and source controls, not a hosted/native result |
| Fixed from-zero Host CI suite | 78 methods pass | Host callsite controls, not a new from-zero native campaign |

Final command exits, test counts, source digests and local library identities are
in `validation.json`, `validation-initial.json` and `raw/`. Raw text logs are
retained in `raw-logs.tar.gz`; `raw-log-index.json` records each member's length
and SHA-256. Extracting that archive recreates the `raw/*.log` paths in the
validation records. Repeated validations are not added together as independent
coverage. The sampling harness's zero exit means the reported problem was
reproduced; it does not mean cryptographic acceptance.

The local integer/backend comparison uses cryptography 50.0.0 with its embedded
OpenSSL 4.0.1. The distinct CLI signature oracle uses `/usr/bin/openssl` 3.5.7,
whose digest is retained in `raw/migration-openssl-binding.json`. Hosted CI selects
cryptography 50.0.2 and a separately pinned OpenSSL 3.5.9. No local result is
transferred into an unexecuted hosted configuration.

## Preserved failures and incomplete execution

The first signature attempt refused before any test because no explicit
OpenSSL binding had been supplied; its zero-test/error log is retained. A later
attempt explicitly selected the actual local executable, digest and version.
The initial relation-test run incorrectly treated two already-clamped fixtures
as effective negative controls. It recorded two failed subtests. The corrected
tests distinguish seventeen effective mutations from those two no-ops; both
original and corrected records remain in `raw/seed-relation-tests.log`.

The initial CI contract run recorded 104 tests with two failures and three
errors because the strict expected lane/callsite had not yet been updated for
the three new commands. The repair retains the full original straight-line
lane, fixes the exact prefix expectation and adds three controls. Original
failures remain in `raw/ci-contract.log`; the 107-test passing successor has its
own log. No source guard, native command, budget or failure-exit rule is removed.

The source snapshot initially lacked 231 historical evidence blobs. Two required
Python evidence sources and fifteen directly linked archival documents were
recovered from GitHub and matched to their exact baseline Git blobs. All
implementation source and the PQ pin set were readable; 214 historical evidence
files remain unmaterialized locally. Their unchanged Git tree entries are
preserved, not deleted or replaced with invented content. The repository-wide
link check remains blocked by those historical files, including compressed
archives. This is not a complete materialization/replay of every historical
archive; the new/changed documentation links are checked separately.

The configured Hepta desktop was reachable and reported Cargo/Rust 1.95.0.
A bounded source-discovery command timed out, and the selected existing checkout
was at `cfaaadb4fb40772be41c31721ecc9b9e8769a8f2`; resolving the required `12e510b`
commit there also timed out. No native test or Clippy pass is claimed from those
readiness attempts. No Rust source, Cargo manifest or lockfile changes in this
increment. The existing native migration gates remain required and unqualified.

## Reproduction

Select a canonical OpenSSL >=3.5 executable and independently verify its source,
version and digest, then set `TRNM_PQ_OPENSSL`, `TRNM_PQ_OPENSSL_SHA256`,
`TRNM_PQ_OPENSSL_VERSION` and `OPENSSL_DIR` under the existing backend contract.
Run from the repository root:

```sh
bash scripts/project-preflight.sh
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_pq_account_migration.py' -v
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_pq_migration_journal_owner.py' -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_pq_seed*.py' -v
python3 formal/pon-nakamoto-v1/pq_seed_relation_vectors_v1.py
python3 scripts/ci/check_pq_research_integration.py
python3 scripts/ci/test_pq_research_integration.py
```

The new CI calls are in `protocol-contract`, whose head and merge workflows
install the conformance Python dependency and prepare the pinned PQ provider.
The pure framing test remains in `repository-truth`. Hosted workflow results
must be read from the exact published commit; wiring alone is not a CI pass.

### Original-header sampler characterization

Retrieve `include/zkp/random.hpp` and `include/zkp/hash.hpp` from the exact upstream
commit in `upstream-source-manifest.json`. Keep their original licensed bytes and
verify the recorded Git blobs before compiling `sampler_component.cpp` against
that include root and real OpenSSL. No upstream header is patched or replaced
by a stub. The retained command used C++20, `-O2 -DNDEBUG -Wall -Wextra` and
`-lcrypto` with g++ 14.2.0. `raw/sampler-observation.json` binds the executable,
command, public outputs and independent Python SHA-256 comparison. It establishes
only the seed-independent first output block on the exercised path, not the
number of resulting fixed query indices or full verifier behavior. Independent
SHA-256 comparison means another program recalculated the expected formula;
it does not assert an independently implemented hash provider.

## Remaining gates by route

| Route | Retained component capability | Still required |
| --- | --- | --- |
| A: new PQ genesis | Root-checked exact-ledger inventory; zero-value identities and unknown rows preserved in classification | Real complete operational/external-debt inventory and explicit source retirement |
| B: prior PQ commitment | Trusted configured registry, pinned source anchor, supported balances/nonce/task/reward preservation, restricted CLAIM | Historical binding custody, ordinary source application coverage, source write retirement, activation/reorg and durable effect reconciliation |
| C: seed recovery | Public-input framing and independently reproduced public relation vectors | Wallet custody/entropy, exact relation security, qualified backend, resource bounds, real proof/PQ possession and atomic native owner integration |

No Boolean in this record substitutes for those obligations. A previously
stolen and settled balance is not recreated by a seed proof. Consensus state and
irreversible external effects retain their different recovery owners.
