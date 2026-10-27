# PQL11b: runnable corpus fixture and PQ-named nested module closure

**RESEARCH ONLY / HOLD_NO_GO / DO NOT ACTIVATE.** Exact parent: existing sibling PQL11 PR #494 at `7d9a8550c684c8a7324b7811929cbf4ee95efe53`, which itself targets #492 (`668c41cead73ebef83212094d0c077ee788f1570`). This is a compatible, stacked improvement to #494, not an overwrite of its branch. The protected main stays `9fedf7ecbbe07177069c030592b4e03dcffebb81`.

## Reproduced blocker on exact parent blobs

- `scripts/ci/test_pq_research_integration.py` contained duplicate `pqg_native_verify.c` in its positive fixture's `REQUIRED` tuple, even though the checker rightfully rejects duplicate required paths. Exact #494 originals (`check`: `ab7aa05706d06959c6c727a6c61e212faabc59de`, `tests`: `9c69007966b7a0dc02361c1913fbf16f65ddeb77`) were locally reconstructed byte-for-byte and executed: **16 methods; 17 failures and 2 errors** across subtests. Those were test fixture failures, not proof of invalid main.
- Once the fixture duplicate was removed, #494's recursive scanner still allowed unpinned source called `native.rs`, `mod.rs` or `helper.py` under `pq_verifier/`, `pq_authority/` or `pq_next/` directories. Three concrete unpinned examples failed the new negative assertions on unchanged original #494 scanner: **19 tests, three subtest failures**.

## Minimal composition

- Keep #494's bounded iterative directory traversal, 10,000-entry ceiling, symlink rejection and all existing source/activation checks.
- Recognize `.py`, `.c`, `.rs` files as PQ source if **any path component relative to a scoped source root** starts with `pq_`, `pqg_` or `pql`. This prevents a renamed leaf in a named PQ module from avoiding a required exact Git blob pin.
- Deduplicate `REQUIRED`, preserve an explicit negative duplicate-path test, and add three unpinned nested-module cases plus pinned nested-module positive/readback mutation tests.
- Update exact source manifest to pin the combined checker/test and this document/evidence, without modifying consensus, protocol, native Rust source, transaction caps or acceptance flags.

## Actually executed

`cd scripts/ci && PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_research_integration.py` on exact reconstructed two-file Python source in Linux x86_64 / Python 3.13.5: **19 PASS / 0 failures / 0 errors**. Test fixture includes #494's traversal budget, nested symlink, source mutation, explicit activation denial, new nested module negative/positive, and restored unique required paths. The 106+ source manifest Git SHA equality can be checked against the exact proposed tree without inferring runtime eligibility.

## NOT_RUN / OPEN

Full stacked checkout/CI preflight, whole repository `check_pq_research_integration.py`, Rust/Cargo M00-M17, audited ML-DSA signer and transaction/nonce/reorg authority, genuine hybrid ML-KEM WAN, HSM and independent antirollback, Hepta export/Cell Final-use, W1 quantum-effective hardness and invalid-ticket economics, physical failure and independent cryptographic acceptance. No source inventory alone can resolve these production gates. All production and independent acceptance stay false, with draft-only review and no automatic merge.
