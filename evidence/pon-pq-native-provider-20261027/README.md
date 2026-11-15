# Local PQ provider and native-owner audit observations

Source changes: `f1829c8fa8550a1665bc2da34cbd8b6e6a8b2714` (provider/wiring) and `0915e5ab19f4489618b9c7cfa25fe65644bfa010` (explicit source archive). Audit candidate: `31dc8b2247aed8cbb4e3f6912659da97a2cbc2b3`. These observations do not assert production activation or a hosted CI run.

## Actual installer execution

`full-download-build/provider.json` and its gzip log preserve a complete local download, official archive SHA-256 verification, OpenSSL 3.5.9 static configuration/build/install, and actual ML-DSA-65 generation/sign/correct-verify/wrong-message-rejection. It used make -j2, 164 seconds wall time and approximately 290 MiB. `executed-prepare-pq-provider.sh.txt` is the exact f1829c8 script that ran; its SHA-256 matches the receipt. The generated private test key is not included.

`sandbox-download-failure/` preserves the earlier actual failed download, exit 7, no environment exports. The later successfully approved invocation did not convert this failed observation into success.

The v2 explicit local-archive input was added after the complete run. Seven source/wiring and failure-path tests passed on 0915e5ab; that new branch was not subjected to another complete build. The full-run v1 receipt must not be relabelled as execution of v2. No test stubs produced a successful provider or signature.

## Native owner coverage

`pq_owner_migration_review.md` identifies the remaining classical authorization owners, exact files/lines, wire incompatibilities and migration gates. `pq_owner_source_inventory_31dc8b2.json` preserves the candidate identity and per-file hashes. Its lexical match count includes possible inline-test matches and is not a count of production paths.

Actual in-process ML-DSA primitive support is distinct from application authorization. No native authority owner consumes the new cryptographic observation at the audited candidate. Ledger, network, task, Hepta handoff, operator, settlement, DA and Cell discovery migration remain incomplete. Whole-chain quantum security remains unqualified. Pure PoN and existing native consensus are unchanged.

## Readback

The manifest records every retained artifact's bytes and SHA-256; gzip entries also record exact uncompressed bytes and SHA-256. The manifest excludes itself. Standard-library Python can recompute these values without Rust, Cargo, Bazel or any model execution. Full logs are kept even where the final wrong-message negative prints an expected verification error.

The installer does not run OpenSSL's full upstream tests or native Rust feature tests. Hosted source-head/actual-merge workflow execution and all native PQ owner migration gates remain outstanding. Source identities, script identities and scopes are recorded separately rather than borrowing another source's result.
