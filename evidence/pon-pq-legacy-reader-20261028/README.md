# Strict legacy evidence reader on the explicit PQ source

## Result and unchanged scope

This continuation starts from local source
`969150c1f1ad1821ee5ac3c11f0535677e9bb8e9`, whose tree
`f90cd9f63fce5fb785061419c9cb12b57ae24873` is identical to published
`a1e40747746772d1326bb3e656aec4ba10440147` in Draft #524. The original
strict Layout reader refused this PQ successor with
`durable backend composition/domain`. That observed refusal is retained.

The repaired reader returns the original **4,775-byte** legacy DDL and
`native-branch-schema-v2`, for both the explicit PQ source and the previously
supported non-PQ Layout source. The DDL SHA-256 remains
`ce0de86674de23181ef1f6fb59f357f94971feeaee0c5503f065dbf45bb5c964`;
the independent native domain hash remains
`8c2627fa0b06e51742e7e6d40662c61d4b4727e810abc02b24634a8a817dc0e0`.
Recognizing the source join grants no PQ, authenticated, shared-account or growth
evidence qualification. No Rust runtime, protocol namespace, feature or data
permission changes in this continuation.

## What is checked

The original closed Layout contract is retained. The explicit successor adds
fixed reviewed contracts for `StateBackend::selected_ddl`, all NPQ1/2/3 schema
domains and selection order, the actual Settings and executor predicates, the
ordinary opener's `pq_explicit: None` bridge and both mandatory entry guards.
The reader verifies the selected packet dispatcher, the original legacy header
prefix/decoder and the ancestry context/header projection that uses that profile.
Unknown source bodies, substituted module owners and weakened guards refuse.

The legacy reader rejects all PQ table prefixes in its source DDL, foreign
schema domains in real SQLite metadata, changed catalogs after metadata
resealing and PQP1/2/3 packets even when both stored copies and the replay input
are replaced. Existing authenticated, growth and shared-layout refusal controls
remain in place. Historical literal V1 and inline composed V2 controls remain.

The shared lexical helper preserves joint punctuation and literal prefixes.
The original structural comparator accepted two actual source mutations:
splitting `&&` into `& &`, and splitting `b"..."` into `b "..."`.
Both observations are retained and both now refuse. The exact PQ contract also
tests these boundaries. These are source-contract findings, not a demonstrated
runtime exploit; the helper is not a Rust parser or compilation verdict.
Caching is local to one extraction and keyed by the complete immutable input
text. Paths, source bytes and prior acceptance results are not cached across
invocations. A same-length file replacement has an explicit refusal control.

## Actual validation

| Observation | Actual result | Scope |
| --- | --- | --- |
| Original strict reader on frozen PQ source | REFUSE | Preserved initial incompatibility |
| Original strict reader, two token-splitting mutations | Both ACCEPT | Preserved defects; never qualification |
| First expanded reader run | 67 methods, five failing subcases | Two ambiguous growth fixture targets and three exact refusal-message expectations; retained as failure |
| Targeted repair run | 9 passed | The failing cases and actual lexical regressions |
| Complete final reader run | **74 passed, zero skips**, 198.537 seconds | Original 53 methods plus 16 source/SQL/packet methods and five lexical methods |
| Source-integrity negative suite | **34 passed** | Real Git/filesystem and process source-boundary controls |
| Evidence-source suite | **38 passed** | Historical source acquisition and exact measured snapshot controls |
| Composed CI structure contract | Passed | Source/workflow structure only; no native workflow execution |

The final reader command had a fixed 1,800-second ceiling; it finished in
198.810 seconds including its wrapper. Its 1,542 recorded source/config/workflow
inputs matched before and after. The other complete suites used fixed
120-second ceilings. The first failed run was not erased or relabelled.

The local reader environment was Python 3.12.14, cryptography 50.0.2 with
OpenSSL 4.0.3, and NumPy 2.3.5. This is a reader regression run; it is not the
formal NumPy 1.26.4 pinned qualification campaign or new native runtime evidence.
The separate [hosted Cargo evidence](../pon-pq-hosted-a1e407-20261028/README.md)
retains its own source, environment and binary identities, including the actual
164 selected tests and strict selected-target Cargo/Clippy verification.
The first local CI-structure check refused the sparse checkout's missing fuzz
lockfile. Materializing that exact unchanged tracked blob made the check pass;
both observations and the blob identity are retained. This sparse checkout is
not presented as a complete hosted-CI execution of the new commit.

## Evidence and later composition

[summary.json](summary.json) records the results and exact helper hashes.
[raw-inventory.json](raw-inventory.json) binds every member of
[observations.tar.gz](observations.tar.gz), including raw successful and failed
logs, before/after source hashes, the imported-reader provenance, both original
tokenizer counterexamples, environment and the retained test-selector inventory.

After the frozen reader run completed, the independently reviewed hosted Cargo
archives and four-literal recent-batch guard repair were incorporated. The
[source identity join](source-identity-join.json) explicitly records that later
workflow change rather than rewriting the earlier observation. Reader helpers,
all Rust/runtime/config inputs and formal vectors remain byte-identical to the
tested reader snapshot. The workflow's original failed job, all sixteen guard
comparisons and all four reviewed material patches remain in the hosted evidence
package. Synchronizing the literals does not certify a rerun of that workflow.

Whole evidence-package acceptance, full workspace qualification, independent
migration trust/source retirement, remaining authority owners, transport,
custody, History/Hepta final-use permissions, physical I/O and whole-chain PQ
remain separate. `p1_complete=false`, `public_network_ready=false` and
`production_activation=false` remain unchanged.

The local shared Git checkout also lacks an inherited historical log blob,
`7f4d96ac57a7907f68f186f302da8082b215bd4e`. Ordinary `git commit` refused to
build a tree, and that failure is retained. The continuation tree preserves
every inherited object reference and composes only the fully available changed
paths; no old log is replaced or synthesized. Complete source verification of
the new published tree remains the full-checkout CI's responsibility.
