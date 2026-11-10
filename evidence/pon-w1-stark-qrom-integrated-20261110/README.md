# Same-source STARK route and QROM observation continuation

Status: **HOLD / NO-GO**. The current source-observation workflows execute
successfully together with the separate proof-route readers. This does not
establish a STARK/QROM theorem, native service acceptance or production authority.

## Actual source and ancestry

| Identity | Value |
|---|---|
| Executed integration merge | `784274926d97207e9ee94cf76eef22e1006d84e1` |
| Executed tree | `ebe84c04a79dd6bedf75d8b2ba852a87dbfd749f` |
| First parent, #859 | `eb272801e18112e90506fe5016e4dfc4660ad736` |
| Second parent, #857 | `06c3d24cc4fc05011e04951d30f066c057394836` |
| Verified real merge base | `e2a02f9271b49f146e70806c8a66e161b5973971` |

The merge preserves both parent branches. It resolves the corpus, sole plan
and three CI command/contract files, unions required source paths and refreshes
the generated inventory and actual integrated blob pins. There are no new
cryptographic input/profile/wire parameters. The shared current mapping,
historical lifetime reader, FRI transcript helper, original 105-name historical
closure roster and original 69-name proof-chain roster retain their bytes.

This directory is an evidence-only child of the executed merge. Its later
publication identity must not replace the code identity above. Earlier branch
passes remain scoped to those branches.

## Executed validation

| Scope | Actual result on the merge |
|---|---|
| Fixed-field algebra tests | 16/16 PASS |
| Three-route reader tests | 28/28 PASS |
| Conditional iid sampler tests | 7/7 PASS |
| Retained receipt replay tests | 13/13 PASS |
| Complete CI command-contract suite | 169/169 PASS |
| Source-integrity controls | 43/43 PASS |
| PQ corpus controls | 57/57 PASS |
| Current implementation named roster | 75/75 PASS |
| Current closure named roster | 110/110 PASS |
| Original proof-chain roster | 69/69 PASS; independent completion check PASS |
| Actual current implementation workflow shell blocks | 8/8 exit 0 |
| Actual current closure workflow shell blocks | 8/8 exit 0 |
| Preflight, corpus, generated inventory, repository/link and three report commands | Exit 0 |
| Cargo metadata | Exit 127: Cargo executable absent |

These scopes overlap. In particular named rosters include separately reported
modules; they are not added into a distinct grand total. Of the fifteen
selected commands in `validation/SUMMARY.json`, fourteen exit 0 and the Cargo
command cannot execute. No new Rust dependency graph, build, formatting,
strict Clippy, STARK proof, recursive execution or resource qualification pass
is claimed.

Both real workflow block sets run on the same clean merge. They check complete
tracked source before and after, including 26,399 entries, retain genuine V1
refusal processes, execute the fixed current named rosters, reproduce their
reports and enforce final stage/completion status. Source endpoints match.
The closure comparison allows only its separately frozen semantics lock
provenance difference; five other report comparisons remain exact.

The runner extracts the actual stored YAML run blocks. Its step status inputs
come from observed subprocess exits. It does not execute or certify GitHub
checkout/upload infrastructure, a hosted Action, an original historical-positive
lane or an ordered prospective-merge source. Local head execution is the scope
of this evidence; exact new-head hosted CI must be observed separately.

## Parent failures are preserved

The original #857 hosted implementation run `42774670477`, head job
`129690267245`, rejects the historical V1 verifier input size. The original
closure run `42774670391`, head job `129690267582`, rejects the historical
`store.rs` identity; its LifetimeLedger fixture runs zero tests. Their raw
logs and source/scope record are in `parent-hosted-failures/`.

These failures are retained on source `06c3d24c`; they are not reclassified as
failures of this merge or erased by its local passes. The #850/#859 historical
and current workflow distinction is now present in the same candidate as the
#849/#857 route work. Historical readers and their refusal checks are preserved
rather than relaxed. New hosted CI acceptance is not implied.

## Reproduction and limits

`validation/SUMMARY.json` records the selected commands and their actual exit
codes, with original stdout/stderr and clean source observations. From this
repository, the internal runner may be invoked against a fresh external output:

```bash
python3 evidence/pon-w1-stark-qrom-integrated-20261110/reproduction/run_integrated_workflow_blocks.py --root "$PWD" --out /tmp/new-integrated-observations --base eb272801e18112e90506fe5016e4dfc4660ad736
python3 scripts/ci/w1_qrom_proof_chain_controls.py run --output /tmp/new-integrated-proof-chain
python3 scripts/ci/w1_qrom_proof_chain_controls.py check --output /tmp/new-integrated-proof-chain
```

The reproduced source identity will be the checked-out source, not an automatic
relabeling of the original executed merge. Output paths are create-only. The
retained workflow blocks and observations remain in `workflows/` and the
original named proof records in `proof-chain/`.

All three cryptographic profiles retain their separate fields, parameters and
primitive/transcript premises. The domain obstruction and sampler law keep
their narrow, explicit hypotheses. Actual iid transcript behavior, relation and
compiler refinement, RBR/state restoration, quantum extraction, the shared
oracle, full FRI/PCS/Fiat-Shamir, recursive and lifetime composition remain open.
The fifteen historical IDs and eight open implementation interfaces remain;
zero complete security obligations have been discharged. Complete security bits
and actual lifetime bounds remain null; production and consensus qualification
remain false.
