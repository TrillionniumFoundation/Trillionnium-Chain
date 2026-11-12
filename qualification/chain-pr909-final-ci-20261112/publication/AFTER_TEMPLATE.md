## Problem

Fixed Chain source `297bb40798ca1b4e4a987ef00582067282cda4e9` has no explicit reader for Hepta's HEPLCP04/tag-9 local decisions. Treating a local defer/retain as training NoUpdate, or treating a commitment readback as authenticated adoption, would conflate separate claims.

## Changes

- Add an explicit read-only HEPLCP04 parser that binds the original five-stage prefix, qualified proposal, LocalDecisionV2, a separate Selection, and subsequent NextUse/RetainedModelNextUse.
- Check exact original request/owners, proposal and bundle identities, policy/reason, time ordering, checkpoint-prefix continuity, and separately pinned Root scope.
- Preserve original HEPLCP02 readers and their refusal behavior byte-for-byte. Defer/retain remain local choices after a qualified candidate; they are not relabeled as training/evaluation NoUpdate.
- Add original-Rust codec/coordinator vectors, a pinned offline reproduction entry, negative controls and a read-only CI workflow with full-checkout head and prospective-merge lanes.

## Fixed source and execution

Fixed, tested code source: `6bf73a220ec147dba333da2404bd6c3ce7f4b1f8`, tree `6c004b08b87daa4a225a8728363b21f3fe08ab4a`.

The entire tree is byte-identical to local tested commit `843934e3c377f7344a48b4b462a3672cf4b3f00d`; its parent is fixed `297bb40798ca1b4e4a987ef00582067282cda4e9`. API publication changes commit metadata, not source bytes. All 62 source-addition paths / 44 unique blobs were checked. No existing tracked file changed.

Current PR head is evidence-only child `e338c000f26e9357ed33213624da787a3a009ed9`, tree `876aa62d1ab49458d29e9168f4c69e7b47b8884b`. Its ten added evidence files retain the complete 47-file local validation archive and original hosted job logs; no executable source changed. The fixed results below name their actual tested commits.

The evidence-only head also completed its own [hosted structural run 43030977516](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43030977516): original full-source guard before/after and 14 tests passed in each lane. Actual head source was `e338c000f26e9357ed33213624da787a3a009ed9` / tree `876aa62d1ab49458d29e9168f4c69e7b47b8884b`; actual prospective merge was `bfa5cf58953a67dd9b9a27ce52b63524933a029d` / tree `4b08c77fd511466c8f2e5bc46307e0d6fd629063`, using the same fixed base `c8416237`. These repeat the same methods and add no ordinary-loop acceptance.

This stacks on #907's branch, which subsequently advanced to `c84162378f34b9284e90587df4c466dfee3e193b`. Results from that moving head are not inherited. The hosted prospective-merge lane independently tested actual merge `1698cf9d02dc88da96d2db4e0641a9011cc3bb2b`, tree `df0baad8f8629e3195f80417b7bfc53a02e33af9`, combining that exact base with code candidate `6bf73a2`.

| Scope | Actual observation |
| --- | --- |
| Original Rust export from fixed Hepta afd2 | exit 0 |
| Independent fresh --locked --offline replay | exit 0; exact retained stdout match |
| Original source / copied workspace inputs | 89 / 94 files unchanged before and after |
| Structural native vectors | 3 synthetic local-policy cases; 15 cuts; 24 signing payloads |
| Frozen local legacy tests | 25 iteration + 13 completion + 13 scope passed |
| Frozen local new tests | 14 passed |
| Local total | 65 passed |
| Full local source guard | refused sparse index; not passed |
| Hosted full-checkout head | original source guard passed before/after; 14 new tests passed |
| Hosted prospective merge | original source guard passed before/after; same 14 new tests passed |

The local run kept all 2,557 materialized tracked files unchanged; 26,312 tracked files were not expanded. The original source guard refused that sparse checkout before and after the run. That refusal is retained and the guard is not weakened. Full-checkout hosted source validation subsequently passed separately on both exact commits recorded above. The two hosted lanes repeat the same 14 test methods; these are not 28 additional unique tests, and this is not an all-workflows-green claim.

The initial helper test errors, branch-name refusal, commit-identity failure and log-whitespace refusal are retained. Original stderr with meaningful trailing spaces is stored losslessly in explicit length/hash/base64 containers. The complete final execution archive and lossless hosted job logs are now attached in the evidence-only child. [Validation index](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e338c000f26e9357ed33213624da787a3a009ed9/evidence/heplcp04-interop-20261111/VALIDATION.md) · [original hosted run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43029319486).

## Acceptance boundary

The native exporter is an isolated assembly of unchanged pinned codec/coordinator sources, not a whole Hepta daemon or an ordinary task campaign. Checkpoint commitments do not contain the original signed attestations. This reader does not verify signatures, authenticate owner custody, observe a native-use export or establish an independent consumer.

Authority stays DENY_ALL. ACK, CURRENT activation, production learning, independent B/C, model benefit, settlement, FinalUse and whole daemon/Root cold restart qualification remain false. New ordinary complete-chain counts remain zero. This remains Draft.

[Protocol and reproduction boundary](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/6bf73a220ec147dba333da2404bd6c3ce7f4b1f8/docs/development/specs/pon/HEPLCP04_LOCAL_DECISION_INTEROP_V1.md)


## Broader CI snapshot (2026-11-12 06:44 UTC)

All nine pull-request workflow runs for the unchanged head `e338c000f26e9357ed33213624da787a3a009ed9` are now completed: **5 success, 4 failure**. The complete repository CI is not green. The following are workflow conclusions; job counts are identified separately and do not change the structural or ordinary-loop acceptance totals above.

| Workflow | Run | Terminal conclusion |
| --- | --- | --- |
| PoN work and time contract V1 | [43030977425](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43030977425) | success |
| Chain Hepta closure evidence contracts | [43030977436](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43030977436) | success |
| HEPLCP04 structural readback | [43030977516](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43030977516) | success |
| PoN original large-state CPU acceptance | [43030977477](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43030977477) | success |
| PoN original workspace test-profile CPU acceptance | [43030977526](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43030977526) | success |
| PoN priority acceptance | [43030977438](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43030977438) | failure: 7 failed / 6 succeeded / 1 skipped jobs |
| trnm-required-baseline | [43030977601](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43030977601) | failure: 11 failed / 10 succeeded jobs |
| PoN owned process cleanup | [43030977513](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43030977513) | failure: 6 succeeded / 2 cancelled jobs |
| CodeQL exact-source analysis export | [43030977440](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43030977440) | failure; previously archived transport refusal |

For the source-bound failures below, **H** means actual checkout `e338c000f26e9357ed33213624da787a3a009ed9` / tree `876aa62d1ab49458d29e9168f4c69e7b47b8884b`; **M** means actual prospective merge `bfa5cf58953a67dd9b9a27ce52b63524933a029d` / tree `4b08c77fd511466c8f2e5bc46307e0d6fd629063`, with fixed base `c84162378f34b9284e90587df4c466dfee3e193b` and H as parents. Run-level `head_sha` is not substituted for a job's actual checkout.

### Priority acceptance

The historical-artifact job `130582693678` performed no checkout. It requested artifact `11531476198` from historical run `37730166589`, found zero artifacts and failed. The reason that artifact is absent remains unknown.

The service-model jobs failed in both H (`130582694482`, `130582694747`) and M (`130582694472`, `130582694530`); the x64 history jobs also failed in H (`130582694631`) and M (`130582694539`). Their original control steps exited 1, with host summaries reporting `systemd_run_exit=1`, `failure=null` and `final_host_errors=[]`. These are actual child failures, but the retained job summaries do not expose the child assertion/stderr, so a product/environment cause or timeout is not inferred. The ARM history lanes are successful in metadata; those results do not erase the x64 failures.

### Required baseline

- **From-zero controls:** the cross-architecture H jobs `130598327693` and `130598327905`, and protocol-contract jobs H `130598327819` / M `130598328085`, failed in the original from-zero control step with the same incomplete child-error summary. Earlier successful protocol groups do not make these jobs successful.
- **Dependency policy:** quality jobs H `130598327708` / M `130598327796` refused one or more dependency graphs and retained a `supply-chain` failure. Specific graph/advisory details are not printed in the original logs; no particular dependency or vulnerability is asserted.
- **External evidence:** jobs H `130598327976` / M `130598328088` hit the original `selected_body` hash check in `check_public_readiness_evidence.py:501`, reporting `ValueError: durable backend selected implementation`. Repeated invocations each report 71 methods, 46 failures and 22 errors, many because this earlier rejection replaces the negative control's intended later schema error. This is one observed hash-gate rejection pattern, not 68 independent root causes; repeated invocations and lanes are not summed. The logs do not establish whether the current source or reviewed reference is responsible. No reference hash was refreshed.
- **Runtime:** only the **M** runtime job `130598328213` failed: `ordinary_npq6_witness_selection_dispatches_account_packet_without_owner_downgrade` unwrapped a transport `Connection reset by peer (os error 104)`; that binary reports 5 passed / 1 failed, with Cargo exit 101. The server-side reset cause remains unresolved. The **H** runtime job `130598327706` is successful in the original job metadata; the M failure is not attributed to H.
- **Aggregation:** H `130669194540` / M `130649216164` rejected the unsuccessful Rust shard set. These aggregation refusals are not additional independent native failures.

### Cleanup and previously archived CodeQL

Cleanup's two macOS jobs (`130557620566` prospective, `130557620949` head) have metadata reporting cancellation, zero steps and no assigned runner. Both original log requests returned `404 BlobNotFound`. Their checkout, execution and cancellation reason remain unestablished; the six other cleanup jobs succeeded.

The previously archived CodeQL failure remains `GitHub GET /pulls/909: transport failure; no fallback`; its post-run source guard verified H. This update does not reread or reclassify that log.

The complete source-bound index and original failure bytes are retained on a separate evidence commit: [README](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/__CHAIN_FINAL_CI_EVIDENCE_HEAD__/qualification/chain-pr909-final-ci-20261112/README.md) · [INDEX.json](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/__CHAIN_FINAL_CI_EVIDENCE_HEAD__/qualification/chain-pr909-final-ci-20261112/INDEX.json). Length/hash/base64 containers preserve original BOMs, line endings and meaningful whitespace without trimming. The evidence commit does not advance this PR's tested code head.

The earlier structural qualification remains scoped to its exact sources and methods. These broader CI results add no ordinary business closure, independent C adoption or ordinary NoUpdateRollback; this PR remains open Draft.
