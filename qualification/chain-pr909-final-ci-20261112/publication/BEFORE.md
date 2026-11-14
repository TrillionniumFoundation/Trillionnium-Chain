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


## Broader CI snapshot (2026-11-11 15:16 UTC)

The HEPLCP04 structural workflow on this evidence head completed successfully. The work/time and closure-evidence contracts, original large-state CPU acceptance and original workspace test-profile CPU acceptance also completed successfully. These are separate gates and are not added into an ordinary adoption/FinalUse count.

The complete repository CI is not green: [CodeQL export run 43030977440](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43030977440) failed after polling, with the original log reporting `GitHub GET /pulls/909: transport failure; no fallback`; its post-run source guard still verified e338c000 / tree 876aa62d. [Owned cleanup run 43030977513](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43030977513) retained successful Linux head/prospective-merge jobs and cancelled macOS jobs; the cancelled macOS log endpoint did not provide a log, so no cause or execution PASS is inferred. Priority acceptance and the required baseline were still running at this snapshot.
