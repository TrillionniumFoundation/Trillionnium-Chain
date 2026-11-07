## Retained historical PR description

This is the Cell section observed in PR #688 before this new implementation was
integrated. It is historical, includes unfinished work from an absent checkout,
and does not grant acceptance to the new source.

## Cell residency — published baseline and interrupted continuation

Published baseline `5c070abeb61d0ea8702fa94fffe9330d1699119c` remains the shipped candidate increment: finite immutable chunk residency, hot/selected pins, versioned local mappings and deadline-bound local selection. Its exact-source 223 native + 8 doc controls and evidence remain [here](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/5c070abeb61d0ea8702fa94fffe9330d1699119c/evidence/cell-residency-20261104/README.md).

**2026-11-05 continuation is uncommitted and NOT accepted.** The execution environment became unavailable during final fixes. No new Cell source commit was pushed by this continuation.

Before the later readiness edits, the local candidate passed 337 M09 native tests + 8 doc controls (0 failed/ignored), 23 sealed-worker/framing/startup controls, 91 source-negative controls and both locked dependency graphs (fuzz:148 packages; metadata only). The byte observer passed:70,656 cold bytes,4,096 new adapter bytes,74,752 unique resident bytes,1,000 local reads after provider shutdown. These results do not validate the subsequently edited source.

Implemented locally: sticky transport cancellation; one cross-closure prefetch deadline/byte/dial/request budget; duplicate-pin constraint intersection; sealed-FD Python handoff with retained bytes reserved inside the original 8GiB.

Still open at interruption:
- Opt-in provider Ready event/API and same-35s-budget client waiting were edited; Rust formatting, compilation and final native/Clippy gates are pending.
- Real 272,189,990-byte cold transfer failed on its first manifest response-header request at 2.041s; consumer admitted 0 bytes. The 35s aggregate limit was not extended. Resource pressure was observed but causation is unproved.
- Native Hepta compilation hit SIGKILL with an OOM counter increment; no native model load/query/unload passed.
- Full private source-closure execution and typed cooperative sealed-supervisor cancellation remain incomplete. A real negative control showed direct SIGINT can leave the inner child live during constructor adoption; fixture children were cleaned.
- Fresh parent/source pins, V10 freeze, exact committed-source gates and publication remain pending.

Workspace recovery root:`/workspace/scratch/a3c4a3b1a304`. Keep Draft/HOLD; no production, FinalUse, WAN, shared-FP32/GPU or distributed-inference acceptance.
<!-- cell-residency-20261104-end -->

---
