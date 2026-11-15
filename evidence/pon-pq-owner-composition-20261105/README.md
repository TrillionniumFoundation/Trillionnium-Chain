# Fixed-parent PQ owner composition — 2026-11-05

Status: **source composition prepared; native acceptance pending; HOLD_NO_GO**.
No test result from either parent is a test result for the combined source.

## Fixed inputs and preserved evidence

- First parent: [#688 source 84179f7b0f74bdc0152f904ffbf0b11709eec036](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/84179f7b0f74bdc0152f904ffbf0b11709eec036).
- Second parent: [#698 source 42b5ca15e271779bc5a66efe1987b485140d3880](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/42b5ca15e271779bc5a66efe1987b485140d3880).
- Merge base: `e94781d2323f5dc8987e1eb7ed2bef23ee8745c3`.

The complete source-tree comparison found 77 second-parent-only changes,
1,655 first-parent-only changes, seven identical changes on both sides and
14 differing overlaps. Eleven overlapping texts merge without conflict.
Existing binary evidence and historical logs remain their original Git blobs.
Historical native failures, including SIGKILL, do not become success or disappear.

## Conflict decisions and new boundary fix

| Surface | Composition decision |
| --- | --- |
| PQ corpus manifest | Preserve identical non-pin contracts and every false acceptance flag. Union both required-path and source-pin sets, add the public-submit owner and regression, and recompute pins against the resulting source tree with the existing Git-blob formula. No test qualification is inferred from pins. |
| Sole development plan | Both conflicts are concurrent insertions with empty common-base sections. Preserve both additions and their source attribution; append this pending-acceptance continuation. |
| Recovery/release boundary | Retain the more explicit #698 descriptions of direct checkpoint-API refusal, complete journal checks, and current publication expiry/root generation. These describe implementation blobs already identical in both parents. Preserve #688's current Cell authority-view paragraph and #698's independent SDK paragraph together. |
| Required-native workflow | Keep the current 52-entry roster; correct the stale 49-entry assertion. Preserve exact nonzero selector execution and child-harness exclusions. Run the new public-submit refusal separately and retain the complete classical recovery target. |
| Classical public-submit recovery | Require the actual Node's classical network profile before packet reads or network calls. A PQ-only transport namespace with a classical account ledger must refuse with `PQ_NETWORK_REQUIRED`, including after cold reopen. |

The public-submit regression uses the actual PqNetworkV2 owner, an original
nonempty mined/admitted packet and a bound nonblocking TCP listener. It requires
zero calls, zero connections, no uncertain submission, and unchanged Node/PQ
ledger observations. It does not supply a PQ parent-recovery implementation,
independent keys, an external rollback service or production startup evidence.

## Required new execution

Record the final committed source and tree, compiler, provider, binary and exact
command with the existing native recorder. Run the current 52 required controls
in their original order, using the existing nonzero-test reader. Also retain the
complete PQ ingress and operator auth/startup families, including all four new
canonical tests, the complete Node library, and the public-submit integration
target. Compute family unions from the final binary registry; historical 49/94
counts do not replace current selectors.

Run CPQ1 profile/retirement/encoding and complete-signature budget tests, their
compile-fail contracts, checkpoint/release/Cell current-authority controls, the
independent OpenSSL/TUF controls, exact locked graphs including the separate
fuzz graph, formatting, strict all-target Clippy, negative source-integrity
tests and repository links on the combined source. Keep original W1, F0,
four-second/16-hostile-producer and independent confirmation gates unchanged.

All combined-source native execution is **NOT_RUN at this preparation point**.
Source composition and a passing source guard do not supply independent
cryptographic audit, W1 quantum-effective cost/security, pre-exposure ownership,
independent monotonic custody, PQ listener confidentiality, production WAN
deployment, or a complete Hepta CURRENT/FinalUse/Chain acceptance pair.
All six whole-chain domains remain **UNQUALIFIED**, and production activation
and every inherited whole-chain promotion flag remain false.
