# QROM source-identity diagnosis and local validation

This package preserves the original failed Actions evidence and three distinct local attempts. It does not claim that the replacement workflow has passed hosted Actions or that cryptographic soundness or production admission is qualified.

| Evidence | Result and scope | Payload |
| --- | --- | --- |
| Original Actions head and prospective merge | Both failed; 81 required names, 67 started, 63 successful in each job. Original V1 reader rejected the changed verifier input. | `head.zip`, `merge.zip`, full job logs, `DIAGNOSIS.json` |
| Historical validation 1 | Original 81 required / 81 started / 81 successful; full historical tracked source identical before and after; all original stages passed locally. | `historical-validation-1.tar.gz` |
| Current validation 4 | Final 75 required / 75 started / 75 successful; current V2 mapping completed with qualification HOLD; four owned QROM source files identical before and after. This is component worktree validation, not a complete committed-source or hosted-workflow gate. | `current-validation-4.tar.gz` |
| Interrupted validation 3 | UNKNOWN_EXECUTOR_UNAVAILABLE; only the two original preliminary files survive and no completion receipt was recovered. | `interrupted-validation-3.tar.gz`, `interrupted-validation-3-status.json` |

## Original failure and identity

Canonical run: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42575267240

- Head job `129021450451`, artifact `13654917681`, commit `e2a02f9271b49f146e70806c8a66e161b5973971`.
- Prospective-merge job `129021450202`, artifact `13654499724`, commit `459eb070e8c631bb387b5d4ac362c3e43e945af1`.
- Both tested tree `86d2014b560659106b3af6e6c19e1f82a290a60e`; complete source before/after matched within each job.
- Exact original refusal: `input exceeds bound: formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs`.

The historical reader uses each contract's exact historical byte count as its bound and then checks exact length and SHA256. The verifier changed from 9,233 to 11,172 bytes; a second pinned project input, `pon_wire.rs`, also changed. Increasing a generic cap would not satisfy the original identity contract. The preserved diagnosis classifies this as historical source-pin drift. No cryptographic soundness break is established by this integration refusal.

`DIAGNOSIS.json` is the unmodified original readback snapshot. Its `fresh_current_mapping_executed=false` describes that earlier diagnosis; the later mapping observation is separately recorded in current validation 4.

## Historical and current lanes

Historical validation 1 replayed the original embedded runner and original 81-name roster on exact commit `0c830e0be8939ce80c8443c9ad68021b87343a00`, tree `273d0c1c69cd9bdfb85dc027bfdd8a49c2121c2c` (11,470 tracked entries; 1,110,561,461 tracked bytes). The archive includes all execution logs, source receipts, reports, original extracted entry scripts and the command record. The detached historical checkout used read-only `project-preflight.sh --audit`; its successful output is retained.

Current validation 4 includes all final component-run logs and receipts. The original V1 CLI really exited 2 on current source, with its exact stderr and empty stdout retained. `historical-drift.json` records two selected source-pin changes and `historical_v1_on_current_passed=false`; the wrapper's successful observation does not turn that refusal into a V1 pass. Current V2 closure mapping and the new 75-name roster have their own report and scope. Four-file before/after identities bind the final QROM workflow, runner, test module and roster; they are not a complete repository receipt. Earlier successful predecessor runs are not added to these counts.

All soundness, production and consensus qualification flags remain false; unconditional quantum security bits remain null. Complete candidate-source, hosted workflow, final commit and publication results are reported separately by the integration owner.

## Integrity and storage

`manifest.json` records the SHA256 and length of every payload, original uncompressed logs and every ZIP/tar member. The two ZIPs retain their exact downloaded bytes. Gzip uses an empty filename and mtime 0; tar members are sorted with mtime 0 and neutral ownership. `SHA256SUMS` also covers the manifest. No temporary full source checkout is included, and no signed download URLs are used.

To inspect locally, verify `sha256sum -c SHA256SUMS`, decompress logs with `gzip -dc`, and extract each validation archive with `tar -xzf`. Historical archive entry scripts are the exact executed workflow snippets, not a replacement implementation. Keep the interrupted-attempt annotation separate from its untouched original files.
