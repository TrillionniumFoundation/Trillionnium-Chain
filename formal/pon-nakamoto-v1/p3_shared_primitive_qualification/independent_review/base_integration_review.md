# Read-only base integration review

**Conclusion:** the examined changes preserve the legacy SHA component 1 and
packed-carry component 4 semantics. I found no integration conflict with the
separate, independently parameterized tagged SHA3 profile in these two files.
This is a model-assisted source-delta conclusion, conditional on retaining
the required module declarations and running the final merged-head gates.
Qualification remains **HOLD_NO_GO**.

## Exact scope and identities

I read Git objects and the complete two-file diff from
`cc836dfc13ef0006eb0878abd8cb5eca9a76bec0` to
`09fbc0f45151a68a1bf205641171840fbf309882` in the desktop worktree. Commands
used exact commit IDs, disabled external/textconv diff helpers, and made no
native edits, builds, tests, commits or checkout changes. Both read jobs exited
0 with complete, untruncated stdout and empty stderr. Their object identities,
SHA-256 hashes and complete diffs are retained in
`base_integration_review_receipt.json`.

All file paths below are relative to
`formal/pon-nakamoto-v1/w1_public_stark_research/`.

| File | Base Git blob | Target Git blob |
|---|---|---|
| `src/proof_config.rs` | `4001a5064ad9944c741ccc5f4d19df18fc3ea16c` | `1c6f2028dd753e611112ba8b7a3d85a8585eb635` |
| `src/proof_wire.rs` | `5cc315bc6afd9f5224e3f66e95f5863efaa8a1ca` | `a90cdce7e7c8cea049d9a573f6ea42ac62ec979c` |

Target SHA-256 identities:

- `proof_config.rs`: `98876ea9e223f90079f69bd6f1f75f6a17b9988ed9412fdda8a16bc40367aebf`.
- `proof_wire.rs`: `e8660e3b91849f538713b32835035f0eb39425326268dd9302b3c7b01b090921`.

## Findings

`proof_config.rs` adds `SCHEDULE_SHA_COMPONENT = 5` and admits it in the
legacy configuration constructor. The field/extension aliases, Poseidon2,
MMCS, transcript domain, FRI settings and grinding settings are unchanged.
For inputs 1 and 4, the broadened allowed-component assertion has the same
result and the remainder of configuration construction is unchanged.

The private metadata helper becomes generic over the SHA AIR and takes its
height/component explicitly. Existing public wrappers continue to supply
`W1ShaAir`, its original `trace_height()`, SHA component 1, and their original
arithmetic component, including packed-carry component 4. Their existing
metadata inputs therefore remain the same. The new scheduled-SHA wrapper uses
component 5 separately; it does not replace the old wrapper. The conditional
security disclaimers, unknown complete/quantum/lifecycle fields and
`HOLD_NO_GO` remain intact.

`proof_wire.rs` adds a distinct `ScheduledSha` selector and `W1P3SCS4` magic,
with its own width/preprocessing-width branches. The old `Sha` and
`PackedCarry` arms retain their magic, widths, degrees (13 and 14), quotient
chunk counts (2 and 1), and next-row behavior (true and false). Grouping
`Sha | ScheduledSha` for the common degree/quotient/next-row values does not
change the result for `Sha`. The scanner and limit-counting algorithm below
the selector helpers are unchanged.

The reviewed tagged profile uses its own field alias, parameters, component
enum, configuration and wire module. It imports neither legacy
`proof_config` nor legacy `proof_wire` in its three implementation files.
Its closed component conversion still accepts only 1 and 4; adding legacy
component 5 does not extend the new profile. Its `W1S3SH01`/`W1S3PC01` magics
remain distinct from the new legacy scheduled-SHA magic. No silent switch to
the scheduled SHA AIR follows from this diff.

## Integration caveat

The final `lib.rs` must retain `sha_schedule_air` as well as both tagged module
declarations. The root agent reported that the existing AIR/public/sha-plan
and Cargo files are unchanged across this advance; I did not expand this
two-file review into a full review of the ten intervening commits or the new
scheduled AIR. The final conflict resolution and merged tree were not the
subject of these exact-object reads.

Run the exact merged-head source, formatting, build, test and verification
gates before reporting integration success. Keep existing native/ABBA receipts
bound to their actually measured source snapshots; this review does not
relabel them as merged-head execution. No cryptographic security gate is
closed here, and no pruned/MMCS proof mapping or attack construction was
developed or reviewed.
