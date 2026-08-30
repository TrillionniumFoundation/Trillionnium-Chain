# A21 / P1 sealed native commit-receipt verifier v1

Status: **repository-owned candidate hardening; no production activation**

## Exact source boundary

```text
candidate_branch = feature/chain-g1-external-blocker-closure-20260830
candidate_code_closure_commit = c0e309743f9696c8ee8bc035ff4c427df4d0eb25
candidate_code_closure_tree = 3b46b2e72879afb4750aab61ebab955ef2c375d1
remote_tip_inspected = feature/chain-a21-p1-seal-native-commit-verifier-v1-20260830@b58665a783c0e1bcceb33455acde65ee6ada4034
remote_verified_source = c05364e7324fe3ff2c4a8b22322698a0cddd5dc1
remote_verified_source_tree = a8626c41ea26bfb808d5a4aba07082849077954e
remote_workflow_run = 33315186665 (payload) / 33315186656 (required baseline)
production_candidate = false
production_consensus_activation = false
```

The remote source and commits are unsigned GitHub objects.  The exact remote
baseline and payload jobs passed, while actor-gated PR jobs were skipped.  The
remote branch is not the canonical branch and was not merged; this document
records a read-only comparison plus the equivalent safe sealing already present
in the local candidate.

## Capability-forgery boundary

`NativeCommitReceiptVerifierV0` now has a private sealed supertrait.  Only the
crate-owned durable verifier and explicitly named in-module test verifiers can
implement it, so downstream crates cannot install an unconditional `Ok(())`
verifier and mint `VerifiedNativeCommitReceiptV0` from caller assertions.  The
token remains opaque and the candidate commit path still requires exact native
application readback, receipt binding, block identity, state root and carried
PoCO proof.

The companion replay-floor verifier used by A20 is sealed by the same style of
private capability boundary.  These changes close repository API substitution;
they do not supply a production Core/Safety owner, live finality loop, signer,
broadcast path, external anchor or independent review.

## Local verification

At the code-closure source, the native commit sealed-authority regression,
A20 tombstone tests (5), the complete `trnm-poco-node` library suite (158),
strict Clippy and the payload-recovery gate passed.  The A22 deterministic
authority inventory still reports five findings (four candidate-P0 seams and
one review-required native verifier seam), so this package is not an
independent audit or a blanket claim that every public verifier interface is
sealed.

All release and activation claims remain false.  Independent exact-source
review, real multi-host campaign, HSM/monotonic anchor, physical power-loss,
independent audit and soak/activation evidence remain external blockers.
