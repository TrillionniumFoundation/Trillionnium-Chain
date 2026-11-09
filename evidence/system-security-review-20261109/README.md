# Eight-boundary system security evidence review, 2026-11-09

**HOLD_NO_GO — DENY_ALL.** This packet is a current execution of a read-only
review of retained materials. It is not a new native campaign, training run,
independent evaluation, provider effect or production acceptance.

The implementation continues #835 at
`e2a02f9271b49f146e70806c8a66e161b5973971`, tree
`86d2014b560659106b3af6e6c19e1f82a290a60e`.
[The contract](../../docs/security/SYSTEM_SECURITY_BLOCKERS_V1.md) explains the
eight rows, independent stage detail and authority boundary.

## Inputs and source meanings

| Input | Retained fact | Source meaning |
| --- | --- | --- |
| `inputs/fixed-probability.json` | All 16 classical/quantum cost points have null lower/upper bounds; 10 obligations remain open. | Exact contract bytes from the #835 baseline. This is a source declaration, not a cost measurement or all-strategy proof. |
| `inputs/joint-consensus.json` | Seven limitations from the earlier joint-consensus report. | Explicit limitations-only extraction, with the full original report hash. Historical execution source `06cb1834de5dc4a42bd54eba0f5a4491686b9cb0`, tree `e881dd7cf318a562b09de38ff7774a508724fa18`, is retained. |
| `inputs/campaign.json` | 0 complete campaigns out of 3; 27 planned confirmation rounds, 12 observed, 3 confirmed and 15 unobserved. | Exact stored JSON from delivery `c2297ad53fef1d9b552e657cfd205d583c91980d`; its execution source remains `11791e2da79b69322271be2cffe03725165151d1`, tree `162552848110fda532504b78865a16930bc6d9bb`. |
| `inputs/resource.json` | Local resource-owner physical coverage, honest service and independent rollback qualification remain false. | Exact #830 contract bytes at `bb3f13ed78edd367381275a3ae4752f1f4da4c22`, tree `ece61caafae0b994f16ed3f744c35297ccc45cd8`; this branch is not included in #835. |
| `inputs/completion-readback.json` | Original completion reader retains its explicit training/settlement/FinalUse limits. | Unmodified 7,135-byte aggregate reader result, retained as one engineering-control record. It is not converted into separate authenticated training, evaluation or payment receipts. |

`security-inputs.json` supplies the exact upstream URLs, source declarations and
SHA-256 values for the first four inputs. The last input has its original locator
and SHA-256 in `packet.json`. The joint-consensus extraction has a distinct schema
and is never described as the complete original bytes.

The frozen `plan.json` describes this audit's reference context, not a frozen
native experiment. Its Hepta reference is the original retained runtime source
`edf03ecb8a814a0f5e86b1d6a752aeac80b1a978`, tree
`c7588a07d20310059d4016559fa550d397b7eb09`. No latest-Hepta or new paired execution
claim is made. The profile hash names the baseline
`config/pon/public-resource-profile-vectors-v1.json` bytes. Actual loaded
executables, environment closures and Hepta lock observations are absent and
remain null. Native case rosters remain unconfigured, not waived.

The retained completion record has no asserted native exit, no assigned learning
stage and zero reported test counts. Its original collector exited zero, but the
normalized audit outcome is UNKNOWN. `learning=null` means that this packet does
not supply the complete typed stage sequence; it does not assert that no real
training has ever occurred elsewhere. The new stage view therefore preserves
missing stage evidence instead of manufacturing receipt identities.

## Reproduce the read-only report

From the repository root:

```sh
python3 scripts/ci/chain_system_security.py \
  --plan evidence/system-security-review-20261109/plan.json \
  --plan-sha256 a4c34a0389320bdce8117124662c7d11ac3e29ee0bd511e3e27c02a329984553 \
  --packet evidence/system-security-review-20261109/packet.json \
  --evidence-root evidence/system-security-review-20261109 \
  --security-inputs evidence/system-security-review-20261109/security-inputs.json
```

The expected exit is **2**, indicating a valid HOLD report. Exit 1 indicates an
input refusal. Neither is a native-success status. The generated `review.json`
preserves the original seven-gate review, all eight system-security rows, the
stage projection and the four schema-specific source classifications. Same
declared source is still unauthenticated; historical declarations never count
as current acceptance. No authority or qualification field becomes true.

## Validation scope and retained development observations

Component validation covers the stage reader, command binding, the system
projection, its mandatory CI placement and the current source corpus. Final
source-bound execution records are delivered separately from the implementation
commit so that adding logs cannot change the source identity attributed to a run.

The development records preserve a real CI-source check failure: duplicate
reader commands placed in another lane were initially not refused by the new
guard. The corrected guard checks global uniqueness as well as placement in
`repository-truth`. The original native selectors, budgets, order and vetoes
remain unchanged. A separate system-reader fixture initially expected unresolved
Unknown after a later query had already reconciled it; that assertion was
corrected without changing effect semantics, and its failed observation remains
in the development logs.

The workspace interruption left some source-materialization commands without
recorded completion. Original pinned files were re-read from the exact Git tree
and checked before use. Interrupted operations are not counted as passed tests.
Full native/workspace acceptance, physical independence, WAN service, model
benefit, settlement and FinalUse remain open. The separate #837 SQLite cleanup
is not imported into this source or counted in this report's component results.
