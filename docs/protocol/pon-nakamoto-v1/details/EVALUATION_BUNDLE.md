# E3 — immutable evaluation inputs and bounded consumer consent

Owners: M16 produces candidates and proposed controls; M11 evaluates; M09 validates
artifact bytes; M10/M12 consume the resulting evidence through their existing paths;
M14 validates the complete service receipt before asking its actual owner to sign.
No new trainer, artifact registry, authority issuer or chain store is introduced.
This is a stricter controlled-experiment producer contract, not a consensus encoding
upgrade or a declaration that normal Agentd has a PoN destination.

## Claim and actual caller

`evaluation_bundle.py` seals the exact current artifact, candidate, four materialized
control artifacts, calibration selection, task partitions and statistical policy.
`model_loop.py --mode evaluate` requires both the bundle file and the expected bundle
hash from its admitting caller. The former unbound `--reference` alone now fails with
FROZEN_BUNDLE_REQUIRED before any output score is written. A digest read from the same
untrusted file is not an independently admitted expected digest.

`settle_model.py --bundle-hash` verifies the caller's expected bundle, candidate bytes
and task identities, then recomputes both named evaluation partitions. It compares
predictions, whole and marginal scores, and the selected reference with BOTH stored
per-evaluator reports and the aggregate report before constructing any signed test
transaction. Editing both report copies does not avoid this recomputation. No-gain or
zero-marginal results produce not_adopted/zero reward without opening a new ledger.
This does not turn the development attestors into independent operators or alter the
chain's explicit attestation trust model.

## Fixed object and identity

Schema: `pon-evaluation-bundle-v3`. Canonical bytes use the existing canonical JSON
rules. Bundle identity is `H("evaluation-bundle-v3", bytes)`; all model identities use
`H("artifact", canonical_model_bytes)`. A complete bundle is at most 2 MiB, including
all models. Every embedded model uses the existing 64 KiB integer-model shape and
range checks. No pickle, executable plugin, floating-point score or authority field
is admitted. Network and parameter commitments are explicit and must match locally
installed values; the consensus genesis configuration is unchanged in this increment.

The closed fields are schema, network, parameters, source_commit, round,
parent_release, parent_artifact, candidate_artifact, candidate, controls,
control_artifacts, selected, calibration_lock, control_macro_scores, partitions,
policy and scope. Source commit is forty lowercase hex characters; digest identities
are sixty-four lowercase hex characters. Rounds are positive u64 values; booleans
are not integer aliases. The current control must equal the actually admitted parent
artifact supplied by the caller, not the previous unaccepted candidate.

Each partition binds row count, sorted unique source groups, full canonical task
commitment, sorted task-ID root and normalized-content root. The producer rejects
cross-partition task IDs, source groups and exact normalized source-content overlap.
Identical features are not proof of identical source content; semantic near-duplicates
and source-owner authenticity still require their own evaluation policy.

The evaluator checks the complete named partition against this manifest, then replays
the calibration predictions of all four materialized controls and verifies their exact
reduced scores, deterministic selection and lock. A self-consistent rehashed claim of
stronger calibration performance cannot substitute for this replay. Train or calibration cannot be relabelled as evaluation. Changing a label,
feature, group, content identity or candidate produces a different commitment and is
rejected under the original expected hash. Hash verification authenticates equality
with the caller's record, not the provenance, independence or future time of that record.

## Strongest deployable baseline, not strongest file size

The four controls are current, best_single, mean_merge and pooled. They are real
materialized parameter bundles usable by the normal integer inference contract;
no control is just a mutable mode flag or unbound array of predictions.

Best-single selection and final control selection use mean accuracy over source
groups, with equal weight per group. Thus one hundred correlated snippets in one file
cannot outweigh two independently named one-snippet groups simply by repetition.
Calibration scores use reduced numerator/denominator decimal strings (each at most
2,048 ASCII digits, no sign or leading zeros). Exact rational scores can exceed u64
without introducing floats or changing the consensus canonical-JSON integer bounds.
Ties use the declared order above and the lowest expert index. Mean deltas use exact
rational ties-to-even rounding. Candidate weights are never changed after sealing.

Evaluation requires at least twenty source groups and the four-comparison corrected
one-sided group-direction test. It additionally requires positive mean group gain:
a majority of tiny improvements with larger overall losses does not pass. Labels and
predictions are integers in [0,2], not booleans or coercible strings. Corpus rows are
bounded to 32,768 and source groups to 4,096; statistical gates cannot be lowered by
caller parameters. Inputs are read with explicit byte ceilings before JSON parsing.

## Atomic boundary and crash behavior

The producer writes the new bundle with exclusive-create, flushes and fsyncs the file
and containing directory, then passes its returned hash to evaluation. Existing paths
are never overwritten. An interrupted partial write fails canonical/digest checks; it
is not reclassified as a complete plan. This is a producer output artifact, not an
independent monotonic authority or the Hepta publication journal. Actual public export
must still pass the existing learning-artifact owner, current withdrawal head and
kernel.operations intent/outbox. Renaming a downloaded bundle into this directory
cannot grant those permissions.

## Three attempts and genuine future generations

The existing `learning_cycles.py` now seals and evaluates this object in each real
training attempt. It still begins from the actually admitted parent and retains
no-update outcomes. Source-file pools are disjoint, but remain retrospective public
repository inputs; neither a CLI flag nor wall-clock execution turns them into
independent future user experience. `future_window_observed` and public reward authority
remain false; a caller's unverified future claim is separately labelled.

Three genuinely improving public generations require new authorized experience,
independently admitted source/time/withdrawal records and a normal Hepta destination.
This producer cannot mint those records. Existing losing/zero-reward runs are retained.

## Full inference consent

`inference_receipt.verify` requires every expected field, including output, units and
provider_nonce, before returning a digest to be signed. The consumer must bind the
actual received output bytes and agreed service charge/nonce, not merely its model
and input. All counters are strict positive integers. Oversized receipt bytes reject
before JSON parsing. Receipt digest/signature encoding is unchanged; this closes a
permissive client precondition, not a new consensus protocol.

## Threat-derived tests

`test_evaluation_bundle.py` contains exact counterexamples for changed control weights,
weaker control selection, parent/candidate substitution, task/group/content leakage,
boolean types, lowered multiplicity, unknown authority fields, malformed/partial locks,
positive direction with negative mean, actual worker invocation and forged settlement
reports. `test_inference_receipt.py` additionally checks omitted cost/nonce/output and
bounded parsing. The invariant registry binds exact selectors. Test success proves
those executed cases, not universal model safety or independent scientific acceptance.

[Current executed evidence](../../../../evidence/pon-evaluation-bundle-v1/README.md)
retains source identities, all raw results and the no-adoption/zero-reward outcome.
