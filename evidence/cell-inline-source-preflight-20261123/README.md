# Private source-trained candidate exposure preflight

The private training owner embeds `paired_source_exposure` in the frozen candidate it produced. The source owner can keep its freeze in a per-operation directory while the original weights and tokenizer remain under the model root. The plain-model evaluator accepts these two paths separately. It binds the canonical digest of the embedded exposure in its source listing, which the existing funded contract binds as its evaluation protocol. An externally registered catalog, when present for the same freeze, remains part of the source listing and is checked alongside the manifest. The prior catalog-only development payment remains reproducible. [Original paid fixture](../cell-released-pair-funded-evaluation-20261123/README.md)

The uncommissioned qualification used the existing engineering candidate `a44f85e1484f904e1fbd5c4e6c0d5804e636073f33ade25a158ee4f94c8e0336`. Its original qualification recorded a correct parent response and a failed candidate response on the retention item. The decision was `NoUpdate`. A separate process inspected one artificial request, verified both model inventories and both tokenizers' input checks, and read the inherited source exclusions. Changing the exposure commitment failed. Changing the manifest under the original freeze failed. Presenting a different freeze with the original exposure commitment also failed. The inspection created no native reservation, inference prediction or payment. This published observation contains the hashes and counts. Original source records and model materials stay with their owner. [Observed commitments and refusal results](OBSERVATION.json)

## Inspect an authorized request

Run from the Chain repository root with a private model root, exact freeze, checkable paired request and pinned Hepta source. Provide previously retained digests and the CPU environment used by the Hepta evaluator. The source-trained evaluator must include its original source-exposure checks. The final output is a commitment to the checked materials. The job directory must be new.

```sh
export TRNM_DEV_FROZEN_FILE=/private/paired-training/operation/FROZEN.json
export TRNM_DEV_PAIRED_REQUEST_FILE=/private/paired-intake/released/paired.json
"$TRNM_DEV_HEPTA_PYTHON" -B scripts/dev_intake_evaluation.py inspect-source \
  /private/new-inspection "$TRNM_DEV_HEPTA_MATERIALS" "$TRNM_DEV_HEPTA_SOURCE" \
  "$retained_freeze_sha256" "$retained_request_sha256" "$retained_candidate_sha256"
```

For an eligible, separately commissioned research candidate, the existing released-request dispatcher accepts the same optional `TRNM_DEV_FROZEN_FILE`. It requires the independently retained intake release for the exact study, request, candidate and original freeze. The request, freeze and source remain in a private job directory. The chain stores commitments. Local input compatibility cannot authorize an expenditure or establish retention, participant independence, commercial demand or subsequent use. Those decisions require their original qualification, user and payer evidence. No new native service order was commissioned for this candidate.

## Owner retention prerequisite for paid source-trained work

A source-trained candidate released with `scope=owner_intake` must carry the canonical `source_retention_sha256` in the **original Hepta release**. The private owner witnesses this digest at freeze, before receiving the incoming task. The Chain launcher supplies the canonical release digest obtained separately from that protected intake. Receiving a caller's JSON and accepting the caller's own hash cannot establish its origin.

The dispatcher reads the original source owner's `RETENTION.json` next to the freeze, or from the operator-supplied `TRNM_DEV_SOURCE_RETENTION_FILE`. Before creating a funded admission, a separate offline process invokes Hepta's source-dispatch verifier on the captured freeze and report. The report must cover every frozen retention item in order, include a demonstrated parent success, retain every such success, carry owner scope and record zero prospective records read. The signed contract request covers the same retention digest and original release. Delivery and ledger readback recheck both commitments. Research fixtures remain explicitly labeled. The historic #7022 pair uses its original release format.

Four synthetic refusal controls exercised the paid dispatcher's prepare stage with the observed `NoUpdate` candidate. A pre-qualification release failed before the task file was opened. The original `NoUpdate` report failed. Swapping it for an eligible-looking report broke the retained digest. Even with a synthetically re-pinned positive label, the Hepta verifier rejected the failed old item. All four returned before creating the signed admission, any reservation or any model prediction. [Owner-dispatch refusal observations](OWNER_DISPATCH_REFUSALS.json)
