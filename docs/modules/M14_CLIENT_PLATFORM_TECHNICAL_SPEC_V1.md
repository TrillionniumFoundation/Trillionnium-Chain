# M14 Client currentness, model loading and user results

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Closed service-consent receipts and fully verifying reference client observations; neither is a local capability.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M14.QueryCurrentState

Read active pointer and generation kv in one snapshot and recompute root; return no unconditional finalized flag. A production confirmation adds depth/work evidence and freshness; localhost ACK is not independent proof.

**Atomic/commit boundary:** Indexer is derived; cursor(generation,ordinal), no new balanceauthority.

### M14.ConsumePublishedModel

Consumer consent binds expected network, parameters, model, request, input, provider and quota; no opaque result hash silently substitutes another service. Check exact consumer expectations and canonical bytes; signature also binds full genesis parameter context. Confirmation reads one active view, validates all memberships, and checks that tip/generation still match before returning.

**Atomic/commit boundary:** Check exact consumer expectations and canonical bytes; signature also binds full genesis parameter context. Confirmation reads one active view, validates all memberships, and checks that tip/generation still match before returning.

## M14.ServiceReceiptBinding

**Invariant:** Consumer consent binds expected network, parameters, model, request, input, provider and quota; no opaque result hash silently substitutes another service.

**Scope:** Closed service-consent receipts and fully verifying reference client observations; neither is a local capability.

**Atomic boundary:** Check exact consumer expectations and canonical bytes; signature also binds full genesis parameter context. Confirmation reads one active view, validates all memberships, and checks that tip/generation still match before returning.

**Failure schedule:** Replace every receipt field; Missing expected identities; Extra authority field; Noncanonical bytes.

**Expected result:** Consumer consent binds expected network, parameters, model, request, input, provider and quota; no opaque result hash silently substitutes another service.

**Resource and retention rule:** Fixed digest identities, positive bounded counters and no hidden reduced deployment profile.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_inference_receipt.py::InferenceBindingTests.test_every_service_identity_is_bound`

`formal/pon-nakamoto-v1/test_inference_receipt.py::InferenceBindingTests.test_duplicate_or_implicit_receipt_fields_reject`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Stale confirmation, input/model substitution, cross-genesis signatures and unsafe remote-result authority.

Controlled full-verifying confirmation is implemented in N2 below; succinct light verification, public-network currentness and normal Hepta final-use integration remain unimplemented.

## Current source and verification

- [`formal/pon-nakamoto-v1/inference_receipt.py`](../../formal/pon-nakamoto-v1/inference_receipt.py).
- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M14` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Frozen evaluation and consent continuation

See [E3](../protocol/pon-nakamoto-v1/details/EVALUATION_BUNDLE.md) for exact bytes,
owner boundaries and failure schedules. No public export or future-window authority
is created by a frozen artifact. The following additional regressions are executable:

- `formal/pon-nakamoto-v1/test_inference_receipt.py::InferenceBindingTests.test_expected_cost_nonce_and_returned_output_cannot_be_omitted`.
- `formal/pon-nakamoto-v1/test_inference_receipt.py::InferenceBindingTests.test_oversized_receipt_rejects_before_json`.
- `formal/pon-nakamoto-v1/test_inference_receipt.py::InferenceBindingTests.test_expected_boolean_counter_alias_rejects`.

## Bounded receiver / confirmation continuation

The actual controlled caller is `formal/pon-nakamoto-v1/client_confirmation.py`.
[N2](../protocol/pon-nakamoto-v1/details/NETWORK_CLIENT.md#n2--executed-bounded-history-receiver-and-local-confirmation)
defines page fields, caller-pinned cursors, full work/state validation, per-block commit,
interrupted-prefix recovery, local confirmation and clock/currentness limits. The existing
Ledger remains the only persistent owner. Maturity now binds this caller and its exact
regressions; native public-host and ordinary Hepta integration flags remain false.

A receiver computes work and transaction membership rather than accepting RPC assertions.
This is a full-verifying reference client with explicit optional native work/execution
components, NOT a succinct light client or proof of the globally latest tip. Completed
lower-work delivery does not replace the receiver's heavier observed branch. Successful
logical-clock tests cannot be reported as live confirmed public throughput.

The current-clock observation checks every verified ancestor, not only the tip. Exact
stored retransmission does not reuse an earlier clock verdict. Cancellation yields no
partial confirmation, and a generation change during traversal rejects STALE_VIEW.
See N2 for the actual callback, retry, memory and linear-history cost boundaries.

## Native cache / receiver continuation

The exact continuation is specified in [native execution](../protocol/pon-nakamoto-v1/details/EXECUTION_PARALLEL.md), [admission](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md) and [client/recovery](../protocol/pon-nakamoto-v1/details/NETWORK_CLIENT.md). It does not promote native persistence, independent acceptance or public-network capacity. Exact additional counterexamples:

- `formal/pon-nakamoto-v1/test_client_confirmation.py::VerifiedHistoryTests.test_batch_distinct_memberships_share_only_one_coherent_observation`.
- `formal/pon-nakamoto-v1/test_client_confirmation.py::VerifiedHistoryTests.test_batch_rechecks_future_spike_below_all_requested_inclusions`.
- `formal/pon-nakamoto-v1/test_client_confirmation.py::VerifiedHistoryTests.test_batch_cancellation_cannot_leave_reusable_currentness`.
