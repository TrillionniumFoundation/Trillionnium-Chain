# Native growth confirmation and observed-clock contract v1

## Scope

The existing Node owner now exposes transaction confirmations for its explicitly
selected PNP2/PGH2 permanent-account growth namespace. The ordinary
Node::confirmation and Node::confirmations entries dispatch to that owner's
native implementation. This fills the earlier call-path failure in which those
entries required a materialized complete State that the growth owner deliberately
does not provide.

The result uses the existing Observation and ConfirmationBatch structures and
the installed depth and required-work parameters. Its network, parameters and
genesis identify the selected growth namespace. No signed statement, stored
schema, difficulty rule, chainwork function, account wire, production switch,
finality authority or execution authority changes.

## Actual verification path

Within one read snapshot, the owner checks its cold-audited storage epoch and
binds the selected tip, generation, complete working commitment and account
checkpoint. Each distinct requested included block goes through the original
complete retained W1 verification, original-parent account witness, M06
execution, receipt, state commitment and delta comparison. Its complete body is
decoded and each requested transaction must belong to its committed body.

The active ancestry is walked to genesis once per batch. Every PGH2 header and
trace identity is bound to its stored record and parent. Height must decrease
by one, and cumulative required work must equal the parent's work plus the
original contribution for that header's target. Every ancestor timestamp is
compared with this call's observed clock plus the unchanged future skew. A
passing tip timestamp or an earlier successful observation cannot pay for an
unexamined future ancestor.

For an included block on that active branch, confirmation requires both the
installed depth and the installed work multiplier applied to the included
block's required work. A legal retarget can make six successors insufficient
in work even when their depth is six. An off-branch included block yields a
reorged, unconfirmed observation with no depth or work delta.

Before returning any batch, the same active tip and generation must remain
selected and the observation must have written no rows. The read transaction
is released and the growth epoch is checked again. This last check is necessary
because SQLite data_version inside a read snapshot can hide a foreign WAL
commit. A changed epoch is a refusal, not absence, successful confirmation or
permission to replay an external action.

## Progress and cancellation

Callers that need cancellation or resource accounting use
Node::growth_confirmations_with_progress. Its typed Sync callback retains the
original W1 and M06 progress checkpoints and adds distinct-body and complete
ancestry observation checkpoints. Errors at entry, native work, execution,
ancestry or the final boundary return no partial successful batch and release
the read snapshot.

The legacy Node::confirmations_with_progress callback is a non-Sync FnMut and
cannot safely stand in for the growth execution callback. A growth owner using
that entry receives GROWTH_USE_CONFIRMATION_PROGRESS. The callback is never
silently discarded. The default non-progress confirmation entries use the
native growth implementation.

Node::check_observed_history and Node::activate_observed also use the complete
growth ancestry clock observation. The latter still delegates actual
activation to the existing growth writer, required-work comparison and reorg
journal. A lower-work or already-active target does not bypass the requested
clock check. Clock-free recovery and activation remain their existing distinct
APIs; they are not relabeled as current-clock observations.

## Regression contract

The [native tests](../../../../trillionnium/crates/trnm-pon-node/src/store/growth/tests/confirmation.rs)
exercise complete PNP2 packets, actual Node owners and their SQLite stores:

- A separately opened receiver admits all actual packets, confirms the included
  transaction through the ordinary API, and repeats the observation after cold
  reopening without changing rows.
- Multiple transactions in one body share one complete body replay; empty,
  oversized, duplicate and nonmember requests reject the entire batch.
- Cancellation reaches actual W1, M06, ancestry and terminal callbacks.
- A future non-tip ancestor defeats a lower clock even after an earlier
  successful observation; the exact inclusive skew boundary still succeeds.
- A real difficulty decrease leaves depth six below the required work.
- An actual higher-work fork revokes active membership; extending the original
  branch restores membership, and cold recovery preserves the result.
- Changing included proof bytes while retaining its header and terminal trace
  cannot avoid complete work replay.
- Actual foreign WAL commits at entry, inside ancestry, and before terminal
  return invalidate the observed epoch, even when the foreign writer restores
  the original row values.

The implementation is in
[growth/confirmation.rs](../../../../trillionnium/crates/trnm-pon-node/src/store/growth/confirmation.rs).
These are local implementation controls. Two local Node directories do not
establish independent operators, separate fault domains or a public WAN.
No same-resource throughput improvement, cheapest legal work bound,
time/difficulty consensus theorem, whole-chain quantum reliability or
production qualification follows. All existing broader HOLD gates remain.
