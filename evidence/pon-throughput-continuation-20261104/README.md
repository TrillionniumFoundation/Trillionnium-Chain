# Complete-validation throughput continuation

This continuation starts from `362fbebe5027d731f16c88f710bfef7e922cd230`
on the existing integration PR #688. It preserves the original four-second,
F0, campaign, CPU, Host and independent-client verification gates.

## Changes and bounds

- Persistence merges two ordered borrowed State iterators. It still visits every
  union key and invokes each original checkpoint, compares canonical delta bytes,
  writes the same rows and completes the same transactional readback. The walk is
  O(N), with no temporary union tree or repeated per-key searches; it is not O(k).
- Generic History uses inline fixed-width record fields over the identical SQL
  CTE and full ancestry walk. It preserves type/width error precedence, all
  ancestor checks and cancellation. Indexed public/PQ History is a separate path.
- Explicit PQ caller authentication retains eight exact canonical ML-DSA public
  key expansions in the original intake epoch. Every signature is verified and
  every attempt remains charged. The retained material is not an authority or
  verification-result cache.
- Continuous public Submit reuses its already encoded immutable Packet when
  computing the scope digest. The later receiver, policy, nonce, CPU and final
  binding checks remain independent and in their original order.

The new differential controls cover original output bytes, ordered deltas,
absent/null values, SQL type and shape errors, foreign SQLite mutation, exact
SPKI/pin binding, fresh messages, invalid signatures, bounded churn and optional
material-lock contention/poison. Original tests remain.

## Measurements

The existing PQ Node workflow explicitly executes these ignored observations in
its original compiled test profile on head and actual merge for x64 and ARM:

```text
store::history_page::tests::inline_record_tests::history_inline_record_complete_call_cost
ingress::public_v3::pq_identity::verifier_cache::tests::pq_caller_authentication_complete_cost
```

The second selector requires `TRNM_PQ_AUTH_COST_DIRECTORY` to be a nonexistent
child directory; the existing workflow uses its retained command-record directory.
The state delta observation runs in the ordinary complete Node library suite.

Both observation arms use the same executable and exact inputs, retain original
validation/accounting, and alternate their order. No timing-ratio assertion grants
acceptance. Component timings exclude independent stages stated in each output;
none is a confirmed TPS, WAN capacity or release qualification.

## Initial failed attempt

The [first-attempt record](first-attempt.json) retains candidate `ed7d45a9`,
the actual ordered merge, failing jobs and the formatter's actual diff. Two
pre-existing inline source guards still pointed at the base store/History blobs.
The guards stopped recent-batch before native execution; the repository check
also rejects such drift. A separate original branch-encoding job reached rustfmt
and reported whitespace-only corrections in three new/modified files.

The correction updates the expected literal blobs to reviewed source, preserves
both comparisons and every original test, and applies the actual formatter output.
The initial failure is not replaced with a passing result.

Base preflight and two locked Linux metadata graphs ran before local executor
loss. New code is validated only by its own exact-source hosted outcomes. Until
those terminal records exist, new component/native/throughput outcomes remain
unverified. Original business failures and all existing HOLD exit conditions remain.

## Same-operation projection and shorter read critical section

The composed continuation preserves the concurrent W1/cache/cohort changes in
`bbcb3804576b9eb0b908eb3054bedccc189fb7ef`.

A cold complete-commitment calculation returns its already parsed account map
bound by a private lifetime-bearing object to the same immutable State. Only the
ordinary unscoped verifier consumes it. A complete-cache hit lends no map, and
readback-scoped verification keeps its existing path. Full current SQL graph
reads, comparison, aggregate checks and every progress callback still run.
Native differential controls count actual parser calls and visited State rows,
compare all cancellation points, mutate current SQL nodes after projection, and
check exact-state binding, malformed accounts and root-error precedence. An ABBA
observation includes the complete `verify_state_with_cache` call; it remains a
component observation, excluding Node admission, networking and confirmation.

Public History drops its Node guard only after the complete original indexed
read and next-ID checks. Owned Packet values plus the bounded immutable encoding
profile, context hashes, fixed tip and cursor are enough for grammar re-encoding,
hex and Page JSON. Original deadline/stop/CPU progress checks guard formatting.
A deterministic native test pauses formatting, commits a heavier fork through
the real Node writer, and compares the still-fixed-tip page with the held-owner
reference. Byte/error, fresh foreign corruption and cancellation controls remain.
The separate test-only SQL snapshot and authenticated PQ durable replay paths are
not promoted or changed by this response-formatting optimization.

Native compilation and exact-source outcomes for the full composition are
required before reporting any of the new controls or timing observations as PASS.
