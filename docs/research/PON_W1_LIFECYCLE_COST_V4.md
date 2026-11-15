# W1 lifecycle cost observation V4

Status: **local native diagnostic; HOLD / NO-GO**. This document supplements the
single [development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md);
it does not activate a work profile or change cumulative credit.

## Problem addressed

The retained V2 producer observer emits a search only after it returns. V3
retains four complete searches in memory and emits their cohort after all four
finish. Successful complete campaigns retain those attempts, but a preparation
error, generation error, external cancellation or timeout can stop the process
before its current cohort becomes visible. Earlier completed searches in that
cohort can then disappear from stdout. A collector cannot safely turn that
missing record into zero consumed resources.

V4 adds a separate native entry point and streaming record namespace. Existing
V2/V3 example files, selectors, challenge domains and record meanings are
unchanged. The shared producer search now has an observer interface; its
historical wrapper uses a no-op observer and does not sample a clock per attempt.

## Native execution and refusal semantics

The [native entry point](../../trillionnium/crates/trnm-pon-node/examples/pon_w1_lifecycle_cost_v4.rs)
uses the existing thirteen producer implementations, nine material classes,
eight samples and four actual searches per preparation. It deliberately keeps
the V3 challenge stream, so complete proofs can be compared byte for byte.
Distinct challenge domains do not prove statistical independence of actual SHA-256 outputs.
The target is the retained diagnostic value with first byte 127 and all
remaining bytes 255, whose ideal terminal-hash density is one half. These
measurements cannot fill MU1's fixed one-sixteenth success experiment or its
one-through-eight-unit cost grid.

Every operation records and flushes its begin before entering native work:

1. Campaign and material preparation.
2. Cohort and producer preparation.
3. Each search and each individual proof attempt.
4. Each complete production and reference verification.

A completed attempt retains its nonce, exact challenge, transcript digest,
ticket, proof SHA-256, target outcome and optional thread CPU/wall durations.
Generation failures retain their started identity and measured failure. An
observer write or flush failure stops the caller before the next native action.
A process killed during work leaves an unfinished prefix.

A target hit is explicitly unverified. The V4 observer emits verification
begins before the original full production and reference calls; it requires
both accepted results before counting that search as fully verified. Every
consensus credit field is zero. The observer does not invoke the Node admission
or cumulative-credit owner.

There is no success fallback. Unsupported specialized producers remain
unsupported, producer-stream disagreement fails the campaign, and verifier
disagreement fails the campaign. Only normal completion of the entire fixed
roster emits the terminal complete record. A failure record, if its sink is
still writable, reports an unknown unfinished cost and no qualification.

A begin record means the action was about to be attempted. A kill immediately
after that flush can occur before or after the native call starts. Its actual
resource use is **unknown**, never assumed zero or assumed equal to a full
successful call. Flush means delivery to the host collector; it is neither a
power-loss durability guarantee nor independent execution authentication.

## Timing scopes

The observer keeps these quantities distinct:

| Observation | Included work |
| --- | --- |
| Attempt CPU/wall | Native generation and complete retained trial digest before the finish observation |
| Search CPU/wall | All attempted native generation and V4 streaming observation for that search |
| Full verifier CPU/wall | One complete production or reference verification call |
| Cohort total | Actual preparation, four searches, streaming, comparisons and complete verification |
| Campaign total before terminal record | Material work and all campaign work/observations before writing the final record |

These times overlap and must not be added together. V4 observation overhead
belongs to its search/cohort/campaign totals. Those totals are not directly
comparable to V3's producer-only total. The process startup, final write,
collector, device, memory and externally billed costs still need their own
complete receipts. An unavailable thread CPU clock remains null.

## Prefix reader and retained evidence

The [readback tool](../../scripts/pon_w1_lifecycle_cost_v4.py) verifies consecutive
sequences, the fixed declared roster, exact task/challenge/ticket identities,
preparation/search/attempt/verification ordering, complete trial-stream agreement
across supported producers (including losing attempts), candidate
proof hashes and final counters. It verifies both full-verifier observation
paths and refuses a target-hit-only promotion.

The reader reconstructs the same nine frozen material recipes as the retained
[V2 cost reader](../../scripts/pon_w1_cost_matrix_reader.py). A self-consistent
task hash cannot relabel zero matrices as full-rank input, or replace a frozen
recipe with different canonical matrices. The same fixed constructor support
matrix binds all 117 material/producer pairs: 59 pairs are supported, including
14 specialized pairs in addition to the 45 generic pairs. Declaring a supported
specialist unsupported cannot omit its four searches while closing the roster.
With eight samples, a complete observation has 1,888 searches; exhausted searches
remain searches and are never imputed as verified winners.

Every completed trial's proof digest, including a losing trial, is checked
against the reconstructed canonical `PNW1` A/B/AB prefix and that trial's reported
trace. Reusing the prefix hash makes this check independent of producer claims
without repeating full matrix products per attempt. The reader still does not
replay the challenge-dependent W1 transcript or authenticate execution. Source,
binary, process and resource receipts remain separate requirements.

Deleted or duplicated records and reordered events within an active operation
cannot close the grammar. The reader permits a different ordering of complete
cohorts when their identities, trial streams and final roster still agree.
An unfinished line is retained as a partial tail. Missing terminal completion,
an unknown/nonzero process exit, or a started operation without its finish
returns INCOMPLETE and exit code 3. Malformed or contradictory records return
exit code 2. Exit code 0 means only that this complete declared observation and
a supplied zero exit agree. The reader does not authenticate the supplied exit,
source, executable, resource contract or actual device work and does not replay
the complete W1 relation itself.

Capture stdout and stderr separately, preserving original failed attempts.
Record the exact source/tree and loaded executable SHA-256, command, original
resource contract, process identity, exit/timeout/cancellation status, and
source-before/source-after observations outside the tested checkout. Bind the
raw journal bytes and readback report in that same evidence manifest.

Example commands, after the normal preflight/build gates:

~~~bash
cargo run --locked --offline --release -p trnm-pon-node \
  --example pon_w1_lifecycle_cost_v4 -- --actual-lifecycle-v4
python3 scripts/pon_w1_lifecycle_cost_v4.py /absolute/retained/journal.jsonl \
  --process-exit-code 0
python3 -m unittest discover -s scripts/ci -p test_w1_lifecycle_cost_v4.py -v
~~~

The native observer controls cover refusal before generation, retained
generation failure, malformed generated proof, a sink failure between
attempts, and byte-identical complete streams through the retained wrapper.
The reader's synthetic-prefix controls never claim a successful native run;
they cover cancellation prefixes, partial writes, missing/duplicate records,
changed identity, false credit authority, premature completion and retained
unknown costs. A complete native V4 run and its exact receipt remain a separate
required observation.

## Work-cost and joint-consensus boundary

This change repairs visibility of interrupted local experiments. It proves no
minimum cost for all legal algorithms, no all-device physical resource
simulation, and no joint timestamp/difficulty/credit or honest-service theorem.
The original Node resource deadlines and public service criteria are unchanged.

The current fixed-probability contract still has sixteen unknown cost points.
Every measured complete legal strategy is evidence about that implementation
and experiment; it cannot be promoted into a universal lower bound. Shared
preparation, all failed/unpublished work, task/branch selection, retained
classical/quantum state, post-win proving and transport remain part of the
required lifecycle model.

The [ESA 2026 Komargodski--Weinstein publication](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESA.2026.2)
still presents optimal protocol hardness as a conjecture. Its
[full fixed version](https://arxiv.org/html/2504.09971v4), section 5, explicitly
separates multi-instance/streaming requirements from its simpler main
definition. It cannot certify this implementation's complete cost model.

[Quantum Multi-Solution Bernoulli Search](https://quantum-journal.org/papers/q-2023-03-09-944/)
provides a query-model result with classical honest parties. Matching that
query model to actual W1 computation, variable work, retained state, verification
congestion and the current Node remains a separate proof obligation.
