# Frozen full-W1 session continuation

This research successor retains the complete failed source-5d9578 artifact and
continues its missing segment proofs. It changes neither the full W1 relation
nor the pinned native assembler/verifier. The original attempt remains failed;
partial receipts have no whole-proof or consensus authority.

## Actual original observation

The exact source was `5d957878ea82b09b555c713976f5157fde1089a0`, tree
`aeba742e5523ef10136ce800ab217cc571f34f4a`, run `40511022475`, attempt 1,
job `122212651078`, artifact `12743386213`. The complete ZIP is 8,139,466 bytes,
SHA-256 `d862b93d949612e6fc764d82622d507b208743bc8e6b6701dbf481802b040e8b`.
All 315 original members, totaling 10,934,918 uncompressed bytes, are retained
as 32 ordered archive parts and checked before use.

Full guest execution used 13,364,385 user cycles and exported 62 po2-18
segments. Segments 0 through 25 actually produced verified segment receipts;
the 3,500-second work stop terminated the next workers. Outer observed wall
time was 3,500.259693808 seconds, user CPU 13,885.722470 seconds, system CPU
7.647299 seconds, maximum waited-descendant RSS 2,414,420 KiB. This RSS metric
is not concurrent physical process-tree peak. There was no complete receipt;
whole-proof verification and hostile-proof auditing were skipped.

## Two separately budgeted continuations

The checked policy permits exactly two shards: 26 through 43 and 44 through
61. Each has the original two workers, two Rayon threads per worker,
300-second stage ceiling, 3,500-second work stop, and 3,600-second outer phase
ceiling. No automatic retries or other source/run/session selection exist.
These are two new independent budgets, not a successful original one-hour
attempt. Worker zero exit observed after its original wall budget is refused.
The work-finished boundary is captured before cleanup and must precede 3,500
seconds; cleanup and final outer settlement remain separately visible.

Every shard freshly builds the original fixture, guest, host and backend,
executes the complete guest, and byte-compares image, input and the complete
claim against the retained original. It checks every other manifest invariant
except the measured wall time and individual segment digests. Each fresh
segment must still match its own measured size/hash and bounded inventory.
Fresh execution is an independent relation cross-check and supplies **no proof
segment**. All 62 original assets, their manifest and claim must remain exactly
byte-identical to the pinned archive. Only these original assets are passed to
the unchanged native segment prover. Thirty source pins protect the original
relation, guest, host, scheduler, budgets, locks and build helpers.

This separation is required by an actual failed CI observation. RISC Zero
3.0.6 writes host-provided 128-bit memory entropy at guest startup, so a new
execution has different intermediate trace states. It cannot be spliced into
the old receipt chain. Policy and attempt namespaces advance to v2; v1 policy
is refused. The original exact-rerun diagnostic and all its controls remain.
The [failure and upstream source evidence](../../../../../evidence/pon-w1-original-trace-repair-20261027/README.md)
retain both failed shards and bind the new trace-selection rule.

Selection treats a genuinely absent policy as original generation mode.
Invalid policy, a dangling link, or a link to a real policy is an error and
does not select generation. Finalized shard evidence is traversed through
owned directory descriptors without following links. Limits are checked
before file reads: 512 files, 32 directories, depth 4, 256 path bytes,
32 MiB per file, and 64 MiB aggregate. Nonregular files, concurrent directory
changes and file changes are refused. These are local artifact bounds, not
an Internet ingress qualification.

## Complete-proof acceptance

Assembly requires both shards from the same exact GitHub run, attempt and
full source-before/source-after record. It rejects missing or duplicate
segment ownership and any incomplete, failed, over-budget or unclosed shard.
All 62 receipts then enter the unchanged Rust `assemble-segments` operation.
Its full Composite verification binds image, journal, original claim,
pre-state/post-state and empty assumptions. There is no fake receipt,
development mode, Groth16 conversion, PoVW or added PoW/grinding.

The assembly job separately runs native verification, the original 17 hostile
proof cases, both late invalid inputs in the actual guest, and the conditional
soundness report against the actual completed receipt. No synthetic `prove`
process is invented. The continuation report compares complete source records,
including tree and input inventory, and checks the actual assembly terminal.
The report additionally binds assembly and soundness phases to the exact source,
original phase ceilings, and assembly run/attempt. Only after this succeeds can the [loopback measurement](LOOPBACK_COST.md) run
between two further real native verifications.

Generation CPU counts the original failed phase, both continuation outer
phases and assembly exactly once. Segment CPU is not added a second time.
Cumulative independent phase wall time is explicitly different from parallel
elapsed time. Missing observations stay unknown, not zero. Build/control and
loopback costs remain separate. The measured maximum of the finite invalid
corpus is not a theorem about the globally worst input; loopback is not WAN
or gossip throughput.

## Validation status at this source freeze

The [retained original and local controls](../../../../../evidence/pon-w1-session-continuation-20261027/README.md)
include the original failed ZIP and log, the first 21-control pass, and the
35-control pass after four static-review fixes. The latter uses real owned
zero-exit children to test observed late completion and keeps actual wait4
accounting. Other controls cover retained-byte corruption, source/session
substitution, budget relaxation, policy downgrade, directory/byte flooding,
symlinks, nonregular files and missing-cost reporting.

The first hosted continuation run `40606062524` on `8a999681` actually built
and executed the guest but **FAILED** in both exact-rerun comparisons. Neither
shard started a segment proof. The retained-original-trace v2 successor has
passed local controls; its new heavy continuation, complete native assembly,
full positive/negative proof audit and real-receipt loopback remain **NOT_RUN**
at source freeze. Earlier failed attempts remain failed. Controls do not
establish a complete proof, public deployment, work hardness, physical resource
accounting or whole-chain quantum resistance.

## Independent report provenance repair

The [final local review](../../../../../evidence/pon-w1-session-continuation-20261027/final-review/README.md)
reproduced seven accepted substitutions in the original report reader: foreign
assembly/soundness source, relaxed phase caps, and stale assembly source/run/attempt.
The corrected reader rejects each while retaining its positive control. All 37
continuation controls and 14 real-loopback component controls passed. The initial
sandbox socket denial and initial negative-fixture cleanup error are retained.
No synthetic report-reader control is treated as a cryptographic proof.
