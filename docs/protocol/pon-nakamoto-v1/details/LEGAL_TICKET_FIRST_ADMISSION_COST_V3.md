# Distinct legal ticket and first admission cost

This finite experiment adds the costs missing from the prior producer-only
and repeated-admission observations. It is a positive legal-ticket campaign;
the production work relation, ticket predicate, Node, storage and recovery
implementation are unchanged. The two eligible producers are the original
general prepared task and maintenance split-limb prepared task.

## Fixed paired execution

The native [driver](../../../../../trillionnium/crates/trnm-pon-node/examples/pon_legal_ticket_cost_v3.rs)
uses eight fresh stores: two rounds, two producer arms and preparation either
per search or retained for 64 challenges. Every cohort runs 64 searches with
eight attempts at most. Fixed disjoint nonce windows include every miss,
exhausted search and winner. Arm order reverses in the second round. Both arms
and reuse modes must produce the same complete header/proof/ticket stream per
round. Special low-rank tasks are not substituted for the legal native task.

Each winner is unique within its store and submitted to ordinary `Node.admit`
exactly once. The original template acquisition performs its real full proof
search and is charged separately; that seed is never admitted or counted as
another winning ticket. Paired fixtures repeat across stores, so the reader
reports first admission calls and globally distinct fixture packet IDs
separately. Sibling tickets are not a measure of live-chain rewards or TPS.

No explicit activation call occurs during the admission phase. Ordinary cold
open performs the original STATE_RECOVERY selection: all admitted siblings
have equal parent, target and height, so the lowest ID wins the original
work/height/ID ordering. The driver checks this result, then retrieves and
encodes every admitted packet and compares exact byte length and SHA-256 with
the bytes encoded before its first admission. This checks process restart
and durable byte readback; it does not simulate physical power loss.

## Exclusive cost accounting

The thirteen phases retain separate wall and process CPU time: directory,
Node open, bootstrap material, original template acquisition, task matrices,
producer preparation, all proof attempts, packet encoding, first native
admissions, Node close, cold open/recovery, cold packet readback and cold close.
`CLOCK_PROCESS_CPUTIME_ID` includes the Node's worker threads. Unavailable CPU
readings remain unknown. Native admission already executes ordinary work
validation and SQLite persistence; no standalone verifier cost is added again.

The reader reports three scopes per first-admitted ticket: preparation plus
all attempts plus encoding plus admission; all thirteen exclusive phases;
and the observed outer cohort including harness overhead. Both rounds are
aggregated by summing costs and first admissions before dividing. Settings
creation is reported separately; the unchanged whole-process capture also
retains startup, serialization, cleanup and failure overhead. An exhausted
search contributes cost and zero tickets. Zero winners have no finite cost
per ticket, never a fabricated zero.

All packet hashes and exact stream digests are retained, but the driver does
not retain complete winning packet payload files after deleting its temporary
store. This limitation is distinct from its actual cold byte readback check.
The native executable, raw complete JSONL, independent reader summary,
compiler/lock/source identities, hardware observations and failures are retained.

## Execution and boundaries

The [workflow](../../../../../.github/workflows/pon-legal-ticket-cost-v3.yml)
builds the exact source on native x86_64 and aarch64 GitHub runners, checks
architecture, requires the original locked graph/test profile and strict
Clippy, and runs the fixed 240-second campaign under a 250-second capture cap.
It accepts no driver CLI overrides or automatic retries. Full source guards
run before and after, including after failures. ARM is not emulated. These
are shared hosted CPUs, without hardware attestation, energy measurement,
GPU/SIMD batch measurement or a global-minimum claim.

The existing special-matrix, multichallenge and hardware campaigns remain
separate evidence. Their serial batch scheduling is not reclassified as a
hardware batching result. This successor measures end-to-end costs for the
two previously eligible leaders; it does not prove they are cheapest among
every possible legal algorithm. The [bounded independent reader](../../../../../scripts/ci/check_legal_ticket_cost_v3.py)
and eight synthetic accounting controls are source checks. New native x86_64
and ARM observations remain **NOT_RUN** at this source freeze.
