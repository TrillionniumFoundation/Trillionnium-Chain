# DAA branch-local anchor projection — non-activated horizon research v1

Scope: M02/M07/M08/M17 research adjunct to the one existing
[PoN development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [Lease × DAA audit](LEASE_DAA_RESEARCH_V1.md). It is **not** a new plan,
protocol release, accepted ASERT profile, trusted anchor certificate or chain
activation. It changes neither legacy Q4/Revision12 nor M02's 16-block DAA.

## Problem and proposed non-authoritative solution

The genesis/activation-anchored
[research ancestry oracle](../../../../formal/pon-nakamoto-v1/daa_activation_branch_oracle.py)
intentionally refuses walks exceeding 4096 headers. This is correct finite
resource denial but not a viable permanent DAA on a long-lived chain.

Research-only
[projection](../../../../formal/pon-nakamoto-v1/daa_anchor_projection.py)
copies an immutable activation-height anchor fact from each locally stored,
**already fully verified parent**, and updates a bounded rolling window of
11 raw timestamps. Each projected parent contains its exact anchor block,
anchor predecessor identity, anchor target and the anchor predecessor's
raw and MTP11 time. Raw-parent and MTP11 research selectors both use
the exact unchanged ASERT integer oracle.

Candidate calculation is O(1) in the number of ancestors **only when**
its immediately preceding projection is already stored and trusted by the
native owner. Retaining all branch projections, garbage collection,
versioned persistent bytes, snapshot replay, authenticated historical
state, and W1 proof verification are *not* O(1) or implemented here.

An append is only permitted after the Node has independently checked the
actual Packet block ID, W1 proof, correct legacy expected target, complete
state/receipts, signed transactions and parent-specific parameters.
The Python VerifiedHeaderObservation name is a research assertion, not
a private native VerifiedWork/VerifiedHeader capability; the standalone
test does **not** check those authority facts. A SHA-256 projection chain
is a self-consistency checksum, never a peer-supplied trust anchor.

The projection is fork-local, and an alternate fork crossing the selected
activation height obtains its *own* predecessor time and anchor target.
No cached global favourite-chain anchor, reorganization shortcut, source
signature or claimed network checkpoint may substitute for its actual
candidate-branch record. Missing parent is **Unavailable**, not
invalid work; an unknown state must be reconstructed from fully validated
native history, never from peer-provided projection bytes.

## Reproducible local controls

From repository root:

    cd formal/pon-nakamoto-v1
    python3 -m unittest -v test_daa_anchor_projection.py
    python3 run_anchor_projection_campaign.py \
        --height 12000 --output /absolute/new/nonexistent/report.json

An isolated local Python 3.13 run on 2026-10-26 passed all six research
unittest methods. The two 12,000-header synthetic streams had no native
work/proof, no signature, no actual target admission, no network and no
independent operator. Frozen JSON (for this particular local research
source) is [here](../../../../formal/pon-nakamoto-v1/anchor_projection_12000.json).
The complete SHA-256 of that JSON is
17f7037d481e22769bf566499ad082ce8fb11b3d4353a73e5b5ba7435a3a51a5.

Test controls cover: 12,000 sequential heights under raw/MTP11,
forks crossing activation, independent window-equation comparison,
strict input/context/height/parent refusal, tampering detection and
rebuild-after-loss. These are independently authored *research-model*
checks and do not constitute third-party security verification.

## Production blocker that this does NOT close

A genuine P1-C candidate must design a fresh consensus version and
deterministic, separately committed **native M07 anchor projection**.
Write/read/reorganization/cold-open must publish the projected state
atomically with the exact verified header and parent; each crashed
detach/attach cut must either recover the same projection or refuse.
Native admission must recompute/compare the target from its actual
branch-local parent, while the old revision continues producing exactly
the historical targets. Every invalid root, missing parent, changed
activation anchor, future/time-warp condition or peer-supplied summary
must fail closed without silently selecting a different work function.

Use actual 4096+, 12,000+ mined/verified W1 headers, deep competing
branches, restart/power cut, independent full receiver confirmation
and storage compaction proof before claiming long-lived PoN safety.
Preregister WAN conditions and compare ASERT time-warp, median lag,
selfish mining, public verification exhaustion and chain quality;
a fast projection does not cure unqualified W1 work hardness.

All PN1/PN2/PN5 and P0-C/P1-B/P1-C/P2 qualification flags remain false.

## Native compile/test-only companion

The existing M02 source file now carries two gated,
test-only modules under Rust cfg(test): an isolated rolling
anchor projection and a source-bound deterministic comparison.
They do **not** add a Node API, consensus target selection, published
profile, new signature domain or persistence writer. A Rust test
reconstructs two 12,000-header *synthetic* streams with the existing
ASERT arithmetic, calculates exact projection-byte commitments and
requires the above frozen raw/MTP11 digests. A second test forks across
the activation anchor; a third refuses corrupted parent/context input.

The Rust test source has been added to the candidate branch but has
**not** been compiled or executed on the current host, because rustc
and cargo are unavailable here. Only the Python 6/6 test outcome and
Python JSON are observed. Rust source/test presence is NOT native
acceptance, and even a future Rust PASS will not prove W1 validity,
authenticated on-disk integration or independent operator security.

## Durable crash/reorg research follow-on (not installed)

The separate [SQLite shadow journal](DAA_SQLITE_SHADOW_JOURNAL_RESEARCH_V1.md) now
covers bounded atomic header/projection-identity storage, branch selection
compare-and-swap, cold ancestry audit, corruption and injected crash cuts.
It stores an **untrusted upstream-supplied projection digest**, so it neither
verifies actual W1 nor supplies native M07 ownership or a production DAA. Its
10 Python tests are not native consensus qualification. This experimental
writer must NOT be wired as a second authoritative Node database.
