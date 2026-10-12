# Native local derived ancestry index

`trnm-pon-node::ancestry_index` accelerates the public one-packet History path.
The table is a local derivative of already admitted packet headers. It does not
change PNH1, accumulated chainwork, task eligibility, checkpoint trust or the
receiving Node's full packet verifier. Public readiness, scientific hardness,
independent measurement and production activation remain unaccepted.

## Stored shape and namespace

The fresh `native-branch-schema-v2` DDL identity adds `ancestry_jump` to the existing
SQLite owner. Existing layouts fail `SCHEMA` before read-write initialization; no
migration, import, repair or background rebuild is implicit. A new storage
namespace can receive and verify historical packets normally.

The primary key is `(block, level)`. A level is0..62, a block/ancestor/seal is
exactly32 bytes, and the destination height is a nonnegative SQLite integer.
Each non-genesis admitted block gets one row for every `2^level <= height`; genesis
gets no jump rows. Thus the maximum is63 rows per block and the ordinary shape is
`floor(log2(height))+1` rows. Retaining every admitted branch still grows with
stored block count; this is not a total-disk cap or branch-pruning policy.

A row contains block, level, ancestor, ancestor height, left/right half-row seals,
and its own domain-separated `native-derived-ancestry-row-v1` hash. The hash binds
network, parameters, genesis, block, actual header parent/height and every stored
jump field. Level0 must equal the actual admitted header parent and has zero half
seals. A higher level references the two immediately lower-level halves. Header
metadata projection also verifies its context, recorded root/parent/height and
block identifier using the packet's final trace.

A native accepted block insert, all of its jump rows, state deltas and snapshot
changes share one SQLite transaction. Each index INSERT must affect exactly one row. After all admission writes, a private
operation-local expected row set is compared against the final actual rows and
their visible half links. The exact row count also refuses additional levels.
An index write or final-readback error rolls everything back;
it cannot consume a sender nonce or leave a partially indexed admitted block.
The existing exclusive Node owner, path/inode checks, WAL and durability rules
apply; there is no additional long-lived secret or sidecar.

## Bounded lookup and corruption behavior

`Node::public_history_packet(tip, after, maximum_sql, progress)` returns zero packets
only when `after == tip`, otherwise exactly one descendant of `after` leading to
the requested tip under this locally trusted index. It reads tip/cursor metadata,
ascends the height difference minus one by descending set bits, then checks that
the candidate's actual parent equals `after` and height equals `after.height+1`.
A wrong branch, unknown block or inconsistent index fails explicitly.

The maximum index/body caller budget is1024 SQL statements, including two reserved statements
for raw packet length and capped packet BLOB load. A progress callback runs before
each of these statements and can cancel the operation. The existing native
namespace check and one fixed reorganization-status query precede that budget;
neither scans the chain or active state. The query performs at most63 jump
hops, each checking a fixed number of rows. `checked` checks a jump and its two
visible halves with `basic`; it never recursively calls itself. The practical
number of indexed row lookups is `O(log(height))`, rather than a repeated linear
suffix scan. Each SQLite indexed point query has its own database-size cost; this
statement budget is not an exact CPU, filesystem-read or RSS bound.

Before packet projection/body allocation, scalar lengths reject null, undersized
or larger-than1MiB packet records. Hash/parent/root projections are fixed32 bytes;
header projection is the fixed native header length. The native packet decoder
and identifier/parent/height are checked again after the bounded body load.

Reopen checks every eligible level of the active tip, including each row's visible
half links, and then its exact row count, within1024 SQL statements. Genesis
requires zero rows. The original missing/seal/structure error order precedes the
extra-row count check. Activation and resumable publication perform that same
active-tip check after final event writes while their transaction can still roll
back. Admission's expected-row validation needs at most936 SQL statements; the
active-tip check needs at most938, including metadata and row count. This is not a global audit of every retained
branch. Unvisited rows are checked when used for lookup or deriving a new admitted
block. Missing rows, altered seals, wrong local header metadata and visible
half-link inconsistencies fail closed without repair or deletion of evidence.

The public seal detects accidental corruption and locally inconsistent structure.
An owner/attacker able to rewrite arbitrary database rows can recompute it. The
index cannot independently prove arbitrary long ancestry, force honest routing,
or prevent omission by a server. The client pins context and final tip, requires
contiguous parent links and independently verifies every PNW1/task/ledger packet;
`receive_page` does not explicitly activate a prefix as completion of the pinned
remote tip. On restart, the existing Node recovery independently selects the
heaviest fully admitted local branch, which can be a valid downloaded prefix.
That local consensus selection is not completion of the unfinished remote target.

## Actual regression scope

The short native tests mine and admit real PNW1 packets, build a heavier fork,
reopen it, independently validate indexed pages, refuse corrupted active index
rows and refuse the previous schema without modifying its database. A real signed
transfer plus valid proof reaches an injected index-write failure; sender nonce,
active state, admitted block and partial jump rows remain unchanged, and retrying
the exact packet after removing the fault succeeds. Separate pure index tests use
explicitly invalid proof fixtures only to exercise SQL structure, budget,
cancellation, visible resealed link tampering and transaction rollback.

The ignored release integration test `ancestry_long_sync` constructs4105 actual
blocks under `signed-task-lifecycle-dev-v3`, with atomic tag22 renewals at
900/1800/2700/3600. It retains every packet, reopens the same owner, refuses an
altered active-row seal, then requests4105 paid public one-packet History pages
from genesis over loopback. A separate Node performs full native verification,
keeps its old active tip during partial progress and reopens the final confirmed
state. Its output directory can be retained using `TRNM_INDEX_EVIDENCE_DIRECTORY`.
This is a single-host logical-header experiment with published development keys,
not a41050-second elapsed campaign, physical WAN measurement or public/Sybil
fairness certification. A particular run is accepted only by its retained actual
result, not by the existence of this test.

```sh
cargo test --offline --locked --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --test ancestry_long_sync \
  actual_v3_long_chain_public_full_sync_reopen_and_corrupt_index_refusal \
  -- --exact --ignored --nocapture --test-threads=1
```

## Independent retained-index observation

The existing native storage Python reader reconstructs every retained block's
expected jumps by following the actual parent relation. Stored jump destinations
and seals are not used to choose the expected path. It derives all ancestor
heights, half seals and final seals, then compares the exact full table, including
inactive forks, genesis and extra/orphan rows. Migration source and destination
are independently reconstructed before their cells are compared. This offline
reader is broader than the bounded live-tip check; it is not a background runtime
audit or a proof that a malicious storage owner cannot rewrite its inputs.

Actual native fault regressions cover ignored first/last index INSERTs, later
delta deletion/corruption/extra levels, and final-event damage during fast append,
forced staged append and real heavier-branch reorganization. They compare retained
rows, selected State, nonce, retry and cold recovery in both native backends.
Fault injection is into a locally owned test database; these cases do not claim
that an ordinary remote packet can install SQL triggers.
