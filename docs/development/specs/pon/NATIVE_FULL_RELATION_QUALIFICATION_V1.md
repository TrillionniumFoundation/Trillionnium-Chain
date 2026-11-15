# Native full relation and complete path qualification v1

This development qualification keeps native FullLimb/PNW1 as the complete work
replay for the current PGH2/PNP2 Node. It changes no consensus bytes, difficulty,
fork choice, signing domain, stored schema, admission authority or public Host
budget. A correctly replayed work relation is not a certificate of the physical
or quantum cost paid by its producer.

The source integration starts at `62d2d90c9e1f4c8450c89843f1e08360a24283ce`.
Every execution must additionally retain its actual tested commit, tree and
binary hashes; this starting reference does not assign later executions to it.

## Exact native scope

| Obligation | Current implementation | Qualification evidence |
| --- | --- | --- |
| Exact work statement | [PGH2 codec](../../../../trillionnium/crates/trnm-protocol/src/pon_growth.rs) hashes its complete 354-byte encoding, including original header and account witness digest | Header-to-work regression and newly sealed wrong-context packets |
| Canonical complete work | [PNW1 verifier](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs) accepts exactly 49,188 bytes, checks all A/B/C words, current task and target, replays the full transcript and checks every product word | Existing scalar/FullLimb/carry/encoding/cancellation controls |
| Checked work is not cached admission | [Immutable checked packet](../../../../trillionnium/crates/trnm-pon-node/src/store/growth/work_checked.rs) has private fields | Current parent, clock and owner epoch are checked again after consuming it |
| Parent-local Node rules | [Growth admission](../../../../trillionnium/crates/trnm-pon-node/src/store/growth/recovery.rs) reloads network/parameters, parent height, branch-local target, body root, maintenance eligibility and time | Two real branches with different next targets; fresh valid work for incorrect context |
| Complete transition and persistence | Actual parent witness, signed execution, state and receipts roots, exact stored packet/deltas, and active-state invariance precede the sole SQL commit | Full SQLite logical-row snapshots on refusal; successful activation and cold reopening |
| Local operation control | Existing progress errors propagate through work, execution, persistence and activation | BeforeVerifiedWork cancellation has no successful admission/activation receipt |

The development namespace currently admits the fixed maintenance work task.
This qualification does not infer that an arbitrary useful task or an external
Hepta operation has acquired eligibility.

## Integer and algebraic correspondence

The current profile fixes `N=64`, tile/rank `R=8`, and
`q=4294967291=2^32-5`. All external matrix words must be canonical integers in
`[0,q)`. Byte parsing never repairs an out-of-range submitted word by reducing it.

For the complete challenge-expanded matrices, write
`E=EL*ER`, `F=FL*FR`, `A'=A+E` and `B'=B+F`, with arithmetic in the fixed field.
The transcript accumulates every tile of `A'*B'`. Its two complete corrections
are `A*F` and `E*B'`, so

`A'*B' - A*F - E*B' = (A+E)*(B+F) - A*F - E*(B+F) = A*B`.

This identity explains the implementation only when all prescribed products,
reductions and transcript updates execute. There are `(64/8)^3=512` transcript
tiles; the last tile and every corrected output element remain mandatory.
Callback counts observe boundaries and cannot alone prove that computation.
The verifier also compares the trace and complete claimed C bytes before its
single `VerifiedWork` construction.

For [the actual split-limb helper](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/maintenance_limb.rs),
let `B=2^32`, let `1<=m<=64`, and split each exact `u64` product into low/high
32-bit limbs. With a canonical prior, the accumulators obey

- `L < (m+1)B` and `H < mB`;
- `S=L+5H < (6m+1)B <=385B <2^41`;
- `F=(S mod B)+5 floor(S/B) <B+1920<2q`.

Consequently all actual products/accumulators fit `u64`, and one conditional
subtraction after the fold yields the canonical field residue. The zero-term
case returns its canonical prior. The separately retained scalar kernel uses
ordinary `u128` remainder. Existing extremal and differential tests check both
implementations, including full correction products. This bounded argument
does not authorize calling the private helper with larger dimensions.

The producer reduction has its own `x<2^70` precondition, using two folds before
one subtraction. The fixed shape and every call site are part of that argument;
changing a matrix dimension requires a new range review and qualification.

## Fresh valid work for invalid Node context

[The new native integration regression](../../../../trillionnium/crates/trnm-pon-node/tests/native_full_relation_context.rs)
builds two actual 15-block branches with different timestamp spacing. At height
16, the candidate's own parent and the current active tip require different
targets. Each negative case is then freshly mined using its changed header's
actual challenge, actual target and matching A/B task. Both FullLimb and scalar
reference must accept this complete mathematical relation before Node admission
is exercised.

The matrix covers network, parameters, unknown parent, incorrect/overflowing
height, the other branch's target, median/future time, a legal but ineligible
matrix task, a valid newly signed body, stale execution roots, changed state or
receipts, and both unbound and rebound account witnesses. Precise refusal stages
and all logical SQLite rows are checked. Merely reusing an old proof under a
changed challenge would not test this distinction.

An admission return is not activation. Exact resubmission may return an existing
block without a new work replay; it earns no new progress in the reader.

## Actual process observations

[The native example](../../../../trillionnium/crates/trnm-pon-node/examples/native_fullpath_v1.rs)
and [parent collector](../../../../formal/pon-native-fullpath-v1/collect_native.py)
use an explicit development namespace and fresh private stores. The producer
creates a real signed transfer and complete native PNP2 candidate. A receiver
gets the entire packet through its actual stdin, invokes original native
admission and activation, closes its writer, and a separate observer reads an
existing store through the original read-only snapshot path.

The common parent clock records when it observes flushed events. These phase
intervals include parent-reader scheduling and are not exact child execution
durations; the enclosing start-to-independent-readback latency uses the same
external clock. The initial generation span
includes process startup, state/task preparation, signed transaction creation,
candidate generation, search and identity serialization. The following native
winner-preparation span measures actual packet serialization and durable export;
it does not claim a compressed proof was generated. Receiver verification
includes cold owner opening, full W1, signed application execution and durable
admission. Acceptance continues through activation and independent readback.
Nested child durations must not be added again to these enclosing spans.

The fixed four-start component set retains a new valid candidate, exact duplicate,
last-C-element malicious packet, and actual BeforeVerifiedWork cancellation.
All process exits, stderr, packets, offered starts, CPU costs and elapsed time
remain in the evidence. The tampered product preserves the original trace and
block identifier, allowing the real expensive rejection path to be observed.

Same-host pipe delivery is not WAN evidence. CPU is parent plus sequential
children from Linux rusage; RSS is a conservative sum of separately observed
parent/child maxima, not instantaneous resident memory. These are observations
on an unqualified development host, not enforcement of the original resource
contract. A single newly accepted block has depth zero and does not satisfy
the original four-second, six-successor condition. No survivor-only p95/p99 or
throughput claim follows from these component observations.

## Compression requires both gates

The [reader and negative controls](../../../../formal/pon-native-fullpath-v1/README.md)
retain complete frozen starts, source/binary/context identities, original
artifacts, one clock, all five path phases and actual canonical-chain readback.
Failure, timeout, cancellation, partial output, duplicate work and reorganization
cannot be replaced by a verifier microbenchmark or ACK. A missing sample remains
in its original denominator. Parent-linked packets and chainwork are reconciled
with the exact native observation; booleans alone do not confer progress.

Security and performance remain separate obligations. The reader always leaves
the cryptographic gate at HOLD. Any proposed compressed route must map the same
complete Node statement to its actual AIR/PCS/hash/transcript/recursive instance,
then satisfy its end-to-end performance and hostile-input availability contract.
Changing only a proof's envelope does not change the relation it proves.

### Current primary-source review

- [Chiesa, Di, Hu and Zheng](https://eprint.iacr.org/2025/2166) give a conditional
  QROM framework: the actual IOR needs the required state-restoration security,
  with round-by-round and commitment-extraction obligations. The theorem is not
  an automatic qualification of a selected STARK implementation.
- The official [Plonky3 variable-length sponge advisory](https://github.com/Plonky3/Plonky3/security/advisories/GHSA-3g92-f9ch-qjcm)
  requires auditing actual input lengths and permitted shapes. Its stated
  version remediation does not turn an application-level variable-length input
  into a fixed one.
- The official [MultiField32Challenger advisory](https://github.com/Plonky3/Plonky3/security/advisories/GHSA-vj64-rjf3-w3v7)
  requires checking the actual challenger type, encoding and fixed dependency.
  Its existence alone does not establish that this repository uses the affected
  type. This native-only continuation does not modify or qualify the research
  compressed backend.

No full-chain PQ128 result, universal physical-work lower bound, production
admission, release or deployment is granted by this qualification.
