# Native finalized catch-up stream v1

Status: candidate M13 transfer adapter with M06 execution and M15 socket consumers.
No consensus/wire activation, default node listener, signer or production authority.
Execution priority remains the canonical development plan. This is a technical
operation contract, not an additional development plan.

## Trust and operation

`DurableNativeApplicationV0::read_finalized_catchup_block_v1` obtains a historical
block through the existing strict finality readback. It returns exact header,
canonical application payload and proof bytes; it does not export the source's
local commit ID as execution authority. `write_native_catchup_stream_v1` consumes
these readbacks plus `PinnedNativeSnapshotExportV1` and an explicit receiver base.
The sender's successful write/flush does not acknowledge receiver durability.

`NativeFinalizedCatchupV1::receive_framed_stream_v1` consumes a recovered session
whose strict target and validator/genesis context were independently configured
before the stream. The stream cannot choose those inputs. The preamble must match
the actual local base and exact target; block count must equal the height distance.
Every ordinary epoch-0 block goes through existing `apply`: strict proof and
canonical body checks, deterministic preview, real durable execution/commit,
synchronization and fresh readback. No downloaded nonce/replay set is imported.

The final snapshot goes through the actual native Borsh/JMT reader and exact
reconstructed-image comparison. Only after the trailer and EOF match can the
operation return `RestoredNativeApplicationV1`. This is an application owner,
not Core, Safety, checkpoint, vote, signing, rejoin or activation authority.

## Candidate transfer layout

All integers are fixed-width, unsigned, big-endian. A frame is u32 byte length
followed by exactly that many bytes. Zero-length frames are rejected. This local
transfer format neither changes CEV0 preimages nor defines protocol version 1.

| Order | Fields |
|---|---|
| Preamble, 92 bytes | ASCII `TRNMCU01` (8), base height (8), base block ID (32), target height (8), target block ID (32), block count (4) |
| Manifest frame | Exact format below |
| Each block, in increasing height order | One frame each for canonical CEV0 BlockHeader, ApplicationPayloadV0 and ordinary three-chain FinalityProofV0 |
| Each snapshot chunk | One frame; exact index order, length and native-v0 digest are supplied by the manifest |
| End | ASCII `ENDNCU01` (8), followed by EOF; socket sender half-closes its write direction |

Manifest: height (8), block ID (32), state root (32), source-local commit ID (32),
maximum chunk bytes (4), chunk count (4), native manifest digest (32), followed by
exactly chunk-count descriptors of index (4), byte length (4), digest (32).
Fixed part is 144 bytes; every descriptor is 40 bytes. Existing native constructors
reject zero/oversized chunk counts, unknown index order, invalid lengths and zero
identities. No trailing manifest bytes are accepted. Source-local commit ID is
untrusted correlation metadata, not part of the receiver's chosen local authority.

The final target height/block/root must agree with the preverified proof before
any block mutation. Snapshot contents remain untrusted until their full audit.
An alternative valid certificate representation for the same target is not rejected
merely because its proof ID differs; target context, ancestry and all signatures
are still verified by the existing owner.

## Resource and failure contract

`NativeCatchupStreamLimitsV1` accepts at most 16 GiB total transfer bytes, frames no
larger than the existing 8 MiB CEV0 root bound, and at most 4096 suffix blocks.
Zero suffix blocks are allowed only when the recovered base equals the target.
The existing per-session execution/transaction limits, 4 MiB body limit, signature
work budget and native snapshot read limits apply independently. Limits are local
availability decisions, not new transaction-invalidity rules.

Preamble/frame bytes are charged before read/allocation, including rejected
attempts. Manifest has a separate 163984-byte ceiling (144 + 4096 * 40).
Snapshot lengths, frame limits and remaining transfer budget are checked before
mutation. The still-required chunk/trailer budget is reserved at each block.
One extra byte may be probed solely to reject non-EOF terminal input. At most one
block's header/body/proof and one snapshot chunk are retained by the decoder;
decoded JMT state and the source's pinned snapshot remain separately resident.
These limits do not bound total database work, full-history audits or peak state
memory. Cross-session and per-peer aggregate limits remain the hosting owner's job.

Framing/context/limit rejection before a block calls no execution mutator. An
invalid later block leaves earlier independently finalized commits intact. A lost
connection, failed final snapshot or terminal read consumes/drops the session:
there is no live-owner escape, rollback, automatic compensation or success receipt.
Reopen the actual database, supply its current-head proof and request exactly the
remaining suffix. A crash after PREPARED may retry that exact block; a crash after
COMMITTED must recover that head before continuation. Existing uncertainty rules
and external anti-rollback limitations remain unchanged.

`NativeCatchupStreamErrorV1` distinguishes `Limit`, `Framing`, `Context`,
`Transport`, source storage/proof failures and existing typed `Catchup` failures.
A successful source write says nothing about receiver acceptance. An error also
must not be treated as proof that the receiver performed zero durable work.

## Node I/O TCP adapter

`trnm-poco-node-io::AbsoluteDeadlineTcpStreamV1` exists only with the explicit
`candidate-state-sync-tcp` feature. It implements standard `Read` and `Write`,
which are consumed directly by the native transfer functions. No application
implementation dependency is added to I/O. Default features remain empty.

The constructor owns one already connected stream and one caller-selected
absolute `Instant` deadline. Every syscall refreshes its timeout from the same
deadline; fragmented progress cannot restart a per-frame deadline. Expired
reads/writes fail before socket I/O. CPU, cryptographic and database work is not
preempted. `finish_write` half-closes a completed one-shot source; it does not
acknowledge receiver durability. No raw socket or deadline-reset API escapes.

The hosting layer still owns connect/DNS deadlines, authentication/confidentiality
when needed, socket-count/global work quotas and proof-anchor selection. This is
not an authenticated P2P session or a public listener. TCP itself supplies no
peer identity; strict target-bound proofs authenticate state instead. No socket
failure becomes deterministic transaction invalidity or signing permission.

## Verification and remaining integration

Native regressions in `finalized_catchup_v1/stream_tests.rs` use real strict
Ed25519 proof readbacks, actual native execution/storage, empty and nonempty
blocks, fragmented input, forged context/manifest, excessive frame lengths,
shared signature budget, late bad proofs, snapshot/trailer/EOF corruption and
source-local commit-ID substitution. A bounded actual TCP child-process test
covers normal completion, source disconnect after a finalized prefix, and receiver
process exits after PREPARED and COMMITTED, followed by actual database reopen.
Fixture validator keys are test data, not live consensus or independent review.

I/O regressions cover absolute deadlines, fragmented progress and half-close.
Native process tests exercise the real finality/execution/snapshot receiver over
TCP. Existing restored-application WAL consumers remain unchanged; this does not
claim a default long-running Node host is wired. Run explicit I/O feature tests
in addition to the native and default suites.
No all-feature/default-workspace pass alone establishes this optional path.

Full persistent-validator/Core rejoin, membership-changing and two continuous
epoch transitions, incremental JMT persistence, authenticated bounded-history
recovery, large-state/multi-host goodput and external qualification remain open.
The transfer still executes/audits the historical suffix; full snapshot equality
still rejects different legitimate pruning shapes. This contract grants none of
those capabilities and does not change production/readiness flags.
