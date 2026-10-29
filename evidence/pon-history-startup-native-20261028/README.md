# History Startup checkpoint and material-seal candidate

This is an implemented source candidate. Its current M01/M06 material code has
been freshly compiled and executed locally, with all nine focused tests passing.
The new Node path and its four new native methods have **not been compiled or
executed locally**: available disk dropped below the existing 256 MiB stop line.
The independent mandatory hosted gate is the next acceptance boundary. No prior
runtime's successful test is reused as a verdict for this candidate.

The original frozen publication/settled-epoch runtime separately passed the whole
15/0/1 hosted release suite. Its exact original ZIP, all 1,196 member hashes,
source/tree, binary observations, 23 actual kill/wait4 guardians, 14 process
windows and 28 Startup settlements are retained in the
[separate hosted evidence](../pon-history-hosted-afc8d6d-20261028/README.md).
Earlier local failures also remain intact.

## Implemented behavior

The public M06 legacy APIs keep their original read-byte callbacks and unchanged
numeric relation. New typed progress entry points check activation/header JSON
byte reads at intervals no larger than 65,536 bytes, strict JSON visitor work,
activation hex decoding, header/tensor validation, complete checkpoint scanning,
weight/activation quantization, the full hidden-vector nonfinite check, matrix
binding, task hash and descriptor serialization. The first owner error is retained
through serde's I/O bridge; a later parse error cannot relabel a CPU, expiry or
cancellation refusal. The new M01 task hash uses the original framing and field
validation order, with cooperative progress through validation and hashing.

History passes its existing actual Startup operation through these checkpoints.
It does not construct a replacement CPU domain or borrow an additional allowance.
A request-only cancellation object selects one signed Startup operation ID. The
same flag enters the active owner; wrong-operation cancellation is rejected before
reservation. Initial catalog callbacks preserve the original owner error too.
Both existing `read_active` operations now use their existing progress-aware entry
point, retaining the actual SQL State, continuity/root and tip/generation/slot
stability checks. Existing frontier, namespace, marker and recovery checks remain.

The first complete material replay returns private `PreparedHistoryCheckpoint`
Settings plus a consumed `StartupMaterialSeal`. The seal is non-Clone,
non-serializable and confined to the owner thread. It retains the checked material,
both original file handles and exact metadata, and the actual intent hash, live
CPU Arc, cancellation Arc, deadline and budget expiry. At Node entry, the same
active owner re-reads protected spec/bootstrap/model/input bytes; consumption
compares current context and Settings, performs complete second checkpoint and
activation hashes, and rechecks both held and visible identities and policy.
There is no saved boolean that grants permission. General Settings retain their
original complete replay path.

The original actor codecs permit one final LF. The prepared proof therefore pins
the exact protected raw spec/bootstrap bytes actually decoded, including a legal
LF, rather than hashing a canonical re-encoding. A positive LF case accompanies
the context and file-replacement refusals.

## Local evidence and limits

| Check | Actual result and scope |
| --- | --- |
| `material-01` | Fresh current-source protocol, crypto, verification-profile and M06 libraries compiled; test link failed because the standalone runner omitted `--extern hex`. The failed log and receipt are retained. |
| `material-02` | Reused only those freshly built and source-pinned current libraries, corrected the missing test-link argument, freshly linked the test, and executed all 9 tests successfully. No old workspace library supplied the new code. |
| Material test binary | 9,247,296 bytes; SHA-256 `9efdbbe37cb235b40c77c4e719ed404aef3c76e591686f299632ec415d53c860`. Complete gzip and decompression verification retained. |
| Source/cache observations | All current material source hashes still match the executed sources. The old cache supplied only separately pinned read-only third-party dependencies. |
| Exact hosted runner controls | Five real Python tests pass, including missing/duplicate/substituted roster refusals, zero/partial/multiple-summary refusal, owned-process cleanup, gzip splitting/reconstruction and corrupted-part refusal. These are runner tests, not Node runtime acceptance. |
| Format | Whole-workspace `cargo fmt --all --check` completed successfully before the final raw-LF fix; the subsequently changed Rust files also receive direct formatting/check receipts. Hosted formatting remains mandatory for the final source. |
| New Node build, Clippy and 19-method native group | Locally NOT_RUN; source and tests are present for mandatory independent execution. `node-not-run-resource-boundary.json` records the observed resource boundary. |

`material-01-raw.tar.gz` and `material-02-raw.tar.gz` retain complete original run
directories, separately preserving failure and success. Their member manifests
include byte hashes, sizes, mode, uid/gid and nanosecond mtime. Individual source,
compiler, library and third-party cache pins are also retained. Direct rustc
commands are explicitly not whole-workspace Cargo qualification. The local
material library uses opt-level 1, its test harness opt-level 0, and debug/overflow
checks are enabled; these numbers are not release performance measurements.

The narrowly authorized old working Node ELF retirement is separately recorded:
all five remote #526 byte parts matched, their concatenated gzip matched the
original local gzip, decompression matched the entire original ELF, and immediate
filtered FD/maps/exe audits found zero references/unreadable/unexamined PIDs with
stable inode and timestamps. Only that one reconstructable working ELF was
removed. The original local gzip, five published parts and all earlier logs remain.
The initially denied ordinary network read and all readback/audit records remain.

## Required independent gate

`.github/workflows/pon-history-epoch-v1-native.yml`, job `history-native`, checks
every tracked byte at the exact candidate before and after execution. Its runner:

1. Builds the exact new Node release test executable with locked dependencies.
2. Saves every byte of the actual executable as ordered gzip parts of at most
   4 MiB, with per-part and whole gzip hashes, original ELF size/SHA and an
   independent full decompression readback. It repeats the binary hash after use.
3. Requires the exact 20-method inventory: original 15 methods, four new Startup
   methods and the original ignored helper. One native invocation must finish
   with **19 passed, 0 failed, 1 ignored** under the unchanged **600-second** bound.
4. Builds, retains and executes the same-source nine material controls; no empty
   or substituted group satisfies the exact roster and summary checks.
5. Requires `cargo fmt --all --check` and strict Clippy for all three changed Rust
   crates. Failure artifacts and terminal/source receipts are always uploaded.

The four new Node methods cover eight cancellation points (interior material,
both complete second hashes and each actual State read), actual owner-thread CPU
depletion, original deadline and separately signed operation/budget expiry,
one-shot seal/context/handle mutations and file replacement/mutation, legal LF,
and wrong-operation cancellation without a new debit. The real entry controls
check the actual settled CPU, preserved 4-second lifetime debit and cold journal.
The small seal unit controls use real paid CPU handles but explicitly do not claim
to authorize a durable Startup.

The **2-second burst, 4-second signed allowance, zero-credit epoch, 2-worker limit
and at most 4 parent snapshots are unchanged**. The four additional method groups
do not receive a larger native-suite budget. The original standalone process
helper remains invoked by the same mandatory process cases.

## Remaining boundaries

No claim of a measured optimization is made. Complete second file hashes and both
State reads remain necessary; the proposed saving is redundant parsing and
quantization within the same actual Startup. Signature operations, bounded sorts
and root arithmetic still have indivisible intervals; this is cooperative checking,
not hard real-time preemption. Cancellation of the original zero-credit refill
wait is unchanged and is not promised to be immediate.

A known failed Startup preserves its debit and leaves the epoch open. It does not
invent clean-close authority, silently forgive a pending interval, or authorize a
new Startup. General Startup/Close recovery, partial-reorg continuation, exhausted
lifetime ceiling renewal, full journal/store capacity, historical arbitrary
process-tree death observation and physical power-loss qualification remain
separate requirements. This candidate does not claim whole History P0 or
production acceptance.
