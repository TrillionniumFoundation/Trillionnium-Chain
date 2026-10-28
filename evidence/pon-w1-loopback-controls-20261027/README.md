# W1 loopback component controls — synthetic bytes only

Base: `5d957878ea82b09b555c713976f5157fde1089a0`.
The [validation record](validation.json) binds the final helper sources and
[complete raw archive](raw-evidence.tar.gz). No complete W1 receipt was used,
no proof was generated, and the public CLI's real native verification before
and after transmission is **NOT_RUN**. All qualifications remain false.

| Local batch | Actual result | Scope |
| --- | --- | --- |
| 001 | 5 PASS, 9 ERROR, exit 1 | Restricted shell rejected AF_INET socket creation with EPERM; complete failures retained |
| 002 | 14 PASS, exit 0 | Explicitly approved 127.0.0.1 networking, unchanged first source |
| 003 | 14 PASS, exit 0 | Final source, also retaining unresolved original-owner receipts and Python executable identity; CLI negative now supplies all required arguments |

The fourteen final controls cover real two-process streaming and separate
wait4/RSS closure; short frame and short payload; trailing bytes; wrong SHA;
over-limit header before payload allocation; wrong per-run nonce; TCP timeout;
no overwrite of an existing destination; an actual timed-out child; an actual
RSS-breaching child; exit zero without native verification output; absence of
public skip/synthetic/supplied-result options; and original source bindings.
These are fourteen test cases, not independent statistical samples or proof
soundness tests. The original restricted-shell failures were not relabelled.

The final 2,097,152-byte synthetic transfer observed 372,890,599 ns wall time,
including startup, hashing, fsync, readback and closure, plus 160 application
framing bytes. Sender and receiver wait4 CPU were respectively 121,954,000 and
163,834,000 ns. Each recorded 22,155,264 bytes wait4 peak RSS, under its separate
128 MiB gate; parent CPU over the complete interval was 20,443,322 ns. Both
children were actually reaped by their exact wait4 owners. These figures are
not native proof verification cost, WAN throughput, TCP/IP byte count or a
joint parent-and-children memory bound.

The raw archive is 80,292 bytes, SHA-256
`2d90b4f2d1db22c37e045afd4ada192cc7847b501485e97a9b31b5b3803e76ef`,
with 95 members. It retains command/source snapshots, every stdout/process
record, labelled synthetic byte files and per-run local nonce values. Earlier
source files are explicitly labelled as reconstructed from the final source
by reversing the small follow-up and verified against both original 001/002
before/after SHA snapshots. The final source bytes match both 003 snapshots.
The archive contains no signing private key, issuer state, user credential,
model weights or actual proof receipt.

See the [fixed limits and inactive CI wiring proposal](../../trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/LOOPBACK_COST.md).
Publishing is deliberately held until the original full proof attempt is
terminal and one reviewed successor binds genuine receipt reuse or strict
same-session segment recovery. No scheduler, reuse-policy or workflow source
has changed in this component.
