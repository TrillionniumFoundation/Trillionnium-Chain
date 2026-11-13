# Cell provider discovery PQ v3

Status: **historical parallel profile; superseded in the integrated candidate**.
This document retains PR #818 at `43e10d4dded2404f2b6ae8851a68173d9d792be6`
and its original **HOLD_NO_GO** observations. The integrated discovery owner is
[the authenticated epoch profile from #823](CELL_PROVIDER_DISCOVERY_AUTH_PQ_V3.md).
Only #818's complete-version residency joins that owner. Its parallel wire and
SQLite schemas share version labels with #823 but have different layouts and
signed domains; the current implementation explicitly refuses reinterpretation.
The parallel module and example are retained in Git history and original
evidence, rather than exposed as another current discovery entry point.

This continues [PN5 in the sole development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and the [previous discovery contract](CELL_PROVIDER_DISCOVERY_DEV_V1.md).
The implementation is [discovery/pq3](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/43e10d4dded2404f2b6ae8851a68173d9d792be6/trillionnium/crates/trnm-data-availability/src/cell/discovery/pq3.rs).
Its opt-in profile is `cell-provider-discovery-pq-v3`. CDP1/CDP2, their signed
domains, their databases and the existing command-line profiles retain their
original semantics. There is no automatic schema migration, namespace reset,
fallback verifier or production profile selection.

## Why another namespace is necessary

The preceding directories keep a permanent high-water row for every admitted
`(manifest, advertising owner)`. Expiry stops a location being returned, but
does not release any of the 16 per-manifest or 512 total identity slots. A
finite number of valid signed advertisements can therefore exhaust a directory
across prior operations. Round-robin processing of bootstrap replies in one
operation cannot repair already consumed durable capacity.

Deleting an expired latest row is unsafe. An owner can first sign a long-lived
sequence 1 and then a shorter-lived sequence 2. After sequence 2 expires, the
older sequence 1 remains signed and live. Removing all high water would accept
that old record again. A time-based eviction rule must bound the lifetime of
every signature it forgets, including superseded and withdrawn statements.

V3 makes that bound part of the provider's signed statement. Separately, a
provider signature authenticates an advertisement but does not authenticate
the bootstrap that returned it or bind it to a particular lookup. V3 therefore
also authenticates the complete query/response exchange.

## Signed lease epochs and bounded replay retention

CDP3 uses a new `TRNM/Cell/Provider/ML-DSA-65/v3` domain and pure native
ML-DSA-65 verification with an externally pinned authority roster and owner
generation. Its canonical record is 3,600 bytes. In addition to the existing
request/context, owner, endpoint, sequence, times and withdrawal flag, it signs
`lease_epoch`.

Epochs are fixed 300-second Unix windows. `issued_unix_seconds` is in the
signed window, and `expires_unix_seconds` is at or before that window's end.
Expiry is exclusive. A currently eligible statement must name the current
epoch. Sequence high water is scoped to that epoch; a fresh signature in a new
epoch may restart its sequence without reviving a prior epoch's record.

The fresh directory uses application ID `0x43445033`, schema version 3, and
`discovery_meta_v3` / `discovery_providers_v3`. Its namespace, complete deployment
context and authority-roster digest are pinned at creation. Every admission,
lookup and usage read checks the full schema and row/key/statement relations. The durable clock and
epoch cannot decrease. Advancing them retires old rows and publishes the new
metadata in one immediate transaction, with revision comparison and committed
readback before success.

There are two distinct budgets:

| Allocation | Active advertisement cap | Retained current-epoch replay cap |
| --- | ---: | ---: |
| Total identities | 512 | 512 |
| Per owner | 16 | 64 |
| Per manifest | 16 | 64 |
| Per first observed source IP | 64 | 256 |
| Per first observed /24 IPv4 or /64 IPv6 prefix | 128 | 512 |

Expiry, withdrawal and the pinned key's effective expiry stop charging the
active-advertisement budget. Their sequence/digest history remains in the replay
budget until the epoch is retired. A new identity can use released active quota
only while its applicable replay quotas also have room. Higher-sequence updates
reuse an existing replay identity, while their active status is checked anew.
Same-epoch old or conflicting statements cannot recover eligibility by expiry,
withdrawal, reopening the directory or retrying a query.

`usage_at(now, deadline)` reconciles the owner's clock under the original
deadline and reports active, tombstone and retained identities separately.
`usage()` reports the last committed observation time; it does not pretend
that a read-only diagnostic has advanced the directory's clock.

The main database remains limited to 4,096 pages of 4,096 bytes (16 MiB).
Replay slots are finite even within an epoch. Exhaustion returns a capacity
refusal; it does not evict another owner's live or still-replayable history.
Rollover makes old allocations reusable without reopening a fresh namespace.
It does not guarantee an honest admission if an authorized adversary refills
the next epoch. Actual fairness still needs a paid/admitted workload contract
and independent service operators.

The trusted-host assumption remains explicit. File identity checks and local
monotonic metadata do not defeat a privileged whole-store/clock rollback or
attest SQLite's independently opened descriptor. The 16 MiB figure excludes
rollback journals, filesystem metadata, temporary buffers and process RSS.

## Authenticated, query-bound bootstrap responses

Bootstrap authority is independently configured as an endpoint, key ID and
generation, with its own pinned authority roster. It is separate from the
provider-advertising roster. No reply can choose its own trust root. Duplicate
bootstrap endpoints or keys are refused in a configured source list; distinct
keys are still not proof of distinct administrators or failure domains.

CDQ3 requests include the target bootstrap identity and exact endpoint, a fresh
32-byte OS-random nonce, operation kind, and the complete lookup request or
announcement. CDS3 signs a length-delimited transcript containing the complete
canonical query and complete response, including result status, nonce, signer
identity/generation, issue/expiry times and every returned record or announcement
acknowledgement. The signing domain is
`TRNM/Cell/Bootstrap/ML-DSA-65/v3`.

Lookup success, an empty lookup, announcement acknowledgement and typed refusal
are all authenticated. The signed response lifetime is at most 30 seconds,
with the explicit clock-skew check, and ends no later than the authority's
expiry/revocation. Candidate eligibility is also bounded by
the provider advertisement, provider authority, and the original operation
deadline. Reusing a response cannot extend any of these bounds.

The receiver checks fixed framing and bounded lengths before allocation and
native signature verification. It rejects old wire versions, unsigned frames,
changed nonces, query/object/context mixups, different endpoints or key
generations, altered statuses/records, expiry and invalid signatures. It
interprets the status only after authentication. OS-entropy failure refuses
before dial; unsupported platforms have no predictable nonce fallback.

Authentication does not make a bootstrap honest or available. A pinned service
can sign an empty result, omit an honest provider, delay or refuse. The client
continues the bounded multi-source query and existing round-robin admission /
source-and-prefix selection; it does not turn source-count heuristics into a
Sybil-resistance or operator-independence claim.

The rendezvous reads the complete bounded current-epoch replay snapshot, then
filters records whose provider statement or current pinned authority is no
longer live. An expired or revoked key's retained high water cannot turn an
otherwise valid lookup into a signed denial. Among eligible records, active
providers precede withdrawn high water in the eight-record reply. Withdrawals
use remaining slots; none of these choices deletes durable replay history or
adds a verification, connection or byte allowance. A bounded reply does not
guarantee that all withdrawals reach every querying client, especially when
active providers consume the reply. The local replay-protection directory
cannot by itself create a candidate that no authenticated reply supplied.

## Original operation and resource accounting

The original caller's absolute deadline, connection counter and actual response
byte allowance are shared by discovery, manifest acquisition, chunks and retry.
There is no separate cold-fetch allowance or renewed deadline after metadata.

| Resource | V3 bound |
| --- | ---: |
| Explicit bootstrap sources | 4 |
| Discovery exchanges | 8, over at most two rounds |
| Records in one lookup reply | 8 |
| Combined bootstrap/provider validation slots | 64 |
| Distinct selected provider endpoints | 8 |
| Actual discovery response bytes | 256 KiB |
| Finite server connections | 64 |
| Server provider verifications + twice response-signing attempts | 64 |

Each bootstrap verification consumes a slot before verification; provider
records compete for the remaining slots. Rejected or truncated bytes are
charged when actually read. Failed operations retain observations rather than
becoming zero-cost missing samples. Application byte counts exclude request
bytes, TCP/IP overhead, retransmissions and unread socket data. Slot counts
are bounded cryptographic operations, not measured CPU-time guarantees. Each
server response-signing attempt reserves both native signing and its mandatory
signature self-verification; a failed attempt does not refund that reservation.

Discovery results remain untrusted location hints until the existing downloader
verifies the owner-pinned manifest/context and every actual payload chunk.
An authenticated response does not create custody, funds, installation, CURRENT
selection or FinalUse authority. The preceding classical and PQ-v2 transports
remain explicit historical development profiles with their documented limits.

## Relationship to the complete storage network

TCX1 already contains a complete target manifest and requires one complete
base; it does not recursively traverse an arbitrary delta ancestry. Each TMR1
lists at most 16 direct parent IDs; transitive lineage is not traversed during
payload recovery. This does not bound the entire historical lineage depth.
The [model storage contract](CELL_MODEL_STORAGE_V1.md) reports actual matching
chunk identities and bytes. No fine-tuning or quantization method is assumed to
preserve chunks, and no capacity plan assumes a fixed deduplication ratio.

The [complete-version contract](CELL_COMPLETE_VERSION_V1.md) additionally joins
TCV1 to one caller-identified local task's actually resident model and environment bytes, with
one memory/reference budget and original cancellation/deadline. Both current
component contexts must pass before either is delivered to the consumer.
That local byte join still needs the real restricted loader, device/ABI path
and Hepta resource/FinalUse owner for a full next-task product qualification.

The [custody and continuation contract](CELL_CUSTODY_CONTINUATION_V1.md) binds
declared retained-version sets, lease terms and sponsors, and reports continuation
work; the original retention and funding owners must execute effects. No change
here executes payments, purchases independent hosts, extends
unfunded retention, or turns multiple keys on one machine into independent
failure domains. Permanent retention of all uploaded history is not promised.

## Explicit native development example

The [native example](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/43e10d4dded2404f2b6ae8851a68173d9d792be6/trillionnium/crates/trnm-data-availability/examples/cell_discovery_pq_v3.rs)
uses new local directories, public test fixture keys and two finite same-host
loopback services. It performs signed announce/ACK, authenticated discovery,
a genuinely cold payload fetch, full output-byte comparison, withdrawal and
an expected counted refusal after the cache has been populated. The same
original absolute deadline applies throughout; announce and fetch remain
separate, explicitly counted operations. It stops and joins both services.

The withdrawal control requires a clean authenticated response carrying a
verified provider record and the retained withdrawal high water in the client
directory. Authentication, record-validation or capacity failures cannot count
as the expected refusal. The original advertisement must still be unexpired
in the same signed epoch when the control finishes, so ordinary lease expiry
cannot substitute for observing withdrawal.

```bash
bash scripts/project-preflight.sh
cargo run --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-data-availability --example cell_discovery_pq_v3 -- \
  /absolute/path/to/a-new-run-directory
```

The final directory must not exist. Its `report.json` retains failure
denominators, original budgets, actual bytes, public source identities and
server verification/signing reservations. The native CDP3 records and public
rosters are retained for inspection. Fixture keys must never become real
operator keys. This example neither runs a model nor demonstrates independently
operated or public-WAN service. An expiry or resource refusal remains a failed
observation; restarting it is a distinct run, not an extension of the old grant.

## Acceptance evidence

The source-specific continuation report records actual native regression names,
commands, exits and source identities. Required controls include expired active
quota reuse while old sequences remain refused; current-epoch replay exhaustion;
restart and clock rollback; epoch rollover with bounded physical database pages;
old schema/namespace refusal; complete signed-query mutation/replay tests;
real TCP bootstrap-only acquisition and unavailable/unauthenticated sources;
real rendezvous replies that skip expired/revoked provider keys while their
records remain live and prioritize active providers over withdrawn high water;
shared deadlines/bytes/validation counters; and complete model/environment
resident-byte admission plus cancellation and current-pin refusal.

These component controls cannot substitute for the existing PN5 campaign with
at least three independently administered fault domains, 72 hours of elapsed
operation, bootstrap loss/eclipse/spam, cold recovery, renewal/repair payments,
the original failed cohorts and original service deadlines. All production,
public-WAN, independent-custody and complete Hepta-use gates remain HOLD.
