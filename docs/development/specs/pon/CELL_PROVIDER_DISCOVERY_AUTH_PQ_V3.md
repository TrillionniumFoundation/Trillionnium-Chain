# Authenticated, reclaimable Cell provider discovery — PQ V3

This explicit development profile continues
[V1/V2 discovery](CELL_PROVIDER_DISCOVERY_DEV_V1.md) and the
[complete storage-network acceptance contract](CELL_STORAGE_NETWORK_ACCEPTANCE_V1.md).
The authoritative work register is the
[sole development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
Location hints confer no custody, payment, installation or consensus authority.

## Why a fresh profile is required

V1/V2 protect a permanent `(manifest, owner)` sequence high water. Expiry makes
an advertisement ineligible but never releases its identity allocation. A
valid signer can exhaust a manifest over earlier operations, even after fair
admission within each current query. Deleting an expired row would erase that
high water: a signer could submit a newly timed lower sequence, or replay a
lower sequence whose original longer lease outlived a newer short lease.

V3 therefore changes the signed sequence namespace explicitly. Its provider
record is CDP3; its authenticated exchange is CDQ3/CDS3. The new directory has
a fresh application/schema identity and immutable authority/source rosters.
There is no automatic upgrade, eviction-based V2 reset or classical fallback.

## Signed epoch and replay lifetime

An epoch is the fixed 300-second interval selected by `floor(unix_seconds/300)`.
The complete 192-byte pinned request is followed by an unsigned big-endian
64-bit epoch. The provider signature binds that full 200-byte request, owner
key/generation, endpoint, sequence, issued time, expiry and withdrawal flag.
The exact interval is `epoch_start <= issued < expires <= epoch_end`, with
`now < expires` for current eligibility. Expiry may equal the epoch end and is
exclusive.
The original maximum 300-second lease and five-second future skew remain upper
bounds. A future or closed epoch is rejected.

For an admitted directory identity within one epoch, equal statements are
idempotent, lower sequences and equal-sequence changed statements reject, and a
higher sequence can replace a lease or withdraw it. Different valid randomized
ML-DSA signatures of the same
statement do not create equivocation. Every received signature must still be
verified before this statement comparison is trusted.

An expired/withdrawn row, or a row whose pinned provider authority has expired
or been revoked, stops consuming **active** capacity. Its high water
continues consuming **history** capacity until that epoch closes. Closing an
epoch atomically advances the durable clock floor and deletes its rows; the
floor subsequently rejects that epoch across restart. Sequence 1 in a new
signed epoch is explicitly a new sequence namespace, not a rollback of the old
one. Reclamation occurs inside later successful admission, lookup or `usage_at`
operations, not a background timer. Usage reports active, retained, replay-only
and cumulative reclaimed identities; row reclamation does not promise immediate
physical database shrinkage. The directory does not support whole-database/clock
rollback by its host.

Verified-record receipts are sealed by actual native ML-DSA verification. They
carry authority identity, observed time and a non-extendable monotonic expiry.
The observation pairs full-resolution wall time with its monotonic instant.
A record that was valid when received may become expired while later sources
are collected or its signature is verified. Its verified historical statement
still participates in conflict detection; it is not thereby eligible for use.
Durable admission rechecks those constraints and the caller's original deadline;
it cannot revive a record by waiting for a lock, changing rosters or reusing an
earlier verification after expiry.

Each discovery operation also retains its highest actually verified sequence
per owner across both rounds, before current-expiry and directory-quota filters.
A higher observation immediately removes any lower candidate, including when
the higher lease has since expired or its withdrawal cannot enter a full source
allocation. Lower observations still participate in same-sequence conflict
detection before this selection veto. Equal highest statements may try another
eligible source, and a later higher valid statement may proceed normally.
This bounded operation-local veto does not claim that a rejected observation
was durably admitted. Only committed directory rows establish the persisted
cross-operation high water; the veto neither deletes those rows nor bypasses
their capacity limits.

## Fixed active and history allocations

| Scope | Active records | Retained replay/history rows |
| --- | ---: | ---: |
| Whole directory | 512 | 512 |
| Advertising owner | 16 | 32 |
| Manifest | 16 | 32 |
| Authenticated pinned source | 64 | 128 |
| Source IP | 64 | 128 |
| Source IP prefix | 128 | 256 |
| Authenticated source and manifest | 4 | 8 |

The source roster is pinned at creation and remains immutable for the namespace.
It contains at most 64 `(key ID, generation, canonical source IP)` entries;
each client query selects at most four explicit bootstrap endpoints. Server
publication sources and client bootstrap sources share this bounded policy
representation, not an inference of common roles or independent operators.
Source shares aggregate the key ID across generations and IP addresses. The
first admitted source remains attached to an identity within its epoch, including
same-statement and higher-sequence updates. Source IP prefixes are IPv4 `/24`
and IPv6 `/64`; IPv4-mapped addresses are canonicalized first. A source cannot
evade its share with new provider keys, repeated operations or changing response
order. Expired/withdrawn record identities that reactivate must pay active capacity
again, and expired or revoked authority cannot authorize that reactivation. A full
history allocation rejects new keys until safe epoch reclamation; it does not
evict high water, grant a new allowance or claim successful availability.

The provider authority roster's complete digest is persisted. The source roster
pins IDs, generations and IPs. Bootstrap authority validity and revocation are
checked against the caller's current supplied bootstrap key view on each call;
this is not an independently fresh durable bootstrap-revocation oracle.

The main SQLite database remains capped at 4,096 pages of 4,096 bytes (16 MiB).
That is not a bound on rollback journals, filesystem metadata, transient buffers
or total process RSS. Short transactions perform bounded directory work without
network access, and retain exact row/schema/context/roster/revision readback.
Clock rollback, incompatible schema and changed authority/source pins reject.
Fresh creation samples the wall clock. Successful operations persist the clock
floor and a revision; a supplied time below that floor or a revision below the
instance's observed revision rejects. Advancing past an epoch cannot be undone
by subsequently presenting an earlier clock value.

The fresh SQLite identity is application ID `0x43445033`, user version `3`.
Both `discovery_meta_v3` and `discovery_providers_v3` are STRICT tables. Metadata
holds the singleton context (128 bytes), authority and source digests (32 bytes
each), and clock, revision and reclaimed counter (eight bytes each). Provider
rows have primary key `(epoch, manifest, owner)` and retain the exact 3,600-byte
signed wire. Unsigned 64-bit integers use big-endian eight-byte blobs.

## Query-bound source authentication

Every exchange generates a fresh 32-byte nonce from the system random source.
Randomness failure refuses the exchange. The caller fixes the bootstrap endpoint,
ML-DSA-65 key ID and key generation before dialing. A response cannot supply its
own trust anchor. The signed reply binds the exact request and epoch, nonce,
target endpoint/key/generation, reply validity interval, status, length and body.
Success, rejection and capacity statuses are authenticated alike.

The client verifies current supplied key validity/revocation, the expected
bootstrap identity, original query and nonce, exact response bytes and expiry
before deriving a trusted source observation. A correct provider signature does
not authenticate the bootstrap reply. A reply for another query, generation,
endpoint or epoch is rejected; an older V1/V2 frame is not a fallback.

Publication also binds the provider's proof of possession to its exact record,
nonce and targeted bootstrap. Possessing an old public advertisement is not
authority to manufacture a fresh authenticated source request. An acknowledgement
still records only the exact durable advertisement statement, never payment or
service completion.

| Encoding boundary | Canonical representation |
| --- | --- |
| Request V3 | Original 192-byte request plus eight-byte epoch: 200 bytes |
| Provider CDP3 | 291 unsigned bytes plus 3,309-byte ML-DSA-65 signature: 3,600 bytes |
| Lookup CDQ3 | Eight-byte prefix, payload length, nonce, request, target endpoint/key/generation and validity interval: 319 bytes with no payload |
| Announcement CDQ3 | Same query plus signed provider record and 3,309-byte query-bound possession signature: 7,228 bytes |
| Reply CDS3 | 28-byte prefix/validity/body-length header, exact body, then 3,309-byte signature |

Provider signatures use domain `TRNM/Cell/Provider/Epoch/ML-DSA-65/v3\0`;
semantic statement digests use `TRNM/Cell/Provider/Epoch/Statement/v3\0`.
Announcement possession uses `TRNM/Cell/Discovery/Announce/ML-DSA-65/v3\0`
and the unsigned query, including its advertised full payload length.
Reply signatures use `TRNM/Cell/Discovery/Reply/ML-DSA-65/v3\0`, the complete
query bytes (including announcement possession when present) and unsigned reply.
The terminal `\0` denotes a single zero byte. The independent vector records
the complete canonical bytes rather than relying only on these length summaries.

## Shared resource accounting

V3 retains four explicit bootstraps, eight discovery connection attempts, eight
records per lookup response, eight final endpoints and the PQ 256 KiB discovery
response allowance. Authentication overhead is charged as actual read bytes.
All native signature validations, including signing operations' built-in
self-checks, share the original 64 validation slots on their respective client
or server operation. Invalid, truncated and rejected exchanges consume the
actual work already performed. No slot is refunded after failure.

Discovery, manifest fetch, chunk fetch and retry share the original Cell session's
connection/response-byte reservation and absolute deadline. Reports separate
discovery detail from aggregate counters; discovery is already included in the
aggregate and must not be added twice. Source-fair collection retains actual
receipt times, same-sequence conflict history and final durable high-water
readback before selecting live endpoints. Waiting for another source cannot
refresh a record, authority lease or operation deadline.

## Explicit API and evidence boundary

The public Rust entry points are `serve_authenticated_cell_rendezvous_pq`,
`announce_authenticated_cell_provider_pq` and
`fetch_authenticated_discovered_cell_to_file_pq`, with explicit V3 provider,
request, directory, source-roster and bootstrap-key objects. They require an
explicit fresh directory and address policy. Existing command-line V1 profiles
retain their old meaning; choosing a new Rust API is not a production rollout.

The source contract requires real native signature and TCP controls for wrong
keys/nonces/requests/epochs/status/body, revoked or expired authority, refusal
accounting, source shares, cold retrieval, permanent-state recovery, shortened
leases, reopen/rollback/schema faults and exact original budgets. Independent
encoding vectors bind canonical request/provider bytes. Actual execution counts
and failures belong in the source-bound evidence record, not in this normative
contract.

This finite roster profile does not prove open-network Sybil fairness, independent
administration, confidentiality, funded storage, whole-host anti-rollback or
eclipse-free availability. A malicious pinned source can withhold replies; all
surviving sources may be unavailable. Exhaustion returns a bounded refusal and
counts as a service failure. PN5's independent 72-hour WAN campaign and the real
loader/Hepta owner gates remain **HOLD_NO_GO**.
