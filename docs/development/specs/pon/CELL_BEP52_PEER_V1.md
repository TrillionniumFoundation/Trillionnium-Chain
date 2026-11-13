# Cell pinned BitTorrent v2 TCP peer V1

Status: bounded native network component for the existing PN5 candidate. This
adds an explicit TCP transfer path to [the offline BEP52 binding](CELL_BEP52_BINDING_V1.md).
An explicit one-hop, read-only UDP DHT query can return bounded candidate hints.
An additional opt-in iterative client can follow admitted node hints within the
same original session; its exact scope is defined below.
Production, public discovery, independent custody, WAN SLA and ordinary Hepta
execution remain `HOLD_NO_GO`.

## Boundary and authority

`fetch_cell_bep52` accepts an independently constructed `CellBep52BindingV1`, an
explicit list of at most eight caller-approved socket addresses, a local peer
identifier and one mutable `CellBep52PeerSessionV1`. It obtains raw payload bytes
over real TCP, validates each actual TCM1 chunk, stores it in `CellStoreV1`, and
performs the existing complete ordered payload verification before success.
Interrupted transfers retain only verified cache chunks and can resume under
the same session reservation. Repeated chunk digests are downloaded once.

`CellBep52SeedV1::prepare` performs a complete source-cache readback and builds
the bounded hash tree. `serve_connection` serves one TCP stream already accepted
by the owner. Every served chunk is read and hashed again. Preparation is a
historical observation, not an ongoing custody certificate. A caller controls
the listener, accepted peers, process lifetime, storage ownership and export
authorization. This component never starts an accept loop or a detached job.

There is no authority in a peer identifier, handshake, magnet or successful
download. The connection is plaintext and the peer is unauthenticated. Existing
PQ publication approval, current revocation, loader admission and Runtime
FinalUse remain owner obligations. Private models require an explicitly
authorized export policy before this transport is exposed. No model bytes are
advertised or published automatically by constructing a descriptor or seed.

## Optional independently pinned TCV2 content

`fetch_cell_bep52_with_content` accepts a `PinnedCellVersionContentV2` in
addition to the same binding, endpoints and original session. The pinned view
comes from the independent owner's complete loader context and 64-byte TCV2
root. A provider cannot select the expected root through a peer response.

This entry point checks exact full manifest membership before any cache or
socket activity. Every cached chunk and received piece must satisfy the pinned
SHA-512 chunk record as well as its original TCM1 declaration. A received piece
is checked before CAS publication. The final ordered readback computes the
original SHA-256 and domain-separated TCV2 SHA-512 full payload digests in one
scan of the actual cache bytes. All checks retain the original absolute
deadline, cancellation and cumulative socket reservation.

An inconsistent strong chunk record rejects a valid legacy piece without
inserting a payload chunk. Already admitted manifest metadata may remain. A
later whole-payload mismatch returns no successful fetch observation while
retaining previously verified chunks and the consumed network budget.

The original `fetch_cell_bep52` retains its TCM1 semantics. The new entry point
observes one complete manifest; it does not authenticate a publisher, verify
the other model/environment members, freeze future CAS bytes or grant
FinalUse. CPV4, complete-version readback, the actual sealed-loader handoff and
the current execution owner's decisions remain separate required checks.

## Implemented wire profile

The implementation uses the standard framing described by
[BEP52](https://www.bittorrent.org/beps/bep_0052.html), the negotiated extension
envelope in [BEP10](https://www.bittorrent.org/beps/bep_0010.html), and
[BEP9 metadata exchange](https://www.bittorrent.org/beps/bep_0009.html).

| Surface | Contract |
| --- | --- |
| TCP handshake | 68 bytes, standard protocol identifier, BEP10 flag, 20-byte truncated v2 infohash and peer identifier |
| Full identity | Metadata must hash to the full independently pinned 32-byte SHA-256 infohash and equal the exact TCM1-derived canonical info dictionary |
| Metadata negotiation | Each peer advertises its own `ut_metadata` ID; the response/request direction uses the receiver's ID |
| Metadata size | Exact pinned info-dictionary size, at most 256 bytes; no peer-driven allocation or arbitrary torrent parser |
| Metadata request | BEP9 piece zero, matching response index and total size; data is outside the bencoded header |
| Piece requests | Standard `request` / `piece` / `reject` messages with exact request correlation and chunk length/hash checks |
| Availability | Bounded `bitfield` and `have` hints; no chunk approval from a hint, and spare bit/range/duplicate-bitfield refusal |
| Hash service | Standard `hash request`, `hashes`, `hash reject`; leaf/piece layer zero, aligned power-of-two ranges of 2–512 hashes, exact root and bounded proof layers |
| Cancellation | Caller cancellation is latched at observation and checked throughout socket and cache phases |
| Local storage | Existing CAS quota, verified reads, deadline-aware writes and complete payload verification |

The profile has one `cell.bin`, 16 KiB pieces, at most 16,384 leaves and at most
256 MiB of raw payload. A single short piece is valid. BEP9 transfers the info
dictionary only: external piece layers are not part of that exchange. The
downloader already has all independently pinned TCM1 chunk hashes and verifies
the actual bytes against those pins. It does not treat a missing external
piece-layers dictionary as a new source of trust. The seeder can serve BEP52
hash ranges, including zero padding and the appropriate upper siblings.

The network bencode parser is limited to bounded protocol headers. It requires
canonical lengths and integers, sorted unique dictionary keys, at most eight
nested levels and 128 values. Unknown extension names are ignored after bounded
parsing. Later extension handshakes are ignored, as BEP10 permits; this connection
retains its initial ID mapping. Unknown BEP9 message types are ignored under the
same message/byte/deadline accounting.

This is an explicit download connection and a separately prepared seed
connection. It does not implement tit-for-tat, general torrent layouts, uTP,
trackers, peer exchange, encryption, hybrid SHA-1 torrents, automatic endpoint
discovery or an always-running swarm owner. Requests are sequential; there is
no unbounded upload queue. Unsolicited piece/hash responses are refused.

## One original reservation

The session is non-cloneable and carries a nonzero caller operation ID, an
absolute deadline, per-request timeout, connection count, total receive/send
bytes and combined incoming/outgoing message allowance. None is replenished
between peers, metadata exchange, chunks or continued calls. The operation ID
labels accounting; it is not a signed capability or a persistent idempotency
ledger. The enclosing owner must recover that durable identity before resuming
after a process restart.

| Bound | Maximum admitted |
| --- | ---: |
| Explicit endpoints per fetch | 8, no duplicates, unspecified/multicast address or zero port |
| Connections per session | 8 |
| Per-request timeout | 10 ms through 30 s |
| Absolute remaining lifetime at session construction | 24 h |
| Combined frame attempts | 100,000 |
| One frame body | 17,408 bytes |
| One extension-handshake body | 4,096 bytes |
| Receive or send allowance | 8 × 256 MiB + 8 × 1 MiB |
| Prepared hash tree | At most 32,767 SHA-256 digests |

Limits are ceilings, not defaults or a new acceptance service contract. The
owner must supply the existing operation's remaining budget. In particular,
this component does not extend the original four-second Host contract, replace
the separate 30-second attack campaign, or turn a caller-selected 24-hour ceiling
into a qualified SLA.

Socket counters measure bytes actually read/written, including partial and
invalid messages. Oversized lengths are rejected after reading the four-byte
prefix and before allocating or reading the announced body. Failed peers remain
refused in the same download session. Bounded refusal descriptions remain
available after failure; these include local or transport errors, not a fraud
verdict. Keepalives consume message budget. Message counters
count admitted frame attempts, including an attempt that fails or observes EOF.
Request and TCP/IP overhead not passed through the socket application interface
is outside receive-byte accounting; send bytes are recorded separately.

Blocking TCP reads/writes use short timeout slices and recheck cancellation
and the original deadline. A fragmented response cannot reset its request
deadline. TCP connection establishment is bounded by the remaining original
request deadline and observes cancellation at its next checkpoint. SQLite and
filesystem operations retain the existing cooperative deadline semantics; this
is not a kernel CPU/RSS/PID reservation or preemption guarantee.

## Explicit read-only DHT candidate query

`query_cell_bep52_dht_peers` sends one [BEP5](https://www.bittorrent.org/beps/bep_0005.html)
`get_peers` query to exactly one caller-approved IPv4 bootstrap endpoint. The
query carries [BEP43](https://www.bittorrent.org/beps/bep_0043.html) `ro=1`, so
cooperating nodes should not add the caller as a routable DHT node. A query
exposes the truncated content identifier to that endpoint; the caller must
authorize that disclosure. The call does not send `announce_peer`, retain a
write token, answer unsolicited queries, contact a returned node, or start a
routing-table maintenance task.

The original session jointly limits TCP connections and UDP queries to at most
eight. Each query has exactly one outgoing and one incoming datagram attempt,
no retransmission and one hop. The caller supplies an eight-byte correlation
ID that cannot be reused in the same session. A connected UDP socket admits
the configured response endpoint; the returned source address and echoed
transaction bytes are also checked. These are correlation checks, not peer
authentication or protection against a capable network attacker.
The single UDP send uses the remaining request deadline; cancellation is
observed at the following checkpoint. UDP receive waits use short timeout slices.

Accepted response payloads are at most 1,200 bytes. Before a query is sent,
65,536 bytes must remain in the original receive allowance. This conservative
reservation permits reading an entire IPv4 UDP payload, including a malformed
or oversized one, before charging its actual size and refusing it. Unused
capacity is retained. No oversized datagram is silently truncated and counted
as a shorter successful message. Packets discarded by the OS source filter,
IP/UDP headers and retransmissions are outside application-byte counters.

The strict header parser admits at most 32 compact peer candidates and eight
compact node candidates. It rejects malformed widths, duplicates, zero ports,
unspecified, limited broadcast (`255.255.255.255`) and multicast addresses.
Subnet-directed broadcast detection remains the enclosing endpoint policy's
responsibility. Return values are explicitly
named `CellBep52DhtHintsV1` and `CellBep52DhtNodeHintV1`. The report's full
infohash is the caller's original lookup context; BEP5 itself queries only its
20-byte prefix. Every future TCP transfer still needs exact full metadata and
the independent TCM1 pins. A DHT result supplies no provider signature, release
selection, current permission or independence evidence.

This is a bounded query seam, not an iterative public DHT implementation.
Returned candidates can only be used after the enclosing owner independently
applies its endpoint/export policy. The authenticated Cell discovery directory
and its durable identity/sequence history are not populated from these hints.

## Verification and retained limits

Native tests use real loopback TCP sockets. They include an independently
written byte-level peer with metadata extension ID 17, transfer to the ordinary
CAS, complete payload readback and materialization, cached resume and repeated
chunk deduplication. Negative tests cover a matching 20-byte handshake followed
by wrong full metadata, a metadata size bomb, an oversized frame, a partial
header, a keepalive flood, a slowly fragmented handshake, exact byte exhaustion,
latched cancellation, unsolicited pieces and a corrupt first peer followed by
successful repair from the next peer within the same reservation. Hash-service
tests cover padding, proof siblings and wrong-root rejection. A manifest whose
individual chunks are valid but whole-payload digest is wrong still fails.
UDP tests exercise actual read-only query bytes, wrong-source filtering,
transaction mismatches, error responses, full oversized-datagram accounting,
non-followed node hints, replayed query IDs, exact reservation bounds and
candidate/parser limits.
Strong-content controls use real TCP peers and a ready local listener: a wrong
owner root or foreign manifest is refused before dialing, a legacy-valid piece
with a wrong strong chunk record inserts zero payload rows, a cached hit cannot
bypass that check, and a valid strong transfer completes actual readback and
cached continuation. A wrong full SHA-512 record still rejects success after
all individually valid chunks have been stored. These controls retain failure
bytes, refusal state and the original deadline.

These tests establish local wire behavior and integration with the existing
cache. They do not establish interoperability with an independently operated
public BitTorrent implementation, public DHT availability, Sybil/eclipse
resistance, independent operator placement, funded renewal, a 72-hour custody
campaign, WAN p95/p99 or PQ transport security.

## Opt-in bounded iterative DHT lookup

`lookup_cell_bep52_dht_peers` preserves the original one-hop entry point and
wire parser. It accepts 1–8 explicit bootstrap endpoints, 1–8 caller-generated
fresh nonzero transaction IDs, an immutable endpoint policy and the same
non-cloneable `CellBep52PeerSessionV1`. The transaction-ID count is a per-call
query ceiling, not an additional connection allowance. Callers can reserve
room for subsequent TCP acquisition by supplying fewer transaction IDs.

The client queries admitted bootstraps first, then orders advertised nodes by
the BEP5 XOR distance to the truncated infohash. It deduplicates advertised node IDs and
endpoints and checks that a queried advertisement returns its advertised node
ID. The check correlates unauthenticated messages; it establishes no operator
identity or Sybil resistance. Each hop discloses the truncated lookup target to
another endpoint in the owner-approved scope. All queries retain `ro=1` under
[BEP43](https://www.bittorrent.org/beps/bep_0043.html).

| Boundary | Iterative-client behavior |
| --- | --- |
| Public policy | Literal IPv4 unicast only; conservatively reject the IANA special-purpose blocks, multicast and reserved addresses, including the narrow service exceptions inside those blocks |
| Explicit policy | Exactly 1–64 caller-approved IPv4 address/port pairs; a response cannot extend this allowlist |
| IPv6 | Outside this wire profile; no DNS resolution, mapped-IPv6 conversion or mixed compact IPv6 peers |
| Targets and results | Apply the same endpoint policy to bootstrap queries, learned node queries and returned peer hints |
| State | At most eight bootstrap plus 64 advertised node candidates and 32 returned peers; no persisted routing table |
| Cost | UDP queries and TCP attempts share the existing total ceiling of eight, original deadline and byte/message limits |
| Failure | Malformed, oversized, unavailable or miscorrelated replies retain actual costs; further work uses only the remaining reservation |
| Stop | Report frontier exhaustion, peer limit, query limit or remaining-session-budget exhaustion; cancellation and expiry propagate errors |
| Authority | Return hints only; no automatic TCP dial, announcement, serving loop, export authorization or FinalUse |

The public-address policy is a fixed conservative scope based on the
[IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/),
not proof of routability or ownership. Subnet-directed broadcast and public
addresses routed into sensitive local services still require the enclosing
network's egress policy. A successful response does not establish complete DHT
coverage, availability or trustworthy content. Independently pinned full
BEP52/TCV2 identities remain necessary at download and loader admission.

`cell_bep52_iterative_discovery` is a finite native component example. It uses
real local UDP queries across two hops per object, requires an explicit owner
choice before TCP dialing, transfers a synthetic model/environment pair through
the existing BEP52 path and checks the complete independently pinned TCV2 bytes.
Both objects share one receiver session. Its original limit is six combined
attempts: four DHT queries and two TCP connections. It joins all finite server
threads and reconciles application-byte counts. The example is not a model
forward, ordinary Hepta task, independent operator or WAN measurement.

The next network qualification needs independently operated peers, third-party
client captures, the original resource/service contracts, failures in the
denominator and current owner/export admission. Public discovery remains an
explicit open gate: the one-hop and bounded iterative clients do not establish a routing network,
independent operators or resistance to DHT eclipse/Sybil attacks.
