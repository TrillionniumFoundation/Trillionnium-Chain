# Bounded Cell provider discovery, development v1

This is a finite rendezvous service in the independent
`cell-provider-discovery-dev-v1` namespace. It supplies signed location hints for
an already pinned Cell manifest. It does not participate in consensus, select a
model release, lock or transfer funds, grant installation authority, prove
endpoint control, or prove possession, retention, independent custody or model
quality. It implements no DHT, DNS lookup, recursive referral or reverse probe.

The existing configured-peer Cell protocol and commands retain their existing
behavior. The explicit API and separate `trnm-cell-discovery` executable do not
silently replace configured peers. The persistent directory profile currently
requires Unix file identity and locking. Other platforms return the explicit
`CellErrorV1::Invalid("discovery file identity unsupported")` result before
opening or creating a path; pure record encoding is portable but this is not a
cross-platform directory-service claim. The sole project plan remains
[the development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Code and APIs

- [Record codec and address policy](../../../../trillionnium/crates/trnm-data-availability/src/cell/discovery.rs)
- [Persistent directory](../../../../trillionnium/crates/trnm-data-availability/src/cell/discovery/directory.rs)
- [TCP discovery and shared Cell session](../../../../trillionnium/crates/trnm-data-availability/src/cell/discovery/transport.rs)
- [Native negative and TCP tests](../../../../trillionnium/crates/trnm-data-availability/src/cell/discovery/tests.rs)
- [Independent encoding vector](../../../../trillionnium/crates/trnm-data-availability/src/cell/discovery/vectors.rs)

`CellProviderRecordV1::sign` accepts an Ed25519 signing key and a complete
statement. `announce_cell_provider` sends one pre-signed record to one explicit
bootstrap. `serve_cell_rendezvous` serves a finite invocation over a caller-owned
TCP listener. `fetch_discovered_cell_to_file` takes an existing Cell cache, a
separate replay directory, a pinned request, explicit bootstrap addresses and
address policy, the original Cell limits, the caller's original absolute
deadline, and a create-only output path.

Only actual bootstrap TCP responses populate the provider list. The client's
local directory preserves replay high water and checks local integrity; cached
advertisements cannot supply candidates when the bootstraps are unavailable.
During one operation, signed responses are collected by `(manifest, owner)`
and reduced to the highest observed sequence before deriving endpoints. A
verified same-sequence conflict removes that identity for the operation.
The operation keeps at most 64 `(owner, sequence) -> exact record digest`
observations, within the unchanged validation-slot cap, before the persistent
high-water comparison. Thus observing A at sequence 1, C at sequence 2, and
then a conflicting B at sequence 1 still disqualifies the owner; the final
historical record cannot hide its conflict behind a lower-sequence rejection.
These records are local to the operation, are not evicted, and grant no new
signature/network/CPU-time reservation.
Collection still queries every bootstrap in the current bounded round, even
if an earlier response temporarily named eight endpoints. At the end, the
exact observed records must still match the directory's current high-water
snapshot; locally newer records cannot be imported into the provider pool.
The returned list has at most eight distinct endpoints. These are snapshot
observations, not a transaction held across subsequent network operations.

Every resulting manifest is checked against the pinned manifest digest and
the independently pinned Cell context before output publication. Existing Cell
chunk checks and the full ordered payload hash remain required.

## Exact signed record

All integers use unsigned big-endian encoding. A record has exactly 335 bytes;
extra bytes, alternate IP encodings and malformed lengths are rejected.

| Byte offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | `CDP1` |
| 4 | 32 | Operator-selected, nonzero development namespace |
| 36 | 32 | Pinned network digest |
| 68 | 32 | Pinned parameter digest |
| 100 | 32 | Pinned genesis digest |
| 132 | 32 | Pinned Cell context digest |
| 164 | 32 | Pinned Cell manifest digest |
| 196 | 32 | Advertising owner's Ed25519 public key |
| 228 | 19 | IP family byte, 16 address bytes, two-byte port |
| 247 | 8 | Nonzero sequence number |
| 255 | 8 | Issued Unix seconds |
| 263 | 8 | Expiry Unix seconds |
| 271 | 64 | Ed25519 signature |

IPv4 uses family `4` and twelve zero padding bytes followed by the four address
octets. IPv6 uses family `6`, zero scope/flow identifiers, and no IPv4-mapped
encoding. A zero port is invalid. The signature message is SHA-256 of
`trnm.cell-provider-discovery.dev.v1\0` followed by the first 271 bytes.
Canonical public-key and signature-R encodings are required in addition to the
existing M09 strict Ed25519 verification, including its weak-key rejection.

The Cell context digest uses SHA-256 over
`trnm.cell-discovery-context.dev.v1\0`, the one-byte family length, family bytes,
then the exact base, parent, tokenizer, layout and runtime digests in their
existing manifest order. The expected context and manifest come from the
caller; a peer cannot select them through a response.

Lifetime is 1–300 seconds. Issued time may be at most five seconds ahead of the
observed local wall clock; expiry must be strictly later than that clock. The
client fixes a conservative monotonic expiry when each record is received.
Equal-record retries cannot renew that lease. A higher sequence replaces both
the endpoint and expiry; superseded records cannot lengthen or shorten the
final selection. At final selection, current live records are checked again.
For multiple distinct owners advertising the same endpoint, the endpoint may
use the latest expiry among those independently current, actually observed
records: one still-live location hint suffices. The operation then uses the
earliest selected endpoint expiry to shorten its original deadline.
Wall time is not a trusted external clock. A persisted local clock floor rejects
backwards observations; forward jumps or clock rollback can stop service until
the operator resolves the cause. There is no automatic floor/namespace reset.

## Wire exchange and fixed resources

The new request frame is `CDQ1`, a one-byte operation, a two-byte body length,
then the body. Lookup operation `1` has the exact 192-byte pinned request;
publication operation `2` has one exact 335-byte record. The response is `CDS1`,
a one-byte status, a four-byte body length and the body. Status `0` is success,
`1` is rejection and `2` is directory capacity rejection. A lookup body has a
one-byte count followed by at most eight records. A publication ACK is the
32-byte SHA-256 digest of the exact record after durable directory readback.
That ACK proves no Cell service or financial effect.

| Resource | Hard software limit in this profile |
| --- | ---: |
| Explicit bootstrap endpoints | 4 |
| Discovery connection attempts per operation | 8, at most two bounded rounds |
| Records per lookup response | 8 |
| Record-validation slots per discovery | 64 |
| Distinct discovered provider endpoints | 8 |
| Actual discovery response bytes read | 32 KiB |
| Server invocation connections / record-validation slots | 64 / 64 |
| Server request body / response body | 335 / 2,681 bytes |
| Server lifetime | At most 3,600 seconds |
| Address-policy CIDRs / service ports | 8 / 16 |

A validation slot covers at most one strict signature verification and is also
charged when a record fails a cheaper check. It is not a CPU-time measurement.
The caller's original `requests_left` counter and `ResponseBudget` are shared
by discovery, manifest retrieval, chunk retrieval and retries. Discovery does
not create a second Cell deadline or replenish connections or response bytes.
The aggregate fetch report already includes discovery totals; the discovery
subreport must not be added again. `manifest_initial_cache_hit` records the first
actual manifest-cache read before downloading/persisting it. Rejections during
that first manifest fetch are carried into the aggregate exactly once, even
though the common Cell fetch subsequently rechecks the now-present cache.
Counts cover application response bytes
actually read, including rejected headers and bodies; request bytes, TCP/IP
overhead, retransmissions and unread socket data are outside this metric.

### PN5 extension seam — target, not the dev-v1 codec

Public swarm discovery belongs to existing PN5/I09 after the PN3 configured-peer
loader and PN4 funded-duty gates. The current 335-byte record, signed domains,
directory high water and fixed resource limits remain unchanged. A selected DHT
or BitTorrent v2 adapter needs its own reviewed versioned codec and exact vectors;
it cannot reinterpret CDP1, TCM1 or TCR1 fields or silently widen address scope.

| Target input/output | Required binding and result |
| --- | --- |
| `DiscoverProvidersRequest` | Original operation, pinned closure/object ID and context, public/private export profile, allowed bootstraps/scopes, remaining connection/byte/validation/CPU reservation and original deadline. |
| `DiscoverProvidersResult` | Same identity, finite candidate records with expiry/provenance, exact consumed counters and `Candidates`, `Unavailable`, `Refused` or `Unknown`. Candidates remain untrusted location hints until actual pinned bytes verify. |
| `ProviderObservation` | Actual dial/result, verified object/chunks, observed duration/bytes and failure category. A successful probe is neither a storage lease nor operator-independence evidence. |

Target errors distinguish invalid identity/codec, stale/conflicting record,
disallowed scope, capacity, budget/deadline exhaustion and unresolved publication.
Unknown announce outcomes reconcile the exact signed record and sequence; a lost
ACK does not authorize a new sequence, payment, retry effect or fresh allowance.
Fetch may retain verified bytes, but re-entry needs current authorization and the
explicit remaining reservation. Lookup, dialing, repair and model retrieval share
that reservation instead of each creating their own queue or timeout.

For any external infohash/CID, the adapter must commit to the algorithm, codec,
canonical metainfo/DAG bytes and mapping to the pinned release/object IDs. Specify
whether a mapping names a TCM1 wire object, raw payload or complete release;
these have different hashes. Test a valid external hash for the wrong internal
object, alternate codecs, mutable tags, malformed magnets and truncated proofs.
No successful external lookup bypasses the original manifest/context checks.

The PN5 freeze record names at least three independent administrators and failure
domains, bootstrap diversity, topology, TTLs, query/hop/parallel limits, ingress/
egress and queue caps, object workload and the honest completion deadline. Run
at least 72 hours, retaining each cold/warm and fault cohort separately. Required
faults include all-bootstrap loss, eclipse/provider spam, same-owner equivocation,
expired records, clock jumps, slow/corrupt providers, restart and flash crowd.
Pass requires zero pin changes, unauthorized private advertisements, budget resets
or duplicate aggregate counting, plus honest complete-release service inside
the precommitted limits for cohorts with the declared surviving discovery and
provider paths. Total discovery/object loss must return typed Unavailable by
the original deadline without a version or authority fallback; count that as
an availability failure, not successful service. Finite safe refusal alone
does not qualify fairness, and aggregate success cannot hide failed cohorts.
Private manifests reveal model topology and interest even when payloads are
encrypted. The export owner must explicitly choose an authenticated private
discovery profile; unknown/private objects never spill into public lookups.

`LoopbackDevOnly` is an explicit development choice with finite ports.
`ScopedDeployment` requires explicit canonical nonzero-prefix CIDRs and finite
service ports. It rejects loopback, unspecified, link-local, multicast,
broadcast and IPv4-mapped destinations. Private addresses require an explicit
matching deployment CIDR. There is no implicit Internet/private-network scope,
hostname resolution, redirect handling or traversal of peer-supplied referrals.

Deadlines are cooperative checks around network and storage operations. SQLite
has a 100 ms busy timeout; a blocking SQLite, filesystem or kernel call cannot
be preempted by this API. Checks before/after storage and before response/output
publication preserve the declared deadline as an admission condition without
claiming a hard kernel execution-time bound.

## Persistent replay directory

The directory is a separate fresh SQLite namespace, application ID `0x43445031`
and schema version `1`, with an operator-pinned 128-byte deployment context.
There is no implicit schema migration. An exclusive file lock, no-follow open,
regular-file/device/inode/link checks, and live full-schema/context checks
reject the tested stable path replacement and unexpected schema changes.

Keys are `(namespace, manifest, advertising owner)`. Each key permanently keeps
its highest sequence, exact signed bytes and digest, plus its first observed
source IP and source prefix. A lower sequence or same-sequence changed record
is rejected. Equal sequence and exact bytes are idempotent. A higher sequence
may update the endpoint/times while the complete pinned request stays fixed.
The source is the actual accepted publication socket, or the actual queried
bootstrap on a client; it is never an advertising claim.

| Permanent directory allocation | Limit |
| --- | ---: |
| Total identities | 512 |
| Per advertising owner | 16 |
| Per manifest | 16 |
| Per first observed source IP | 64 |
| Per first observed source /24 IPv4 or /64 IPv6 prefix | 128 |

Expiry removes an advertisement's eligibility for return/dial, but does not
delete the high-water identity or release any quota. Capacity rejects new keys
explicitly; existing keys can update without evicting another identity.
NAT, one shared bootstrap, or Sybil keys can exhaust these finite allocations.
This is bounded failure, not an open-network fairness or Sybil-resistance proof.

Short immediate transactions contain no network operation. Publication checks
actual affected rows, old-sequence/digest CAS, metadata clock/revision CAS,
exact in-transaction row readback, and a new post-COMMIT read snapshot before
ACK. Lookup also validates complete stored key/sequence/digest/source-prefix
relations and rechecks the selected rows after commit. A valid old signed wire
cannot silently replace a newer wire while leaving newer high-water columns.
The in-memory observed revision advances only after successful committed
readback. Failed post-COMMIT checks do not roll back durable high water.

The owner uses FULL synchronous mode, DELETE journaling and at most 4,096 main
database pages of 4,096 bytes (16 MiB). `usage()` reports identity count, retained
wire bytes, current main-DB page bytes and that main-DB maximum. This is not a
total disk reservation or RSS limit: rollback journals, filesystem metadata,
SQLite/cache allocations, transient query/signature buffers and networking
buffers are outside that figure. Fixed rows and small frames do not imply a
physical WAL, process memory or kernel-storage bound.

These local checks do not resist a malicious host rewriting a complete valid
row/database, restoring the entire database/clock together, or racing a path
from A to B and back around filesystem observations. In particular, SQLite
opens the path separately from the retained, locked `File`: a same-privilege
host can swap A for B during SQLite open and restore A before the next check,
leaving SQLite connected to B while the path checks see A. The retained File is
not an attestation of SQLite's actual descriptor. Deployment therefore assumes
an attacker cannot rewrite the hosting filesystem namespace. The directory is
neither a chain-locked budget nor a trusted anti-rollback hardware journal.

## Explicit command-line entry point

The independent [trnm-cell-discovery executable](../../../../trillionnium/crates/trnm-data-availability/src/bin/trnm-cell-discovery.rs)
has seven opt-in commands. Every operation requires
`--profile cell-provider-discovery-dev-v1`; none reads a default network,
directory, key, peer list or budget. The existing `trnm-cell` commands, including
their `--seconds` / `--overall-ms` handling, are unchanged.

| Command | Result |
| --- | --- |
| `init` | Open or create the explicit fresh directory and report its allocation bounds |
| `key-public` | Read a selected private seed file and print only its Ed25519 public key |
| `context-digest` | Hash a complete, explicit existing Cell context |
| `sign` | Create, without overwriting, one exact 335-byte signed public advertisement |
| `announce` | Check every explicit owner/context/manifest pin, then publish that exact record to one scoped bootstrap |
| `serve` | Bind an explicit listener and run the existing finite rendezvous service |
| `fetch` | Learn candidates from actual bootstrap responses, verify all Cell bytes, and create the complete local output |

`key-public` and `sign` read exactly 32 raw seed bytes from a regular file opened
with no-follow and nonblocking flags. Group/other permissions and multiple hard
links are rejected; the file must be mode `0600` or stricter and contain no
trailing byte. The CLI accepts no seed through command-line text or environment
variables and never prints seed bytes. These local checks are not a key vault
or a defense against a privileged host, same-owner file mutation or memory
inspection. The owner public key is an advertisement signer, not a chain funds
owner or proof of service.

Network commands require numeric addresses and one explicit address policy:
`--scope loopback-dev --ports ...`, or `--scope scoped --cidrs ... --ports ...`.
The server's `--bind` is separately explicit; `127.0.0.1:0` requests an ephemeral
listener and the first flushed JSON record reports its actual address. It does
not grant permission to advertise or dial every port. Client lists must include
the actual bootstrap and provider service ports in their declared scope.

Client `--request-ms`, `--max-bytes`, `--parallelism`, `--max-connections` and
`--max-response-bytes` are all mandatory. Exactly one of `--seconds` and
`--overall-ms` supplies the original duration. `announce` and `fetch` sample
one `Instant` before argument/file/database preparation and pass that original
absolute deadline to the library. `fetch` calls the existing shared session
once; discovery cannot start a second connection/byte allowance or extend
the deadline. The server's separately declared duration is its finite service
lifetime. Cooperative filesystem/SQLite limits described above still apply.

The fetch JSON record reports aggregate `connection_attempts` and
`received_response_bytes`, plus a separate `discovery` breakdown. The aggregate
already includes that breakdown: adding them would double count. The
`manifest_initial_cache_hit` field comes from the first actual cache read.
`suppliers` and `discovered_providers` are numeric endpoint arrays; neither
represents a count of independent operators. All custody/payment/use authority
fields remain false.

### Minimal local workflow

The following is a same-host development example. Use a new directory, choose
unused loopback ports, and supply the real pinned digests for any deployment.
The repeated-byte digests below deliberately describe a synthetic namespace;
the example does not establish independent custody or WAN availability.

```bash
bash scripts/project-preflight.sh
CARGO_BUILD_JOBS=6 cargo build --manifest-path trillionnium/Cargo.toml --locked \
  -p trnm-data-availability --bin trnm-cell --bin trnm-cell-discovery

PN5_BIN_DIR="${CARGO_TARGET_DIR:-trillionnium/target}/debug"
PN5_DIR=$(mktemp -d)
PN5_PROFILE=cell-provider-discovery-dev-v1
python3 - "$PN5_DIR" <<'PY'
import os, secrets, sys
from pathlib import Path
p = Path(sys.argv[1])
fd = os.open(p / 'advertising.seed', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(fd, 'wb') as f:
    f.write(secrets.token_bytes(32))
    f.flush()
    os.fsync(f.fileno())
(p / 'namespace').write_text(secrets.token_hex(32))
(p / 'input.cell').write_bytes(bytes(range(256)) * 128)
PY
PN5_NAMESPACE=$(cat "$PN5_DIR/namespace")
PN5_NETWORK=$(printf '01%.0s' {1..32})
PN5_PARAMETERS=$(printf '02%.0s' {1..32})
PN5_GENESIS=$(printf '03%.0s' {1..32})
PN5_BASE=$(printf '04%.0s' {1..32})
PN5_PARENT=$(printf '05%.0s' {1..32})
PN5_TOKENIZER=$(printf '06%.0s' {1..32})
PN5_LAYOUT=$(printf '07%.0s' {1..32})
PN5_RUNTIME=$(printf '08%.0s' {1..32})
PN5_CONTEXT=(--namespace "$PN5_NAMESPACE" --network "$PN5_NETWORK"
  --parameters "$PN5_PARAMETERS" --genesis "$PN5_GENESIS")
PN5_CELL_CONTEXT=(--family pn5-cli-demo-v1 --base "$PN5_BASE" --parent "$PN5_PARENT"
  --tokenizer "$PN5_TOKENIZER" --layout "$PN5_LAYOUT" --runtime "$PN5_RUNTIME")
PN5_SCOPE=(--scope loopback-dev --ports 47810,47811)
PN5_LIMITS=(--overall-ms 10000 --request-ms 2000 --max-bytes 1048576
  --parallelism 2 --max-connections 64 --max-response-bytes 4194304)
PN5_CACHE=(--cache-max-bytes 1073741824 --cache-max-chunks 4096 --cache-max-manifests 256 --cache-max-db-bytes 2147483648)
"$PN5_BIN_DIR/trnm-cell" pack --store "$PN5_DIR/origin.sqlite" \
  "${PN5_CACHE[@]}" --input "$PN5_DIR/input.cell" "${PN5_CELL_CONTEXT[@]}" > "$PN5_DIR/pack.json"
"$PN5_BIN_DIR/trnm-cell-discovery" key-public --profile "$PN5_PROFILE" \
  --secret-key-file "$PN5_DIR/advertising.seed" > "$PN5_DIR/owner.json"
"$PN5_BIN_DIR/trnm-cell-discovery" context-digest --profile "$PN5_PROFILE" \
  "${PN5_CELL_CONTEXT[@]}" > "$PN5_DIR/context.json"
PN5_MANIFEST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["manifest"])' "$PN5_DIR/pack.json")
PN5_OWNER=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["owner"])' "$PN5_DIR/owner.json")
PN5_CELL_DIGEST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["cell_context"])' "$PN5_DIR/context.json")
"$PN5_BIN_DIR/trnm-cell-discovery" init --profile "$PN5_PROFILE" \
  "${PN5_CONTEXT[@]}" --directory "$PN5_DIR/rendezvous.sqlite"
```

Start the two finite servers in the same shell. Before continuing, inspect
their flushed listen records and confirm both processes have the intended
addresses. Keep the original shell variables; they contain no private seed.

```bash
"$PN5_BIN_DIR/trnm-cell" serve --store "$PN5_DIR/origin.sqlite" \
  --bind 127.0.0.1:47810 --seconds 120 --request-ms 2000 --max-connections 64 \
  > "$PN5_DIR/cell-server.jsonl" &
PN5_CELL_PID=$!
"$PN5_BIN_DIR/trnm-cell-discovery" serve --profile "$PN5_PROFILE" \
  "${PN5_CONTEXT[@]}" "${PN5_SCOPE[@]}" --directory "$PN5_DIR/rendezvous.sqlite" \
  --bind 127.0.0.1:47811 --seconds 120 --request-ms 2000 --max-connections 64 \
  > "$PN5_DIR/rendezvous-server.jsonl" &
PN5_RENDEZVOUS_PID=$!
```

Sign and publish only after the finite servers are ready. No provider is
passed to `fetch`; its sole selection list is the rendezvous bootstrap.

```bash
PN5_ISSUED=$(date +%s)
PN5_EXPIRES=$((PN5_ISSUED + 60))
"$PN5_BIN_DIR/trnm-cell-discovery" sign --profile "$PN5_PROFILE" \
  "${PN5_CONTEXT[@]}" --secret-key-file "$PN5_DIR/advertising.seed" \
  --owner "$PN5_OWNER" --manifest "$PN5_MANIFEST" --cell-context "$PN5_CELL_DIGEST" \
  --endpoint 127.0.0.1:47810 --sequence 1 --issued-unix-seconds "$PN5_ISSUED" \
  --expires-unix-seconds "$PN5_EXPIRES" --record-output "$PN5_DIR/provider.cdp1"
"$PN5_BIN_DIR/trnm-cell-discovery" announce --profile "$PN5_PROFILE" \
  "${PN5_CONTEXT[@]}" "${PN5_SCOPE[@]}" "${PN5_LIMITS[@]}" \
  --record "$PN5_DIR/provider.cdp1" --owner "$PN5_OWNER" \
  --manifest "$PN5_MANIFEST" --cell-context "$PN5_CELL_DIGEST" --bootstrap 127.0.0.1:47811
"$PN5_BIN_DIR/trnm-cell-discovery" fetch --profile "$PN5_PROFILE" \
  "${PN5_CONTEXT[@]}" "${PN5_SCOPE[@]}" "${PN5_LIMITS[@]}" "${PN5_CACHE[@]}" \
  --directory "$PN5_DIR/consumer-directory.sqlite" --store "$PN5_DIR/consumer-cache.sqlite" \
  --manifest "$PN5_MANIFEST" --cell-context "$PN5_CELL_DIGEST" \
  --bootstraps 127.0.0.1:47811 --output "$PN5_DIR/complete.cell"
cmp "$PN5_DIR/input.cell" "$PN5_DIR/complete.cell"
sha256sum "$PN5_DIR/input.cell" "$PN5_DIR/complete.cell"
```

The servers exit at their original lifetime/connection limits. An expired
advertisement requires a new explicitly signed record with a higher sequence;
neither retrying the same file nor reopening a directory renews it. Existing
output and record files are never overwritten. The
[CLI integration tests](../../../../trillionnium/crates/trnm-data-availability/tests/cell_discovery_cli.rs)
exercise actual finite child processes and Cell TCP bytes, including exact
aggregate counters, private-file failures and pins that must fail before dial.

## Evidence boundary

The native test source covers real TCP announcements and bootstrap-only
discovery of three previously unconfigured providers, an unavailable bootstrap,
origin exit, a corrupt replica/cache chunk, full-payload repair, shared original
connection/actual-byte budgets, replay after restart/expiry, permanent full
capacity, record/context/signature mutations, strict address scopes, old-wire
SQL rewind, schema/namespace/path faults, partial/oversized responses,
slowloris deadlines, and all 64 validation slots across eight attempts.
The exact signed vector was generated independently with Python Ed25519.

Source inclusion and a passing local test suite do not establish independent
WAN availability, the PN5 72-hour gate, custody diversity, open Sybil fairness,
model-version availability, economic retention, model efficacy or production
readiness. Actual native test/campaign artifacts belong in the sole plan when
the owner has executed and reviewed them; this specification does not mark
those gates passed.
