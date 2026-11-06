# Native PQ TLS loopback owner v1

Status: source candidate, native gates pending. This is an explicit development
listener in the ordinary Unix `trnm-pon-node` binary. It does not activate production,
enable consensus authority, retrofit the public-history reactor, or qualify
private tasks, WAN service, independent PKI/custody, or quantum PoN cost.

## Actual entry and immutable configuration

Build the existing `pq-native-openssl` feature. The existing exact dependency is
`openssl = 0.10.81`; no Cargo dependency/version or feature is added by this leaf.
The loaded OpenSSL must support TLS 1.3, ML-DSA-65 and X25519MLKEM768. Unsupported
group/signature configuration fails; there is no alternative provider/profile
or classical retry. The default binary explicitly refuses this command.

The pending exact-source native qualification uses the existing pinned OpenSSL
3.5.9 build with static linking, Rust 1.95.0, two Cargo build jobs and one test
thread, as in the retained native lane. The host's system OpenSSL version is
not evidence of the linked provider. The new binary and its source/linkage
receipt must be checked again before any result is accepted.

The ordinary entry is:

```sh
trnm-pon-node pq-tls-serve --development \
  --store /absolute/new-node \
  --listen 127.0.0.1:9000 --seconds 30 --workers 1 \
  --tls-config /absolute/config.json --tls-config-sha256 EXTERNAL_SHA256 \
  --tls-cert /absolute/server.pem --tls-key /absolute/server-key.pem \
  --tls-ca /absolute/ca.pem
```

`EXTERNAL_SHA256` commits the exact configuration bytes; it is supplied by the
operator rather than computed from the same untrusted input as a new trust root.
The JSON object rejects unknown fields and contains:

| Field | Meaning |
| --- | --- |
| `schema` | `native-pq-tls-loopback-config-v1` |
| `genesis_time` | Explicit development genesis Unix seconds |
| `network`, `parameters`, `genesis` | Canonical SHA-256 hex, checked against those actual development settings |
| `generation` | Positive bounded owner generation |
| `server_spki`, `peer_spkis` | Strict canonical ML-DSA-65 DER SPKI in lowercase hex; distinct keys, original 64-peer maximum |
| `ca_certificate_sha256` | Exact externally pinned CA certificate DER SHA-256 hex |
| `server_name` | Explicit lower-case DNS name, checked against the server SAN with no wildcard or CN fallback |

The config, certificate, CA and key are read from one bounded regular descriptor
with `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`, one link and root/current-UID ownership.
Public inputs cannot be group/world writable; the key cannot grant group/world
access. Secret buffers are zeroized. The key must match the certificate and the
configured native signer. The direct CA, leaf public keys and certificate
signatures use ML-DSA-65; merely enabling ML-KEM does not authenticate a peer.

All configuration checks precede Node open and listener binding. The code path is
`main::run → pq_tls_cli::run → Node::open_with_pq_network → serve_pq_tls13 →`
the original bounded request reader, native verifier, replay ledger, work checks,
Node execution and durable signed receipt. The ordinary CLI integration test
launches this binary and admits a real block, then reopens the actual Node store.

## Protocol and replay boundary

The new policy is `native-pq-network-tls13-owner-v1`. It has new canonical owner
bytes, policy/context/operation/response digest domains, `PQT1`/`PQS1` framing and
a separate signed response schema. The TPQ1 signature/encoding contract itself
is unchanged. Original PNQ2 bytes and domains remain unchanged.

The underlying audited SQL layout is reused, but its immutable owner policy is
incompatible: an existing plaintext store cannot be reopened with this TLS
policy or vice versa. No row, revocation, sequence, cached receipt or old grant
is silently migrated. The original plaintext `send`, `serve` and direct server
handler refuse a TLS-required policy before socket handling/admission.

Each connection uses TLS 1.3 with the single group `X25519MLKEM768`, the single
TLS signature algorithm `mldsa65`, and `TLS_AES_256_GCM_SHA384`. Client and server
certificates are mandatory, use the configured direct CA, and match the native
SPKI pins. After authenticating a request, the server also requires its signer
to equal the TLS peer. TLS session caching, tickets, early data and renegotiation
are disabled; a reported reused session is refused.

rust-openssl 0.10.81 does not expose a safe negotiated-group getter. The group
claim here is explicitly an inference from a private immutable context whose
only allowed group is X25519MLKEM768. Cipher identity is not group evidence.
Independent wire/interop observation remains a separate native gate.

The per-connection TLS state does not enter the durable operation ID. Retrying
the same signed request through a fresh valid TLS connection therefore returns
the original signed receipt, without repeating its effect. TLS does not satisfy
the original PoN work relation or replace the TPQ1 signature/revocation checks.

## Deadline and resource ownership

The original application frame limit remains 2 MiB, with the original signed
payload limit, 16 MiB operation ledger, 4096 retained records, 32 MiB durable
ingress bytes and 64 native TPQ signature attempts. Connections still use one
absolute deadline of at most 10 seconds, including handshake, owner queueing,
read/write, verification, work and execution. Every socket BIO call receives the
remaining portion of that same deadline; handshake completion does not reset it.

The fresh TLS policy additionally limits durable handshake attempts to 16. In
this namespace each accepted connection spends one attempt in the original
durable connection counter **before** reading TLS input. The cap is in the same
SQL mutation, bound into the canonical policy, checked on reopen and never
refunded for failure. Original plaintext owners retain their 64-connection cap.

TLS ciphertext is limited separately in each direction: 64 KiB during the
handshake and 4 MiB over the whole connection, including that handshake. The
combined send-plus-receive ceilings are therefore 128 KiB and 8 MiB. Only received
ciphertext spends the original 32 MiB ingress allowance, before OpenSSL receives
it. The existing declared application-body charge remains, so encrypted body
bytes are conservatively charged again. Application limits and global inbound
allowances are not enlarged.

Handshake attempts are **not** a count or upper bound of OpenSSL's certificate
signature operations. Invalid or same-subject candidate chains can cause
multiple internal checks. The native TPQ attempt counter is not reused for that
work. Standard certificate verification remains enabled. OpenSSL synchronous
cryptography is not preemptible; deadline checks reject late dispatch/ACK but do
not establish a wall-clock CPU execution bound. Public saturation/CPU cost and
external certificate ecosystem qualification remain open.

## Native acceptance required on the frozen source

The required cases include actual Node block admission and lost-ACK retry, exact
cached receipt after cold reopen, old plaintext/store refusal, TLS-peer versus
inner-signer mismatch, CA/SAN/SPKI refusal, TLS 1.2/classical group/missing-cert
refusal, malformed chains, durable handshake exhaustion across cold reopen,
an actual receive TCP/BIO refusal of byte 65,537 before OpenSSL with exact durable debit,
original deadline, real work/signature failures, ordinary binary dispatch and
configuration/feature/nonloopback refusal. The malformed-chain case's constructed
DER length alone does not prove how many bytes OpenSSL sent. These are source obligations until
the exact committed source executes them under the original native runner.

All retained PNQ2 tests and full default/feature graphs remain required. A green
loopback fixture does not provide an independently held CA, a private-task
consumer, public-history TLS integration, WAN availability or QROM/quantum work
security evidence. Public Head/History remains its existing explicitly public,
signed, no-confidentiality profile. Production and consensus activation flags
remain false.
