# Fixed-endpoint native PQ TLS development profile

Status: development candidate. Public WAN, production activation, whole-chain
PQ security, independent custody and whole-Node rollback qualification remain
false. The ordinary public V3 reactor, its history poller, Cell transfer and
provider discovery are not routed through this profile.

## Explicit selection and immutable scope

The ordinary `pq-tls-serve` command retains its existing loopback default and
its refusal of non-loopback addresses before configuration-file reads. A new
caller must select both `--development` and
`--tls-network-profile pinned-endpoint-v1`, and pin the complete configuration
with the existing `--tls-config-sha256` argument. The new configuration schema
is `native-pq-tls-pinned-endpoint-config-v1`.

It uses all fields of the existing [witness configuration](PQ_TLS_WITNESS_CLI_V2.md),
requires `witness` and `--witness-writer-key`, and additionally requires:

```json
{
  "endpoint": {
    "server_address": "192.0.2.10:28443",
    "allowed_client_ips": ["192.0.2.20"]
  }
}
```

These documentation addresses are placeholders, not discovered host addresses.
The supplied listen address must exactly equal `server_address`, including the
nonzero port. This first profile permits IPv4 only, with no wildcard, multicast,
limited broadcast, mapped IPv6, DNS substitution or implicit NAT rewriting.
The source-IP roster is sorted, unique and bounded by the original peer limit.
Missing, null, unknown or cross-schema fields cannot select a different profile.
The legacy schemas reject an endpoint field even when it names loopback.

The address roster filters the network scope. The existing pinned CA, server
SAN, ML-DSA SPKI identities and equality of TLS peer and inner PNQ2 signer still
supply authentication. An IP address alone never authorizes a request.

## Distinct cryptographic and storage namespace

The new policy and transport names are
`native-pq-network-tls13-endpoint-owner-v1` and
`pinned-endpoint-tls13-x25519mlkem768-mldsa65-v1`. Policy, peer context, operation,
response digest, request/response magic, response schema and ALPN are distinct
from the original plaintext and loopback TLS profiles. The endpoint and roster
are part of the complete canonical policy, which is already included in the
independent witness binding. No old ledger or witness is automatically enrolled,
upgraded or reinitialized.

The old policy omits the new optional field, preserving its canonical bytes.
Recovery validates the complete schema/transport/endpoint combination rather
than trusting the presence of an endpoint field. Existing local operation,
revocation and witness histories are never rewound with a chain reorganization.

The native algorithms remain TLS 1.3, configured `X25519MLKEM768`, `mldsa65`
and `TLS_AES_256_GCM_SHA384`. The group remains a single-configured-group
inference; this change does not add a negotiated-group observation API.
Session resumption, tickets, early data and renegotiation remain disabled.

## Checks at actual execution boundaries

The CLI validates profile/schema pairing, endpoint and cryptographic inputs
before witness access, Node creation or listener binding. The library checks
the kernel-reported listener address and actual accepted peer IP. The client
refuses a caller-selected wrong endpoint before TCP connection, and checks its
selected local source address before sending a TLS handshake.

Every endpoint policy requires the existing `PqWitnessV4` owner. This is enforced
at Node construction and at live policy validation, so embedding the library
does not bypass the ordinary CLI requirement. Create and open-existing remain
separate operations. Lost witness replies retain the original uncertainty
rules; the caller cannot reset, retry or fall back to another owner implicitly.

The original durable allowance of 16 handshake attempts, ciphertext accounting,
signature charges, packet limits, absolute deadlines and retained results are
unchanged. Invalid source addresses reach no handshake or per-connection Node
mutation. The endpoint listener additionally stops after 64 TCP accepts during
one bounded invocation, including source-IP refusals. This local accept cap is
not a restart-persistent resource allowance or a public denial-of-service claim.

## Verification and remaining work

The [endpoint roster](../../config/pon/pq-native-tls-endpoint-required-tests-v1.json)
adds six library and three ordinary-binary controls. They complement the original
13 library, four CLI, one feature-off and five witness controls. The workflow
requires actual binary registries, exact selectors, source-bound command logs
and independent execution readers; an exit code without a registered executed
test is insufficient.

Coverage includes legacy canonical bytes, all signed namespaces, malformed
recovery records, wrong targets before connection, missing witness in public
library constructors, wrong source IP, the finite accept limit, real mTLS and
signed witness dispatch, exact replay, process reopen, changed policy refusal
and rejection of a restored old Node database against the retained witness.
The ordinary-binary positive case submits an actual block and requests native
history through the existing TLS `Request` owner. It does not exercise the
separate public-history synchronization reactor or peer-polling transport.

A multi-host result must separately identify both exact sources, binaries,
providers, endpoints, public key IDs, request identities, original limits and
raw results. Loopback results do not qualify a LAN run; a LAN run does not
qualify independent WAN operators, PKI or custody. Public V3 and Cell adapters
must preserve their own existing resource, replay, cancellation and recovery
owners before they can be added to confidentiality coverage.
