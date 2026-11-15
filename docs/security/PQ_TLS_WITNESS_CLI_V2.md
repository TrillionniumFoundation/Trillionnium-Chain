# Explicit TLS CLI selection of the PNQ2 witness

Status: research implementation; native qualification and independent deployment
remain separate requirements. Production activation and consensus authority stay
false. This entry uses the existing development, loopback-only TLS profile.

The ordinary `trnm-pon-node pq-tls-serve` command accepts an explicit
`native-pq-tls-loopback-config-v2` configuration. It selects the existing
`PqWitnessV4` Node constructors instead of the legacy configuration's
`PqNetworkV2` constructor. The CLI creates no witness service or registration.
The [witness contract](PQ_NETWORK_DURABLE_WITNESS_V1.md) continues to define the
protected state and the required independent retention premise.

## Configuration and protected inputs

The command retains the existing TLS flags, configuration SHA-256 pin, development
requirement and loopback address restriction. V2 also requires
`--witness-writer-key PATH`, naming the private ML-DSA-65 writer PEM. The pinned
JSON retains all V1 TLS and network fields and adds this required `witness` object:

| Field | Required value |
| --- | --- |
| `generation` | A nonzero witness generation accepted by `WitnessBinding` |
| `witness_spki` | Lowercase hexadecimal canonical ML-DSA-65 SPKI of the independently retained witness |
| `writer_spki` | Lowercase hexadecimal canonical ML-DSA-65 SPKI matching the supplied private writer key |
| `socket` | An absolute Unix socket path for the existing service |
| `node_mode` | Exactly `create` or `open_existing` |

The binding commits the complete canonical TLS PNQ2 policy, witness generation
and both witness identities. The existing binding rejects equal witness and
writer identities. The TLS server's private key and the witness writer's private
key are supplied through separate flags; this interface adds no further rule
requiring those two keys to differ.

The existing input reader inspects one opened descriptor, refuses symbolic links
and nonregular files, requires a root- or effective-user-owned single-link file,
and bounds the read. Public configuration and certificate files must not be
group- or world-writable. Each private PEM must deny group/world permissions.
Configuration is limited to 262,144 bytes; each certificate or private key input
is limited to 32,768 bytes. Parse and identity errors do not include secret bytes.

V1 remains `native-pq-tls-loopback-config-v1` and selects its original backend.
V1 rejects a witness object, a present `null` witness and the new writer-key flag.
V2 rejects a missing or null witness, a missing writer-key flag, unknown fields,
unknown modes, noncanonical SPKIs and a private key that fails the pinned writer
identity. No input chooses a classical or older backend after a V2 refusal.

For example, with an already provisioned service and a fully pinned V2 file:

```sh
trnm-pon-node pq-tls-serve --development \
  --store "$NODE_DIRECTORY" --listen 127.0.0.1:0 --seconds 30 \
  --tls-config "$TLS_CONFIG" --tls-config-sha256 "$TLS_CONFIG_SHA256" \
  --tls-cert "$TLS_CERTIFICATE" --tls-key "$TLS_PRIVATE_KEY" \
  --tls-ca "$TLS_CA_CERTIFICATE" --witness-writer-key "$WITNESS_WRITER_KEY"
```

The hashes, keys, socket and directory in this example are operator inputs. The
command does not discover, generate, enroll or authorize them.

## Creation, reopen and bounded connection

`create` invokes `Node::create_with_pq_witness` and refuses an existing
`native.sqlite`. `open_existing` invokes `Node::open_with_pq_witness` and refuses
a missing database. Neither mode is inferred from a directory, missing file,
failed Current reply or failed prior attempt. These retain the constructors'
existing filesystem semantics; they do not promise atomic protection against
arbitrary concurrent mutation by another process with the same filesystem owner.

Local schema, TLS identity, witness binding and private-writer validation precede
Node construction. Unix socket creation uses nonblocking and close-on-exec flags;
on Apple those flags are set with safe `fcntl` calls before connecting. The
single connection attempt checks the original 250 ms exchange deadline before
and after `connect`. An unavailable endpoint, full backlog or in-progress result
fails immediately without a blocking connect, connection thread or automatic
retry. This is a bound on connection I/O, not a preemptive CPU bound on earlier
cryptographic preparation.

After connection, the original authenticated Current/CAS protocol and its
exchange limits apply. The selected Node validates its PNQ2 ledger against the
independent witness before listener readiness. Failure may leave the original
constructor's partial local state for explicit recovery; it grants no readiness
or permission to reset, reopen under an older namespace, or retry an uncertain
effect. The CLI never initializes or repairs the external witness registration.

## Authority carried to the real Node

The TLS listener still handles the original PNQ2 request, verifier, replay,
resource, dispatch and reply paths. TLS authentication does not replace the inner
signer checks, task authority, native work checks or the durable request owner.
The TLS version, configured hybrid group, certificate/CA/hostname/SPKI checks,
no-resumption policy and original connection limits are unchanged from
[the TLS profile](NATIVE_PQ_TLS_LOOPBACK_V1.md).

The selected witness protects exactly the PNQ2 resource, peer and request tables.
It does not protect account state, blocks, History, Cell storage, M15 publication,
CURRENT selection, governance, Hepta owners or the complete Node directory.
Readiness reports `pnq2_rollback_witness_selected: true` for V2 and always reports
`whole_node_rollback_protection: false`. Current is an observation, not an
exclusive writer lease. Lost CAS acknowledgement remains an uncertain effect;
the existing recovery rules do not authorize replay, refund or witness reset.

## Required observations and remaining boundaries

The separate [required-test manifest](../../config/pon/pq-native-tls-witness-required-tests-v1.json)
names five integration cases that launch the actual ordinary binary. They cover:

1. Dispatch, exact replay, process reopen and restoration of an older complete
   Node directory while retaining the live independent witness database.
2. Schema, identity and private-file refusals before owner creation or witness I/O.
3. Explicit create/open behavior and refusal of legacy TLS/classical downgrade.
4. Absent and full-backlog Unix endpoints without owner creation or readiness.
5. A reachable authenticated service with the wrong complete witness binding.

These declarations do not constitute executed tests. Qualification requires the
fresh registry and actual results on the final source and binaries, alongside
the unchanged TLS 13 library, four ordinary CLI and one feature-off controls.
The original full Chain gates, limits and source checks remain required.

The independent witness daemon, protected writer/service custody, provisioned
initial state and recovery checkpoints still need actual deployment evidence.
The fixture's independent database demonstrates only its stated process/storage
boundary. This loopback entry does not qualify private-task confidentiality on
other listeners, public History TLS, WAN interoperability, whole-chain PQ,
quantum work security, production activation or consensus authority. Those
claims remain HOLD / UNQUALIFIED in the
[authority surface audit](PQ_AUTHORITY_SURFACE_AUDIT_20261031.md).
