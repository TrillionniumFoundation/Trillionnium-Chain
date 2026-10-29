# Canonical PNQ2 native network owner: bounded candidate contract

Status: **HOLD / no production activation**. This is an implementation contract
under the existing development plan, not a second roadmap or acceptance report.
The current source and executed validation are recorded separately in
[the V6 reconstruction qualification](../../qualification/full-pq-v6-r2/README.md).
The preceding [PNQ1 contract](PQ_NATIVE_NETWORK_OWNER_V1.md) is historical and
does not describe this candidate's active transport provider or wire.

## Provider and explicit selection

`trnm-crypto-primitives::pq_auth` is available without an optional feature. Its
canonical provider is the exactly pinned RustCrypto `ml-dsa = 0.1.1` dependency,
using pure ML-DSA-65 with empty context, exact 1,974-byte SPKI and 3,309-byte
signature shapes. `pq-native-openssl` remains an optional independent adapter
and differential source. A failed canonical verification never retries another
provider or a classical signature as an acceptance path.

Provider availability does not select a ledger, enable a listener, migrate an
account or activate a chain. An operator must supply the exact protected
Settings, peer SPKI pins and policy to `Node::open_with_pq_network`. That opener
selects the incompatible `PqNetworkV2` database schema. Existing namespace
identity, original recovery rules, local revocation and original Node execution
remain authoritative; changing an incoming prefix cannot select another codec.

## Wire and resource contract

Requests use `PNQ2`, responses use `PNP2`; both carry the exact 3,487-byte TPQ1
signed frame. TPQ1 purpose 6 and direction-specific v2 contexts bind policy,
network, signer, generation, sequence, expiry and payload commitment. The
signature-independent logical operation identity does not create spend or task
authority. Native requests still enter the original work and M06 execution.

| Resource | Exact candidate bound |
| --- | --- |
| Complete signed request/response | 2,097,152 bytes |
| Retained replay ledger | 4,096 records, 16,777,216 charged bytes |
| Admitted connections | 64 cumulative |
| Declared ingress bytes | 33,554,432 cumulative |
| Inbound signature attempts | 64 cumulative; failure does not refund |
| Transport confidentiality | `loopback-signed-plaintext-dev-only` |

Ingress counters are retained in the original SQLite network owner. Body
allocation follows the actual length/budget gate; restart and chain reorganization
do not replenish those counters. These are finite development limits, not a
rate controller, measured CPU ceiling, fee market or indefinite WAN service.
The selected ledger codec is independent: Application V6 requires NPQ6/PQP6;
it cannot accept the optional QTX1 adapter as a substitute.

Paid History's PPH4/PPS4 cookie protocol is a separate explicitly selected
transport path on the original public reactor. Its shared intake authentication
budget and original paid-import CPU/crash epoch must not be described as PNQ2's
SQLite ingress counters. Its settings-selected completion identity continues
through the original complete W1 and M06 owners.

## Retained optional adapter and unclosed combinations

`pq-native-openssl` also exposes the retained PQG1/QTX1 transfer-only account
adapter: 8,192 bytes per transaction, 16 transactions, dual possession and
all-source-record liabilities. That optional profile is neither Application V6
nor a complete account/task/release/installation migration. The corpus retains
its separate `native_account_owner_slice_v1` contract and all acceptance flags
remain false.

The following are not accepted by this contract:

- continuous checkpoint owner plus NPQ6: the protected catalog, non-circular
  bootstrap, TaskV5 lease transition and original Journal initialization need
  one reviewed construction; the existing owner combination remains denied;
- research archive plus PQ application, and classic CLI/public-submit automatic
  parent recovery plus PQ application: explicit rejection is not migration;
- production confidentiality, PQ TLS endpoint identity, public WAN availability,
  physical rollback resistance, quantum-effective PoN hardness or proof-system
  security;
- whole native authorization migration, complete Hepta FinalUse integration,
  independent acceptance or any self-awarded security score.

`scripts/ci/check_pq_research_integration.py` checks exact source blobs, source
coverage, the real Cargo provider declarations and these bounded claims. Its
success still returns `HOLD_NO_GO`; it neither executes cryptography nor upgrades
historical evidence into a newly tested source result. Blob pins must be refreshed
explicitly after reviewed source changes, never silently by the checker.
