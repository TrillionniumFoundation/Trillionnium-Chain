# Read-only native PQ authorization inventory

[The detailed review](pq-e642-authorization-inventory.txt) enumerates the account,
network, task, model, DA, settlement, Operator and Hepta authorization owners in
code `e6429b9a226ac43682f11ecb5f760ef0243c35a7`. Its
[machine-readable inventory](pq-e642-authorization-inventory.json) preserves the
45 reviewed source/Cargo file hashes and exact evidence boundaries. It is a
source review, not an exhaustive formal call graph or a new native execution.
Documentation/evidence successor `7745eb9777f392dee134878d6346e05914d00bfa` corrects
the wording of newly written but unexecuted negative controls.

The actual QTX1 account profile uses real ML-DSA-65 and the original M06 State,
balances, nonce and fees. Its selected direct account path refuses classical
PNX1. The native transport uses TPQ1 frames and PNQ1/PNP1 request/response bytes;
it does not automatically migrate the underlying account profile. Features are
off by default, and the PQ constructor/listener remains a library API without a
corresponding product CLI start/import path.

Open account creation, key rotation/revocation/recovery, future settlement of
the four retained liability classes, task/DA/Cell/Operator/Hepta authorization,
and public P2P integration remain incomplete. The network implementation is
loopback-only and serial, with bounded persistent replay history. It is neither
a confidentiality protocol nor an independently validated WAN service.

The retained pre-fix cross-import negative control actually failed: a valid
QTX1 was applied in two different genesis/parameter contexts sharing a declared
namespace. The later source derives the signed network from the complete
parameter/import context. Its post-fix native execution has no completed
receipt. Exact e642 workspace Clippy passed; it does not replace that missing
execution. The interrupted qualification and original failures are retained in
the [account evidence](../pon-pq-account-native-20261028/README.md).

A dual signature cannot recover historical ownership after the old classical
key has been compromised. Authentic target PQ mappings must be established
before compromise or supplied through an explicitly trusted migration process;
the code's externally pinned projection cannot manufacture that authenticity.
Whole-work-package and whole-chain PQ acceptance remain false.
