# Explicit operator actors development profile

This candidate implements `native-operator-actors-dev-v1` inside existing M05 admission,
M06 configuration/execution and M15 composition. It requires explicit public files and
remains a valueless development network. Strict keys and signatures establish supported
format and possession for the signed operation. They cannot prove random generation,
secret custody, independent operators, truthful demand, data availability, computational
hardness or model value. All corresponding acceptance flags remain false.

## Commitment order and exact bytes

The operator supplies a canonical public `pon-native-operator-actors-spec-v1` JSON
object, at most32768 bytes. Object keys use the existing sorted JSON serialization;
no whitespace, duplicates or unknown fields are accepted. One trailing newline is
allowed by decoding but excluded from the hash. `deployment_id` is a nonzero32-byte
lowercase hex identifier. `genesis_timestamp` is1..i64::MAX. The exact six acceptance
fields `production_activation`, `public_network_ready`, `independent_governance_accepted`,
`hardness_accepted`, `demand_truth_accepted` and `objective_model_quality` must be false.

The descriptor fixes source, requester, sorted3..16 evaluators and sorted1..32 positive
u64 genesis allocations. Source, requester and evaluators must be distinct and all
funded. The total funding uses checked u64 addition. Every allocation/role key uses
canonical Ed25519 encoding, rejects weak keys and the exact16 existing funded
`DEV-ONLY-KEY` fixture identities. This finite exclusion does not detect other predictable
keys. Evaluators do not submit a genesis possession proof; their later strict native
commit/reveal signatures prove possession for those messages. Operator custody and
role assignment remain assumptions. Candidate freeze still applies native author/exclusion
filters and requires the complete remaining2..16 eligible set; a genesis roster is not
a promise of three eligible signatures for every candidate.

Only `native-public-evaluation-dev-v1`, `signed-task-lifecycle-dev-v4` and a supported
explicit `linear-expert-dev-v1` or `smollm2-135m-cpu-dev-v1` model profile may be selected.
The descriptor includes exact bootstrap model/input hashes plus nonzero source record,
authorization scope and availability manifest/root. These four statements are operator
attestations, not independently verified permissions or retention evidence.

1. Canonical descriptor bytes give `H(native-operator-actors-spec-v1, bytes)`.
2. An installed actor policy hash and the descriptor hash enter parameters. A new chain
   label commits deployment ID and descriptor hash; `H(network,label)` gives N.
   Existing work/model/wire configuration and actor-specific parameters give P.
3. Public actual model/input files must each be exactly16384 bytes. Every LE u32 value
   must be canonical in the existing field. Hashes and all4096 derived A/B entries are
   checked. No secret is needed to prepare this context.
4. The fixed maintenance bootstrap is QDL2 slot0, generation/revision1, heights0..1000,
   availability-until1100. Its source sequence is1. The QWA2 task gives zero useful-output
   credit, current exact64×64 contraction only and hardness-status0. Source signs the
   existing `qualified-task-source-sign-v2` QWA2 message, which binds lease and manifest
   including N/P. Requester signs `H(operator-genesis-requester-approval-v1,
   spec_hash,N,P,QDL2,manifest_id)`.
5. A node reconstructs the complete template from the public descriptor and actual
   artifacts, verifies both approvals, runs native lifecycle genesis transitions and
   constructs accounts/model state. G is `H(genesis,N,P,state_root,timestamp)`. G is not
   an input to the prior approvals: this avoids a bootstrap signature cycle.

Changing any committed roster/key/allocation/material/source statement/time/deployment
field creates a new N/P/G and invalidates predecessor approvals. No hot upgrade or
historic database relabelling is supported. A bundle is bounded8192 bytes and carries
full QDL2/QWA2 bytes, not Boolean qualification. The existing source statement codec,
PoN relation, chainwork, fees and historical defaults/golden bytes are unchanged.

## Public-only settings and offline CLI

`Settings::development_with_operator_actors(spec,bundle,model,input)` verifies the
complete public bootstrap. It reads no actor secret and never signs a DEV bootstrap.
Existing known fixture public identities may still be derived for configuration or
finite exclusion checks; those public fixtures are not the new actor signers.
Bootstrap getters return the verified supplied statement/material. The legacy Settings
constructors retain their existing fixture behavior in their historical contexts.
`Config::installed_with_operator_actors` is a pure public configuration constructor;
its evaluator roster is used by native frozen rounds. Distinct keys do not attest that
three independent people run the evaluators.

All commands require `--development`. Actor arguments are explicit:

```text
--actor-profile native-operator-actors-dev-v1
--deployment-spec SPEC.json --deployment-model A.bin --deployment-input B.bin
```

Preparation/signing/finalization require no store:

```text
genesis-prepare ... --output TEMPLATE.json
genesis-sign ... --deployment-template TEMPLATE.json --role source \
  --signer-secret SOURCE.secret --output SOURCE.approval.json
genesis-sign ... --deployment-template TEMPLATE.json --role requester \
  --signer-secret REQUESTER.secret --output REQUESTER.approval.json
genesis-finalize ... --deployment-template TEMPLATE.json \
  --source-approval SOURCE.approval.json --requester-approval REQUESTER.approval.json \
  --output BOOTSTRAP.json
```

Normal `status`, `make/mine`, `submit`, `serve`, pool and pinned-peer commands additionally
require `--deployment-bootstrap BOOTSTRAP.json`. They reconstruct identical Settings
from public files; the normal node never needs source/requester secrets. Existing mining
material/bootstrap options select an already parent-admitted task. An explicit `--miner`
is required for actor mining. `task-fixture` and implicit DEV manifest/miner convenience
are rejected. Genesis/profile overrides cannot be mixed with an actor descriptor.
CLI paths and example ellipses are operator inputs, not preconfigured hosts or keys.

The offline signer independently repeats preparation and compares the whole template
before opening the explicit secret. On Unix it opens a regular single-link file without
following symlinks, requires exact0600 permissions and descriptor UID equal to the
process effective UID from safe `rustix::process::geteuid()`. Environment `USER`/`EUID`
is not trusted. Unsupported platforms reject this offline path. A secret is exactly
32 bytes encoded as64 lowercase hex characters, with optional final newline; its actual
public key must match the descriptor role. The secret is not included in output.
Public inputs also refuse symlinks/hardlinks and group/other write permission. Outputs
use create-new0600 and fsync; output/stdout contains only public context/signatures.
These local permission checks do not attest an uncompromised host or secure erasure.

## Authority and remaining obligations

The normal M06 rule remains: a funded authenticated requester can choose a source for
later leases; source must sign the exact task, and every transaction still passes native
signature/context/nonce/expiry/fee/MVCC checks. This profile adds no exclusive source
allowlist, external data licensing proof or source truth oracle. The initial fixture-key
exclusion is not a global ban on recipients or future actor choices. Bootstrap genesis
has no account fee/nonce movement; the explicit two approvals authorize those immutable
initial records, rather than an unsigned RPC transition.

Task renewal/revoke, parent admission, one-output identity and heavier-fork restoration
use the existing native V4 lifecycle. Continued operation still requires new explicitly
signed successor leases/tasks before expiry; no auto-signer or indefinite liveness is
introduced. Pool preview, mining, peer pins and transport context use the actual deployed
Settings N/P/G. Transport caller identity does not grant evaluator/source/ledger authority.
Native model score0 remains score0; this actor profile makes no LLM gain or hardness claim.

The retained tests exercise two public-only stores, exact reopen, actual qualified PNW1
blocks/renewal/transfer/heavier fork, a manually valid proof with bad transaction nonce,
operator evaluator commit/reveal closure, queued native pool mining, pinned-peer context,
real CLI prepare/sign/finalize/status/mine and byte/key/material/signature/file negative
cases. These are local engineering checks, not independent governance/public qualification.
