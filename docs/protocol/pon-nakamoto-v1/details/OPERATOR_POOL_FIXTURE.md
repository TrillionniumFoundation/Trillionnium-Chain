# Finite offline operator pool input builder

The explicit `operator_pool_fixture` example uses the
[operator actor development profile](OPERATOR_ACTORS_V1.md). It creates signed inputs
for a finite20×8 transfer campaign and one V4 overlap renewal. It does not mine, submit,
execute a deployment, certify source truth, create independent operators or grant public
readiness. Existing `public_pool_fixture` remains an explicit historical DEV-only tool.

```text
operator_pool_fixture NEWDIR SPEC BOOTSTRAP MODEL INPUT SOURCE_SECRET \
  REQUESTER_SECRET TRANSFER_SECRET TRANSFER_RECIPIENT MINER
```

All10 positional arguments are required. The public descriptor/bundle/actual16384-byte
materials reconstruct the exact native Settings. The three signer files are explicitly
opened on the builder host with the existing no-follow/single-link/eUID/exact0600 checks.
Actual source/requester public keys must match the descriptor. Transfer sender is the
actual public key of the explicitly supplied transfer file, must be genesis-funded and
must differ from requester to avoid nonce-stream collision. It may equal source; source
statement sequence and ledger account nonce are distinct. Recipient is an explicit
strict supported key. Miner is an explicit strict genesis-funded account, and becomes
`preview_miner`. No signer key or signer filename is written to public output.

The tool signs160 transfers with nonces1..160, grouped8 per file. Requester separately
signs account nonce1/tag22 carrying the source-signed sequence2 successor task. The
maintenance lease remains slot0/generation1, advances revision2 with not-before9,
expiry1009 and declared availability1109. It is previewed for inclusion at height9 and
can be included while the predecessor remains eligible, through height1000; after that
it cannot retroactively authorize a work packet. Renewal preserves material and the
zero-credit maintenance output identity. Availability remains an operator statement.

Before creating `NEWDIR`, the tool validates every supplied public input and constructs
all signatures. Outputs are create-new0600 files under a create-new0700 directory:

- `deployment-spec.json`, `deployment-bootstrap.json`, `bootstrap-model.bin`,
  `bootstrap-input.bin` copy the exact public inputs.
- `bundle-00.json` through `bundle-19.json` contain signed transfer hex arrays.
- `atomic-renew-overlap.json` contains the single signed renewal envelope.
- `manifest.json` retains actual N/P/G, actor profile/spec hash, model/task/evaluation
  selectors, actual public senders/recipient/miner, every raw input, source inventory,
  binary digest and public-material filenames. All six acceptance flags are false.

The manifest keeps `public-pool-development-input-fixture-v1` and existing
`public-pool-fixture-source-v1`, `public-pool-fixture-raw-v1` and
`public-pool-fixture-binary-v1` hash domains. `actor_profile` selects the explicit
operator interpretation; it is not a silent reuse of the historical DEV genesis.
`builder_commit_claim`/`builder_tree_claim` are caller build claims and must be checked
against retained Git bytes. Source inventory and signatures prove byte integrity and
key possession, not physical placement or independent measurement. Operators still
need adequate fees/balances, timely native pool admission, mining and full validation.

Only the four public material files and independently owned transport identities should
reach remote nodes; the builder's three business signer files stay on its offline host.
Normal remote CLI uses all public actor deployment arguments and an explicit miner.
The native example regressions execute all161 signed inputs over20 real PNW1 blocks,
check overlap renewal/nonces/reopen, and reject wrong source, unfunded miner and requester
nonce conflict before output publication. These local tests disclose deterministic test
keys and use logical header time; retained test outputs are not live deployment keys or
public qualification. `TRNM_OPERATOR_PUBLIC_FIXTURE_DIRECTORY` optionally retains only
those public test outputs for a separate verifier.
