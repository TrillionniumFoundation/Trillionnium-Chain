# TRNM Chain Devnet v1 Package (Frozen Legacy Harness)

`trnm_chain_devnet_v1` is the signed, loopback-only integration package for
historical Hepta Research League and Nakama regression. It is not the
canonical CometBFT runtime, a public-testnet artifact, or release evidence.
It is not a Trillionnium World/game package.

The package contains exactly three frozen legacy executables:

- `bin/trnm-chain-node` — signed command ingress, block/state commit, read RPC,
  and verifiable finality receipts.
- `bin/trnm-chain-validator` — an independent Ed25519 validator process with
  durable anti-equivocation state.
- `bin/trnm-chain-cli` — key generation, command signing/submission, receipt
  verification, and operator/genesis workflows.

The historical `trnm-sim`, `trnm-rpc`, and `trnm-cli` binaries are not substitutes
for these live artifacts and are deliberately not used to satisfy this
package contract.

## Trust and scope

- Scope is exactly `loopback-local-devnet`.
- Generated genesis must say `development_only=true`.
- Node and validator listeners must be explicit loopback addresses.
- The archive contains no validator or operator private keys.
- The archive and its internal payload checksum manifest are both signed with
  an operator-supplied Ed25519 release key.
- Verification requires an external trusted public-key file. Trusting only
  the public key carried inside the archive is intentionally unsupported.
- `docs/RELEASE_READINESS.md` remains the release truth. A passing devnet
  package verification does not make this repository public-mainnet ready.

## Initialize a fresh devnet

Generate a new instance after extracting and verifying the package:

```bash
./bin/trnm-chain-cli operator init-devnet --output-dir /absolute/path/to/devnet
```

The command creates:

```text
genesis/devnet-genesis.json
config/node.json
config/validator-1.json
config/validator-2.json
config/validator-3.json
config/validator-4.json
secrets/validator-1.key
secrets/validator-2.key
secrets/validator-3.key
secrets/validator-4.key
```

The `secrets/` tree is instance-local and must remain owner-only. Never copy it
into a release archive, source repository, ticket, or shared evidence bundle.
The build pipeline executes this initializer in a disposable directory,
validates the output and permissions, records only public-file hashes, and
destroys the generated private keys.

## Package verification

Keep the trusted public key out-of-band, then run:

```bash
python3 scripts/release/trnm_chain_devnet_v1.py verify \
  --archive /path/to/trnm_chain_devnet_v1-....tar.gz \
  --checksum /path/to/trnm_chain_devnet_v1-....tar.gz.sha256 \
  --signature /path/to/trnm_chain_devnet_v1-....tar.gz.ed25519 \
  --trusted-public-key /trusted/path/release-public-key.pem
```

Verification fails closed on archive path traversal, links/devices, an
untrusted signing key, either signature mismatch, missing checksum coverage,
missing live binaries, packaged private-key material, malformed JSON schemas,
or scope/readiness drift.

## Operator boundary

Nakama may anchor a signed match-evidence commitment. Hepta may submit typed
evaluation, workload, claim, license, challenge, and resolution commands. The
chain returns a receipt whose quorum certificate and Merkle proofs must be
verified by the consumer. Nakama must not issue research workload or IP claims,
and raw research content must not be placed on-chain.

See `docs/ROLLBACK.md` before starting or replacing an instance.
