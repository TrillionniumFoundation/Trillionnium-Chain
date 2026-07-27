# Devnet configuration

Configuration is generated per instance:

```bash
../bin/trnm-chain-cli operator init-devnet --output-dir /absolute/path/to/devnet
```

Do not hand-edit public keys, genesis hashes, validator-set ids, or vote
endpoints after generation. Regenerate the complete instance when those values
must change. Every listener and vote endpoint is required to remain loopback.

The generated `config/node.json` and `config/validator-{1..4}.json` files are
validated against the schemas shipped in `../schemas/`. Private key paths point
to the instance-local `secrets/` directory; the package intentionally contains
no reusable configured instance and no private key.
