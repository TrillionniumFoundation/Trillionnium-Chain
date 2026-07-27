# Devnet genesis

The authoritative devnet genesis is generated with its validator keys and
configs by:

```bash
../bin/trnm-chain-cli operator init-devnet --output-dir /absolute/path/to/devnet
```

It must use schema `trnm_devnet_genesis_v1`, scope
`loopback-local-devnet`, and `development_only=true`. The package does not ship
a pre-instantiated genesis because doing so without the corresponding private
validator keys would be unusable, while shipping those keys would violate the
release boundary.

Treat the generated genesis, node config, four validator configs, and four
owner-only validator secrets as one instance. Mixing material from separate
initializer runs is invalid.
