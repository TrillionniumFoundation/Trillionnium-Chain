# Canonical public-input fuzzing

This is an isolated `cargo-fuzz` package for the canonical public transaction
boundaries. It does not change or replace deterministic runtime tests.

Targets:

- `canonical_tx_json`: typed transaction JSON decode, protocol validation,
  command dispatch, and accepted-value round trips.
- `signed_envelope_json`: signed envelope JSON/hex/hash/framing boundaries,
  signature rejection paths, and nested canonical transaction decoding.

The checked-in corpus includes accepted transaction families and an
unknown-field regression input. Dependencies are locked in this directory.

## Bounded smoke

Install the pinned runner once:

```bash
rustup toolchain install nightly-2026-07-27 --profile minimal
scripts/ci/install_cargo_fuzz.sh
```

The installer verifies the published `cargo-fuzz 0.13.2` crate archive,
updates only `anyhow` from the vulnerable published-lock selection to exact
`1.0.103`, verifies the resulting complete lock-file hash, and installs from
that temporary source with `--locked`. The fuzz package itself has a separate
checked-in lock file.

Then run the same deliberately short smoke used by CI:

```bash
TRNM_FUZZ_SMOKE_SECONDS=15 scripts/ci/check_canonical_fuzz_smoke.sh
```

The smoke is only a build/integration and immediate-crash gate. It is not
evidence of meaningful fuzz coverage or a long-running security campaign.

## Manual campaign

For a real campaign, run each target with an explicit budget and preserve
`trillionnium/fuzz/artifacts/`:

```bash
cd trillionnium/fuzz
cargo +nightly-2026-07-27 fuzz run canonical_tx_json -- \
  -max_total_time=3600 -timeout=10 -rss_limit_mb=2048 -max_len=2162688
cargo +nightly-2026-07-27 fuzz run signed_envelope_json -- \
  -max_total_time=3600 -timeout=10 -rss_limit_mb=2048 -max_len=2162688
```

Promote every confirmed crash to a minimized corpus/regression test before
closing it.
