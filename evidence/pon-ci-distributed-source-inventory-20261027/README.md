# Refresh the existing distributed native source inventory

At original Chain source `0c804e9f5bcf6e972bbb4524c744d4b3c8801c34`,
[repository-truth job 122143728086](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40490734526/job/122143728086)
passed the repository checker and then failed the existing distributed source
inventory freshness gate. Its checked-in embedded list omitted eight native or
configuration files that were already present in that source.

The same failure was reproduced on clean correction parent
`498b4fc2c0394bc4aa9f987d991ef272e8b302a4`. The original inventory bytes and
generator bytes are identical to the failed CI source. The retained result is:

```text
distributed native source inventory differs; refresh before freezing source
```

This candidate runs the existing `scripts/refresh_distributed_source_inventory.py`
without changing its generator or gate. The generated Rust list gains exactly
eight paths and removes none: two PQ configuration files, the rejection cache,
native PQ authentication and its existing test, history import and its existing
tests, and the protocol PQ frame module. It changes the embedded source bundle
inventory; it does not change those files' algorithms or admission semantics.

[The exact inventory delta](inventory-delta.json) records every added path and
its byte count/SHA-256, both inventory hashes, original generator hash, complete
before/after entry counts, the original failed check, and succeeding checks.

After regeneration, the unchanged `--check` command passes. Pinned Rust 1.95.0
`cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check` also passes.
No native build, benchmark, Hepta Rust execution or hosted rerun was performed.
These source and formatting checks do not establish consensus security, model
efficacy or a successful future CI run. Original failures remain evidence of the
original source.
