# Maintained upstream source: ark-relations 0.5.1

This is the complete published package, locally maintained as an M01 component. Original name, version, license, public feature names and source files are retained. The local Git commit identifies the maintained changes; this is not a new release by the upstream registry owner. Publishing is disabled.

## Original source

- Registry archive: <https://static.crates.io/crates/ark-relations/ark-relations-0.5.1.crate>
- Archive SHA-256: ec46ddc93e7af44bcab5230937635b06fb5744464dd6a7e7b083e80ebd274384
- Published archive: 21501 bytes; 11 files and 90852 uncompressed bytes.
- Upstream Git revision: b34f11d670c2667de3eda6e33daed8027f35043e; directory relations.
- Licenses: [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).
- Original member identities: [UPSTREAM.json](UPSTREAM.json).
- Original authored manifest: [Cargo.toml.orig](Cargo.toml.orig).

The archive hash matches the original exact E lockfile. All published members and both license texts are preserved. The shared registry cache is not edited.

## Local maintenance

- Pin optional tracing-subscriber to =0.3.23; keep default-features=false.
- Rename the empty Layer::new_span callback to on_new_span; preserve filtering/downcast/trace behavior.
- Update tracing API documentation links to 0.3.23.

Reviewed upstream proposal: <https://github.com/arkworks-rs/snark/pull/373> at a7b31d5c1513c1d96bf9861d48a87b83f03b28d2 (closed, unmerged in the retained observation). The reviewed proposal targeted ark 0.4. Only the callback/dependency migration is backported; ark 0.5.1 arithmetic and public features remain.

The proposal supplies review context, not a test pass for this backport. Cargo.toml is active; Cargo.toml.orig and the original hashes retain historical source and original dependency declarations.

## Ordering and strict lint maintenance

Strict Clippy on the complete workspace component exposed an existing ordering
error in the published source. Both `Zero.cmp(&One)` and `One.cmp(&Zero)` returned
`Less`. A retained native counterexample also showed that `compactify` left 12
entries for 11 distinct variables with repeated coefficients. These are actual
behavior failures, not formatting issues.

`Ord::cmp` now defines the single total order `Zero < One < Instance < Witness <
SymbolicLc`, with ascending indices within each indexed category. `PartialOrd`
delegates to it without recursion. Only the previously wrong `One` versus `Zero`
case changes its ordering result; the public enum layout is unchanged. The
[regression controls](src/r1cs/ordering_tests.rs) cover every variant, indices
0/1/usize::MAX, equal values, both comparison directions, transitivity, and
coefficient preservation when compactifying repeated variables.

Other strict lint repairs remove unnecessary lifetime parameters, borrowed
operands and iterator conversions, and use `Option::is_some_and`. Named callback
types retain an explicit borrowed object lifetime; they do not silently impose
`'static` on callers. A real `transform_lc_map` control captures and mutates local
state. These maintenance changes target the repository's Rust 1.95 toolchain;
this component does not promise the published package's older compiler range.

`complete_published_files` and `changed_original_files_at_initial_import` in the
JSON remain historical identities. Later source changes are identified by this
repository's Git commit and are not substituted into those original hashes.

## Verification boundary

No feature or original test is removed to avoid an all-features check. Committed-source workspace tests, doc tests, strict Clippy, lockfile selection, advisories and licenses must pass independently. This file grants no proof-security, public-ingress, consensus or release qualification. Historical failures remain failed.
