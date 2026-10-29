# Maintained upstream source: ark-crypto-primitives 0.5.0

This is the complete published package, locally maintained as an M01 component. Original name, version, license, public feature names and source files are retained. The local Git commit identifies the maintained changes; this is not a new release by the upstream registry owner. Publishing is disabled.

## Original source

- Registry archive: <https://static.crates.io/crates/ark-crypto-primitives/ark-crypto-primitives-0.5.0.crate>
- Archive SHA-256: 1e0c292754729c8a190e50414fd1a37093c786c709899f29c9f7daccecfa855e
- Published archive: 84890 bytes; 57 files and 411170 uncompressed bytes.
- Upstream Git revision: 455d599aae0aa81acf1c2faadf37def63a25a291; directory crypto-primitives.
- Licenses: [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).
- Original member identities: [UPSTREAM.json](UPSTREAM.json).
- Original authored manifest: [Cargo.toml.orig](Cargo.toml.orig).

The archive hash matches the original exact E lockfile. All published members and both license texts are preserved. The shared registry cache is not edited.

## Local maintenance

- Replace derivative with actual educe =0.6.0, default-features=false and Clone/Debug/Default/Eq/PartialEq.
- Convert all 15 derive sites and retain every explicit generic bound, including bound(false) for original empty bounds.
- Retain the original unused-import allowance for feature subsets; no arithmetic or serialization algorithm changed.
- Retain the Criterion development dependency and its default features, and pin it to =0.8.2. The original 0.4 requirement selected Criterion 0.4.0 and unmaintained atty 0.2.14 when this complete package became a workspace member.

Reviewed upstream proposal: <https://github.com/arkworks-rs/crypto-primitives/pull/184> at 2e61b9ba5092c63a30874f6d459e29f26b65df31 (open, unmerged in the retained observation). The reviewed proposal targets a later ark tree. Only its 15 derive conversions and macro dependency are backported; published 0.5 r1cs imports, arithmetic APIs and features remain.

The proposal supplies review context, not a test pass for this backport. Cargo.toml is active; Cargo.toml.orig and the original hashes retain historical source and original dependency declarations.

The Criterion update follows its [official 0.8.2 release source](https://github.com/criterion-rs/criterion.rs/tree/7f0d745532e3c7b2e11bbf9de9b911f91790d3b1), whose declared minimum Rust version is 1.86, below this workspace's 1.95 toolchain. Its manifest no longer depends on atty; [RUSTSEC-2024-0375](https://rustsec.org/advisories/RUSTSEC-2024-0375.html) records atty's maintenance status. The retained 52 Rust source files contain no Criterion API calls, and the published package declares no benchmark targets. No source, test, feature or development dependency is removed. Criterion 0.8.2 does introduce a platform-gated alloca dependency on Unix and Windows; its actual compilation and the complete resulting dependency graph still require the normal checks. The original import hashes below remain historical import identities, not hashes of this later manifest update.

## Strict lint, API and integer boundary maintenance

The complete package's original 45 tests ran successfully, then strict Clippy
exposed additional maintained-source work. All original tests remain. Repairs
remove redundant borrows, copied clones, unused iterator indices and allocation
wrappers; preserve traversal and random-draw order; replace fixed padding loops
with equivalent resize/repetition operations; and give the actual emulated-field
and bit-vector pair a named type. The Rust 1.95 workspace is the supported
compiler for these changes.

Three compatibility or behavior boundaries are explicit:

- `FromFieldElementsGadget::repack_input` and `from_field_elements` now accept
  slices. Both retained implementations are migrated. Ordinary calls with
  `&Vec<T>` still coerce to slices, and the new control exercises both forms
  through both implementations. External implementations of this public trait
  and explicitly typed function pointers must migrate their signatures. This
  is a local API maintenance change, not a claim of complete source compatibility
  with upstream 0.5.0. Private Merkle path helpers also accept slices.
- The new optional `asm = ["ark-ff/asm"]` feature selects the real upstream
  arithmetic feature. It is not an empty declaration for lint suppression and
  is not enabled by default. The upstream Montgomery multiply/square assembly
  requires x86_64 plus both BMI2 and ADX target features. Other upstream x86_64
  carry intrinsics are enabled by `asm` without those two extra target features;
  therefore a generic x86_64 build can still change generated machine code.
  ARM excludes the x86_64 blocks. `ark-ff-asm` was already an unconditional
  upstream dependency. Actual full-feature builds and tests on each supported
  architecture remain required; a local x86_64 pass is not an ARM pass or proof
  that every ISA-specific branch executed.
- Signed integer absorption uses `unsigned_abs` before applying the sign in the
  field. For MIN, the intended magnitude is exactly `2^(bits-1)`, which cannot
  fit in the signed type. The old `abs() as unsigned` produced that magnitude
  when overflow checks were disabled, but panicked when they were enabled.
  The new implementation defines this valid input consistently. The boundary
  control checks MIN, MAX, -1, 0 and 1 for i8/i16/i32/i64/i128, including the
  unchanged little-endian byte encoding. It does not reject MIN or change the
  field's signed-value convention.

Size rounding uses `usize::div_ceil`, avoiding the former intermediate addition
overflow. For representable previous calculations it returns the same count;
this change does not impose a new allocator or input-resource bound. Other
primitive arithmetic, Poseidon parameters and serialization formats are retained.

The original archive/member hashes and initial-import hashes remain historical
provenance. They are not rewritten to describe these later maintenance changes;
the local Git revision identifies the maintained implementation. Upstream tests,
new boundary controls, strict Clippy and documentation checks are separate
observations and do not substitute for the repository's complete security gate.

## Verification boundary

No feature or original test is removed to avoid an all-features check. Committed-source workspace tests, doc tests, strict Clippy, lockfile selection, advisories and licenses must pass independently. This file grants no proof-security, public-ingress, consensus or release qualification. Historical failures remain failed.
