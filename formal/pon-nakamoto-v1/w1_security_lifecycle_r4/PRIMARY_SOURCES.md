# Primary sources and exact applicability

Reviewed on 2026-11-08. This list distinguishes full material read from abstract
or draft metadata. No entry is an automatic theorem for the fixed W1 profile.

## P3 0.8.0 implementation

The retained Cargo.lock is the implementation authority. The official crate
archives were obtained from `static.crates.io`; source hashes used in this work
are fixed by [source_contract.json](source_contract.json).

| Source | Fact used |
| --- | --- |
| `p3-fri/src/prover.rs`; `p3-commit/src/adapters/extension_mmcs.rs`; `p3-symmetric/src/sponge.rs` | Binary FRI rows flatten to four base-field elements and enter one zero-initialized sponge block. |
| `p3-fri/src/verifier.rs`; `p3-fri/src/two_adic_pcs.rs`; `p3-uni-stark/src/verifier.rs` | Zero-difficulty witnesses must be canonical zero; native mutation tests independently confirm rejection. |
| `p3-challenger/src/duplex_challenger.rs` | Buffering, rate-slot overwrite/clearing, absorption-length addition into capacity, and output sampling order used by the counter replay. |
| `p3-challenger/src/fs/pattern/sequence.rs`; `fs/transcript_field.rs` | Typed transcript/algebra identity includes Keccak-256 machinery outside the Poseidon2 counters. |
| `p3-uni-stark/src/transcript.rs`; `p3-fri/src/transcript.rs`; `pcs_transcript.rs` | Actual challenge and opening schedule, including the fixed 64 query indices. |
| Repository `proof_config.rs` at both pinned revisions | Shared primitive, research component domains and fixed field/FRI parameters. |

Newly fetched archive checksums match the retained Cargo.lock:

- [p3-challenger 0.8.0](https://static.crates.io/crates/p3-challenger/p3-challenger-0.8.0.crate): `92cccaed1c107ad279e76dfd10aa71cff1c1898eb282f406288ad556e65e5a8f`.
- [p3-sha256-air 0.8.0](https://static.crates.io/crates/p3-sha256-air/p3-sha256-air-0.8.0.crate): `84c0b9594dc05f5956b9dc64e43be04ee2a33b6dd531a51935303d963643018c`.
- [p3-air 0.8.0](https://static.crates.io/crates/p3-air/p3-air-0.8.0.crate): `be7a317aa82ba3d758229db6dd1e2baa75f9aa6f1179d98b3b1e0c2c6b930d59`.

## FRI and random-oracle Fiat–Shamir

Block, Garreta, Katz, Thaler, Tiwari and Zając,
[Fiat–Shamir Security of FRI and Related SNARKs](https://eprint.iacr.org/2023/1071).
The proceedings text was read from the
[NSF-hosted primary author copy](https://par.nsf.gov/servlets/purl/10510337),
SHA-256 `301d3bc0325838c3361d7bf133cb8e6fe09d0196263f4697f0cc04c3a4839ad2`.
Corollary 4 gives its classical BCS-FRI bound in the form
`Q * epsilon_RBR_FRI + 3 * (Q^2 + 1) / 2^kappa` under that paper's construction
and oracle assumptions. Its quantum statement is asymptotic and is not a
numeric PQ128 certificate. W1 still needs an exact PCS/IOP/encoding mapping;
its shared permutation duplex is not directly that random oracle. Counts of
received proofs cannot replace the adversary's oracle-query budget.

## Duplex-sponge compiler

Chiesa and Orrù,
[A Fiat–Shamir Transformation From Duplex Sponges](https://eprint.iacr.org/2025/536).
The ePrint metadata showed the latest revision dated 2026-03-27. The abstract,
[author-institution record](https://infoscience.epfl.ch/entities/publication/b840dd42-110d-4bfe-b163-30c87676b1d8)
and [author's 2025 slides](https://permutationbasedcrypto.org/2025/files/Michele_Orru.pdf)
were inspected. Direct PDF retrieval was refused with HTTP 403 and is retained
as a failed observation. No unread theorem number or exact constant is asserted
here. This is relevant ideal-permutation compiler literature, but P3's exact
buffer update, length tag, codecs, shared MMCS roles and extraction game must be
matched before importing a bound. Indifferentiability alone is not treated as
an extraction theorem.

## Current protocol-format draft

The official
[CFRG Fiat–Shamir draft 04](https://www.ietf.org/ietf-ftp/internet-drafts/draft-irtf-cfrg-fiat-shamir-04.html),
dated 2026-11-02, was read as a work-in-progress draft, not an adopted RFC. Its
codec and framing requirements, explicit context and extraction/simulation
discussion help identify mapping obligations. They do not establish P3's
canonical decoding, quantitative quantum loss or shared-permutation extraction
security. A session/domain tag distinguishes transcripts without resampling the
underlying primitive.

## Quantum extraction framework

Chiesa, Di, Hu and Zheng,
[How to Prove Post-Quantum Security for Succinct Non-Interactive Reductions](https://eprint.iacr.org/2025/2166).
The primary abstract/metadata were checked, including revision 2026-03-02 and
EUROCRYPT 2026 attribution. It identifies modular quantum vector-commitment
extraction and adaptive noninteractive reduction interfaces. Only the inspected
abstract-level scope is used here: this report does not import a numeric theorem,
assert that the fixed P3 MMCS satisfies it, or transfer a QROM result to concrete
Poseidon2 automatically.

## Compression-function literature and excluded inference

Andreeva et al.,
[On Efficient and Secure Compression Functions for Arithmetization](https://eprint.iacr.org/2024/047),
was checked through its
[author-institution primary record](https://research.birmingham.ac.uk/en/publications/on-efficient-and-secure-compression-functions-for-arithmetization/).
The full PDF was not available through this retrieval path. Security theorems
for its named constructions are not borrowed for P3's raw truncated permutation.
The new restricted-leaf lemma in [THEOREM.md](THEOREM.md) is proved directly for
its stated game; it is not presented as a theorem from this paper.
