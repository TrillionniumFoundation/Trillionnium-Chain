# Source-pinned W1 cost research, 2026-10-27

**PN1 / M01 research evidence. The complete transparent proof backend remains
OPEN. No hardness, model utility, paid-ingress service, hardware fairness,
post-quantum security or production activation is qualified by this bundle.**

The sole development plan remains
[TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The live producer/verifier owner is the existing native Cargo workspace. The
primary forward experiment is the extended native
[`pon_pure_cost_campaign`](../../trillionnium/crates/trnm-pon-node/examples/pon_pure_cost_campaign.rs),
not an archived copy of consensus code. Its v2 reader retains the v1 twelve-arm
format and adds two explicit research arms with compiled source byte digests.
Unsupported arms remain in the denominator and never fall back silently.

## What was actually executed

| Observation | Result and scope |
| --- | --- |
| Independent frozen Rust harness, Rust 1.95 | 102 tests passed, zero failed/ignored; frozen original W1 plus new low-rank and witness controls |
| Original #498 native Cargo graph | `--locked --offline -p trnm-crypto-primitives pon_work`: 95 passed, zero failed/ignored, five filtered |
| New module on the actual 21e native graph | Four existing new-module tests passed, zero failed/ignored; 113 filtered |
| Native v2 cost example | Actual `cargo check --locked --offline` passed; no v2 cost campaign run is claimed |
| Native v1/v2 cost reader | Eleven positive/negative parser and explicit source-byte-binding tests passed |
| Frozen corpus | 1,755 rows, 22,356 measured calls, 20,796 target misses, 1,560 winning calls; 927 unsupported rows retained |
| Independent original Python oracle | All 832 unique retained complete W1 attempts replayed; 60 unique winning tickets |
| Follow-up kernel cohort | 315 rows, 10,752 calls, 9,942 misses, 810 wins; all 448 unique records byte-identical to the earlier Python-replayed corpus |
| Correct-product / false-trace controls | 13 independently computed products, 39 independently rejected false transcripts; every short-hash-search miss reconstructed |
| Actual native public-product API | All 39 claims passed the real `PublicProduct::precheck`; the original full verifier rejected all after 512 transcript tiles |
| PWG1 interoperability | Original native complete-relation example executed the exported 49,640-byte input; entire PWJ1 journal and semantic block ID matched the independent Python output |

The module's first correct implementation was slower than existing prepared
producers. Its follow-up uses exact pseudo-Mersenne reduction and transposed
dot products, but still did not beat the best existing arm in the seven tested
follow-up material classes. It is retained as an adversarial research competitor;
it is **not selected as an ordinary mining default**, and it has no current
Node metering/cancellation integration.

The first campaign's 64-attempt same-material comparisons observed existing
blocked-zero and blocked-one-zero producers below prepared-general cost for
their applicable inputs. Other best observed strategies varied across the
shared host. See [the original CSV](cost-v1-summary.csv) and
[the follow-up CSV](cost-v2-fast-reduce-summary.csv); every figure includes
per-row preparation and all failed attempts. A finite best observed arm is not
the globally cheapest solver. Repeated nonce paths are not independent samples.

Correct-C false-trace generation used a median 17.839 microseconds of process
CPU, while full primitive rejection used a median 1,172.575 microseconds. The
median per-row warm rejection/generation ratio was 67.47. Including one actual
AB setup and all three measured forgeries per material reduces the per-material
ratio to 1.97–18.04. These are shared-host primitive observations. They do not
show a Node eligibility/payment bypass, public-network DoS or reward attack.
The exact public-product filter was tested separately through the real native
API; its success authenticates C only, not the required challenge transcript.

The three complete winner exports preserve target misses and contain all noise
values, both noised matrices and all 32,768 prefix words. Maintenance, rank-two
and zero took respectively 30, two and eight attempts at the research target.
The maintenance operands are exactly `(13*i+17) mod 257` and
`(29*i+31) mod 263`. All headers are synthetic research contexts; matching these
operands alone does not establish current task eligibility. No signature,
Hashcash, stake or committee was added as a security fallback. All additional
proof/FRI grinding fields are zero.

## Evidence identities and limits

The frozen compiled W1 source is
`4b6b8a91b6dfe41fbd7f40f40b359d535c2c4251`; its exact Git blob manifest is
[source-manifest.json](source-manifest.json). The original Python oracle and all
actual compiled copies were checked. The reviewed canonical PWG1/public-product
source is `5e797326b9c7635e43b93f97c65a309e51eafb46`; its manifest is
[parallel-source-manifest.json](parallel-source-manifest.json). The forward
native campaign extension starts from
`21e3ccb5b7e5f3e60cc7e79db676e9708bea3a59`.

Key independent receipts are retained in readable form:

- [Complete original corpus readback](cost-v1-independent-readback.json).
- [Follow-up byte equality and accounting](cost-v2-fast-reduce-byte-readback.json).
- [Correct-product false-trace readback](correct-product-negatives-v1-independent.json).
- [Completed component checks](final-component-verification.json).
- [Backend availability and explicit missing work](backend-availability.json).
- [Actual shared host observations](host.json).

The first cost raw JSON SHA-256 is
`5795397ad8c92219721fc5932739d5aadd29bac2cc01b14704b389d7197a207a`.
The follow-up raw JSON SHA-256 is
`4ce6273e5800017abc0324efac5d6a6cd75587adef042617a18eaaa8d099949a`.
The correct-product negative raw JSON SHA-256 is
`6391f42280bacaca23da40742f31ef5c538133778ec424e32b99482eaf28de3e`.

All observed failures are preserved, including missing initial preflight inputs,
offline cache/layout compilation failures, strict-lint corrections and the
native supplemental driver's first WireError conversion failure. Strict Clippy
for the final frozen harness library/binary passed in a fresh target directory.
Its `--all-targets` command failed on the unchanged #498
`rejection_cache.rs:114` unused assignment. That module is absent from 5e/21e;
the pinned historical source was not edited to hide the failed gate. No entire
workspace, final PR CI, sustained paid-ingress campaign or native v2 campaign
pass is inferred from the scoped checks above.

The N64/R8 complete relation remains expensive to arithmetize: exact q=2^32-5
arithmetic/ranges, bounded SHA noise, every original prefix, full SHA transcript,
task/target/header bindings and semantic block ID must all be proved. The field
has two-adicity one. No real transparent backend, succinct proof, succinct
verification cost or proof-system quantum security was measured here. A full
witness and native full replay are never relabeled as that missing proof.

## Lossless restoration and reproduction

[manifest.json](manifest.json) maps every original evidence pathname to a
SHA-256-addressed gzip object, with both compressed and raw sizes/digests.
Identical original/follow-up byte streams are deduplicated without losing their
separate names. This preserves actual winning **and losing** timed proof bytes. The two
readable CSV copies here use LF line endings for Git review; their original
bytes remain unchanged in the mapped evidence objects.
[restore.py](restore.py) verifies all objects and both source archives, rejects
path traversal, links, duplicate members and oversized output, and executes no
restored program. An output directory must be new.

Verify without extracting:

```sh
python3 evidence/pon-work-cost-research-20261027/restore.py \
  evidence/pon-work-cost-research-20261027
```

Restore the exact follow-up measured source inputs and evidence:

```sh
bash scripts/project-preflight.sh
python3 evidence/pon-work-cost-research-20261027/restore.py \
  evidence/pon-work-cost-research-20261027 \
  --output /tmp/pon-w1-replay-new --snapshot build-input-v3
```

Use `--snapshot build-input-v1` for the first, slower implementation, or omit
`--snapshot` for the final lint-corrected historical harness. Original build
input files, binary digests, commands and logs remain under restored `evidence`.
The final code differs from the measured v3 code only in the retained lint
corrections; it is not given a newly measured performance result.

The source archive is a frozen **measurement reproducer**, outside the active
workspace. It has an independent Cargo.lock and archived local path dependencies.
Their observed read-only cache bytes and licenses are preserved; this is not an
independent attestation of registry provenance and is separate from the native
repository's recovered locked-vendor gate. The original absolute path config is
kept as evidence. Restoration creates `replay-local-paths.toml` pointing to the
exact relocated dependency sources; it does not modify the shared cache or
fabricate registry checksums. Python 3.11+ and Rust 1.95 are needed. From the
restored harness directory, use a private Cargo home/target:

```sh
python3 scripts/verify_research_sources.py
CARGO_HOME=/tmp/pon-w1-replay-cargo-home \
  cargo test --release --locked --offline --config replay-local-paths.toml
CARGO_HOME=/tmp/pon-w1-replay-cargo-home \
  cargo build --release --locked --offline --config replay-local-paths.toml
python3 scripts/test_independent.py
python3 scripts/check_cost_evidence.py ../evidence/cost-v1
python3 scripts/check_negative_evidence.py ../evidence/correct-product-negatives-v1
```

The restored `harness/README.md` gives the exact finite benchmark/export commands.
Fresh outputs must use new directories. CPU timing cannot be reproduced bit for
bit across hosts; byte correctness, all trial denominators and source identities
can be checked independently. The current native v2 path and its official
`--locked` Cargo graph should be used for future native campaigns. Neither the
archived harness nor its dependency lock becomes another consensus owner.
