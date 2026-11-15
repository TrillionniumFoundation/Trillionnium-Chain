# Frozen transparent W1 profile and independent native comparison

## Decision

Keep native complete W1 as the engineering and admission baseline. The isolated
transparent verifier is a research candidate with an explicit acceptance profile,
real negative controls and a reproducible saved-proof comparison. This observation
does not qualify a replacement backend, a complete Node admission statement or
post-quantum soundness.

The measured code is
[`b13211ccf356fe16624da66d970ce71d77a5c51f`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/b13211ccf356fe16624da66d970ce71d77a5c51f),
tree `e3b711355ae8a0fa62b9b52d63537c7b8a1433f8`, following the concurrent
`bd2777f9cc74df10ba07ae8202584ed0fb90a519` integration source. The evidence and CI
workflow are committed separately so the observations can identify the actual
implementation commit without a self-referential source label.

The final integration also preserves concurrent recovery/release work from
`245146c7d2e6f7dfcda463f6a7dd342d4d7ca818`. That commit adds dependency edges for
M15 in the main lockfile; it does not change either independent W1 lock or the
measured W1 source closure. The measurement is not relabelled as a new test of
that separate recovery/release implementation.
The later `8e3df70c1e57a45bb5bbcd6092665dee116695ea` integration also preserves
the separate quantum resource/DAA research and both development-plan additions.
Its research files and CI registration likewise do not change the measured W1
implementation or either independent lock.

| Fixed saved-work observation | Native complete replay | Transparent decode and full application verification |
| --- | ---: | ---: |
| Timed repetitions | 1,000 | 100 |
| Median | 0.544418 ms | 20.1955265 ms |
| Within-run sample p95 | 0.886219 ms | 21.392977 ms |
| Within-run sample p99 | 1.845213 ms | 23.590367 ms |
| Witness or receipt encoding, excluding the shared header | 49,188 bytes | 256,886 bytes |

The primary median ratio is **37.0956259712**, and the receipt/witness byte ratio
is **5.2225339514**. Neither measured component improves. The separate candidate
verify-only median is 20.0486195 ms. These are one shared-host run's observations,
not a comparison of population tails or a statistically established change from
the earlier historical run. Proving, publication, transport, confirmation and
stale-block costs are not newly measured here.

The 318-byte header plus the original witness and receipt totals 306,392 bytes
of these encodings. This is not the complete Node block format and does not
establish that the witness can be omitted. The current journal does not expose
Node's separately checked A/B artifact commitments.

## What changed

The [hardened verifier](../../formal/pon-nakamoto-v1/w1_hardened_verifier/README.md)
installs only the pinned Poseidon2 Succinct verifier into an empty context. The
full path fixes the guest image, final join control ID and both receipt parameter
digests. Composite, Fake, Groth16 and other SDK-supported hash suites cannot
select a different acceptance path. An SDK default change fails the frozen
parameter check instead of silently migrating the profile.

Public journal checks now reject a wrong header, malformed product word, ticket
or work identity before expensive proof replay. They cannot return verified work
on their own: the tentative identity stays local until full successful image,
claim and journal verification completes. A genuine prefix receipt remains valid
for the explicitly labelled integrity diagnostic and fails the complete profile.
Two valid claim encodings of the same real proof produce the same original work
ID. This is not an experiment with independently randomized new proofs.

The [independent native package](../../formal/pon-nakamoto-v1/w1_native_cost/Cargo.toml)
builds the existing native cost source and actual relation tests without a guest
compiler, methods package or prover. It reports the saved header, journal and
work bindings after its timed native samples. Production relation and guest code
are unchanged; additional scalar/reference tests cover boundary products, all
five noncanonical u32 values at both matrix ends, and canonical task/product/
transcript forgeries.

The [comparison observer](../../scripts/w1_transparent_compare.py) checks exact
live schemas and saved-input bindings, pins both executable hashes and records
the declared source commits. It retains direct-child CPU/RSS, exit status, output
hashes, failures and one shared wall deadline. A zero exit observed only after
the deadline is not counted as timely completion. Final validation must also be
observed before that same deadline. No default profile or historical schema is a
fallback for a live observation.

## Reproduced input-boundary repair

The pre-fix executable was saved before rebuilding. On the actual complete
receipt, replacing the first control-inclusion sibling's first u32 at byte
239772 with `0xffffffff` produced a Poseidon2 `elem.is_reduced()` assertion and
exit **101**. The ordinary complete verification command did not return a work
identity. The locked SDK's control Merkle path called `hash_pair` without the
digest range check used in its ordinary STARK Merkle verifier.

The fixed profile checks the leaf and every sibling using the selected suite's
`is_digest_valid()` before either full or diagnostic verification enters that
path. The same saved mutation now exits **1** with
`noncanonical control inclusion digest`. There are 128 sibling-word/invalid-
boundary combinations, checked on both entry paths, plus a noncanonical
diagnostic leaf regression.

The pre-fix executable also accepted changing the leaf index from 1 to 257:
the unused high bit did not affect the depth-eight path. The accepted output
retained the **same** original work ID. The fixed profile requires exactly eight
siblings and an index below 256; it rejects that encoding and long/short paths.
This closes an encoding ambiguity without asserting that the old alias created
an extra lottery ticket.

[regressions.json](regressions.json) preserves both pre-fix results, the fixed
results, executable/input hashes and exact mutation offsets. The pre-fix record
is an ELF snapshot, not an independent compilation attestation. The finite
regression set does not establish an exhaustive decoder audit or arbitrary-proof
forgery. [controls.json](controls.json) contains all 42 current cases: one valid
acceptance, 41 controlled rejections, no panic in that set.

## Relation and measurement boundaries

Both accepted paths bind the saved header, journal and original work ID:

```text
ccf544056c6df13a5ab4e6c021e587ff0008d92388270e64f72a6e2168a326cd
```

The original proof and guest remain tied to
`64be7c4ad51d432e7736ad135476262e23e968f5`; the frozen guest SHA-256 is
`6b58409420f2bd3f7a733de531ce20144580b259fde8ca9362b43d9728a8772c`.
The native implementation has subsequently changed from the historical
Transposed kernel to FullLimb. Identical non-test relation-wrapper bytes and
finite scalar comparisons do not prove all-input equivalence or qualify a newly
rebuilt guest. The observer therefore keeps `source_equivalence_established`
false and records both source identities explicitly.

Native timing includes PNH1 decoding and complete native W1 replay. Candidate
decode-and-verify timing includes bounded bincode decoding, public binding,
profile/canonicality checks, context reconstruction and full cryptographic
verification. It is not a polynomial-commitment-only or STARK-core timing.
Both per-call series exclude file I/O, process startup, proving, transport and
confirmation. Native journal construction is after the samples. Native temporary
result destruction occurs before its sample is taken, while candidate decoded
receipt destruction occurs after its sample. No unmeasured correction is applied.

The native process performs 1,002 complete replays: one warmup, 1,000 timed calls
and one final binding replay. The candidate performs 201 full verifications:
one initial call, 100 verify-only calls and 100 decode-and-verify calls. Its
verify-only call precedes decode-and-verify in each iteration. Whole-process CPU
and wall totals have unequal workloads and must not be divided to obtain the
per-verification ratio. Direct-child peak RSS includes the fork/exec startup
baseline and is not aggregate prover memory.

The Linux x64 run used Rust 1.95.0 on a shared AMD EPYC host, with a cgroup quota
equivalent to eight CPUs and an 8 GiB memory limit. It had no host isolation or
load control. Medians use the mean of the middle pair; sample p95 and p99 use
nearest rank. These describe repeated use of this one saved work item; the
first call is not evidence of a cold machine. Only one
independent existing full proof is involved, and **zero new proofs** were made.

Node additionally checks branch target, parent-state eligibility, task windows,
authorization, transaction/state transition and the manifest's separate
`hash("artifact", A)` / `hash("qualified-task-input-v1", B)` commitments. The
old journal's header and task binding do not implement all of those checks.
There is no proof-only Node entry point. Replacing that admission path requires
a new complete statement/image and independently verified evidence.

## Concrete construction and remaining security obligations

[security-map.json](security-map.json) is generated by the portable
[offline source mapper](../../scripts/w1_profile_source_map.py). It verifies
seven `.crate` archive checksums against the frozen Cargo.lock, checks 37 selected
files against archive members, extracts parameters and independently recomputes
the verifier-parameter digest. It is not a full dependency or compiler audit.
Saved-receipt inspection uses partial wire parsing and a hash-bound historical
verifier log; fresh cryptographic verification is separately recorded here.

| Component | Mapped selection or open obligation |
| --- | --- |
| W1 arithmetic | Original modulus `4294967291 = 2^32 - 5`; original W1 SHA-256 domains |
| Verifier | `risc0-zkvm 3.0.6`, `risc0-zkp 3.0.5`, frozen image and final join |
| Proof arithmetic | BabyBear `2013265921`, degree-four extension |
| FRI parameters | 50 queries, inverse rate 4, fold 16, minimum degree 256 |
| Poseidon2 | Width 24, rate 16, eight output field elements, 8 full + 21 partial rounds |
| Recursive control set | Original parameter root with 27 programs, up to po2=22; observed po2=18 does not authorize narrowing it |
| Upstream estimate | 97 conjectured component bits in source comments, not a complete recursive or quantum bound |
| Application wrapper | Canonical control path/digests and exact acceptance profile; runtime regressions recorded separately |
| Quantum security bits | Unknown (`null`); no concrete quantum soundness qualification |

The [QROM succinct-reduction framework](https://eprint.iacr.org/2025/2166)
supplies conditional theory. The exact AIR/IOR, state-restoration or round-by-
round property, commitments, Fiat-Shamir sampling, each accepted recursive
program, concrete hash interfaces and total query/composition loss still need an
instantiated argument. The literature annotations are dated abstract-level
reviews; no completed full-text theorem/constant mapping is claimed.

[Reed-Solomon proximity counterexamples](https://eprint.iacr.org/2025/2046)
address particular conjectures, not a universal failure of FRI. The map identifies
which concrete source values are known and leaves the required proven/conjectured
bound and recursive composition unresolved. [WHIR](https://github.com/worldfnd/whir)
is a separate academic prototype; its defaults are not this profile or evidence
for its security. No elliptic-curve pairing wrapper is accepted here.

## Validation and retained evidence

| Executed local check | Result |
| --- | --- |
| Hardened verifier release unit tests | 15 passed |
| Independent complete-relation tests | 6 passed |
| Actual full-receipt controls | 42 matched: 1 ACCEPT, 41 REJECT, 0 PANIC |
| Observer tests, including real subprocess deadline failures | 24 passed |
| Offline source-map tests | 7 passed |
| Project boundary controls | 16 passed |
| Repository negative controls | 50 passed |
| CI source-integrity controls | 34 passed |
| Both affected crates: strict release Clippy and formatting | Passed |
| Main workspace formatting and locked graph | Passed; 26 members, 180 resolved packages |
| Standalone native / verifier locked graphs | 69 / 158 resolved packages |

[validation.json](validation.json) contains commands, actual logs and retained
setup failures. The initial missing offline packages and wrong smoke-test input
path did not produce samples. Later locked resolution and correct saved input
passed without changing dependency versions. This W1 change leaves the main
Cargo.lock and frozen verifier lock unchanged at the measured implementation
source; the concurrent M15 graph changes described above remain preserved.

The earlier [complete-proof experiment](../pon-w1-complete-succinct-20261028/README.md)
keeps its failed benefit decision, proving timeout, coordinator interruption and
partial CPU/RSS accounting. This new verification-only observation does not
overwrite that history. Full workspace runtime suites, actual hosted head/merge
results, complete proving/propagation costs and production qualification are
separate gates and are not claimed here.

The separate
[profile workflow](../../.github/workflows/pon-w1-transparent-profile.yml)
runs the independent checks on PR head and prospective-merge source, verifies
source identity before/after execution and preserves failures. Workflow creation
is not an observed hosted pass or an improvement/security qualification.

The complete record is in [reproduction.json](reproduction.json), including exact
source-file, binary and artifact hashes, compiler/environment details and the
known scope limits. [native.json](native.json) and [transparent.json](transparent.json)
retain all samples; [comparison.json](comparison.json) retains process facts and
the failed component-benefit decision; [profile.json](profile.json) records the
actual compiled roots and protocol identifiers.

## Reproduce the isolated comparison

Use a clean checkout of the measured implementation commit, the pinned Rust
1.95.0 toolchain, and its unchanged saved proof assets. These commands create
fresh output directories and do not run a prover or alter Node admission:

```sh
TRNM_W1_SOURCE="$(git rev-parse HEAD)"
TRNM_W1_RUN="$(mktemp -d)"
bash scripts/project-preflight.sh --audit
cargo +1.95.0 build --locked --release --manifest-path formal/pon-nakamoto-v1/w1_native_cost/Cargo.toml --target-dir "$TRNM_W1_RUN/native-build"
cargo +1.95.0 build --locked --release --manifest-path formal/pon-nakamoto-v1/w1_hardened_verifier/Cargo.toml --target-dir "$TRNM_W1_RUN/verifier-build"
TRNM_W1_NATIVE="$TRNM_W1_RUN/native-build/release/w1-native-cost"
TRNM_W1_VERIFIER="$TRNM_W1_RUN/verifier-build/release/trnm-w1-hardened-verifier"
"$TRNM_W1_VERIFIER" profile
"$TRNM_W1_VERIFIER" controls evidence/pon-w1-complete-succinct-20261028/full-proof/header.bin evidence/pon-w1-complete-succinct-20261028/full-proof/succinct.bin "$TRNM_W1_RUN/controls"
python3 scripts/w1_transparent_compare.py \
  --proof-dir evidence/pon-w1-complete-succinct-20261028/full-proof \
  --native "$TRNM_W1_NATIVE" --verifier "$TRNM_W1_VERIFIER" \
  --native-sha256 "$(sha256sum "$TRNM_W1_NATIVE" | cut -d ' ' -f 1)" \
  --verifier-sha256 "$(sha256sum "$TRNM_W1_VERIFIER" | cut -d ' ' -f 1)" \
  --native-source-commit "$TRNM_W1_SOURCE" \
  --verifier-source-commit "$TRNM_W1_SOURCE" \
  --out "$TRNM_W1_RUN/comparison" --total-wall-seconds 120
```

The observer checks executable pins and the existence of the declared commit;
it does not certify compilation. Use the exact clean source and retain build
commands, lockfile and executable hashes as above. To replay the offline source
map, explicitly pass the populated Cargo cache with `--cargo-home` and a new
`--out` JSON path. `HOLD` and false qualification flags remain part of a
successfully completed observation.
