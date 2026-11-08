# Native evidence for the pruned mixed-height MMCS reduction

This packet records a scoped structural binding result and its native regression
checks. It covers the actual P3 0.8.0 binary, cap-zero verifier used by the R1
tagged SHA3-512 research profile. The statement fixes the ordered matrix
dimensions, component and protocol context. It includes pruned openings,
mixed-height injection, duplicate and unequal query lists, and the degree-two
extension-field adapter. See [BINDING_REDUCTION.md](../BINDING_REDUCTION.md) for
the assumptions, proof and limits.

The result reduces a shared-coordinate conflict between two accepted classical
openings to a collision in complete framed hash messages. The postprocessing
also applies when a quantum producer emits those classical openings in the
same oracle/advice experiment. It does not supply a concrete SHA3-512 or quantum
query bound, a quantum commitment extractor, or the complete PCS/Fiat–Shamir
knowledge-soundness proof. Qualification remains `HOLD_NO_GO`, concrete security
bits remain `null`, and production activation remains `false`.

## Exact source identity

The baseline is PR [#795](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/795)
at commit `1fe2f31c70977a030aec73b63fe0617f34d15a77`, tree
`ff035632ecbf4c10d383fbbe936582666f4eb25e`.
The final source-only GitHub commit is
[`4d0a212a0cb592e5c9492c39a6439cd09310ac13`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/4d0a212a0cb592e5c9492c39a6439cd09310ac13).
Its tree `ae3ac43e02ee68d8adcb864b0cf4d21ef21864d7` exactly equals the final native
source tree. The GitHub commit has the #795 head as its parent; local native
commits retain the separate validation stages below. A subsequent commit adds
only this evidence packet, so its full repository tree is different.

[source-provenance.json](source-provenance.json) lists every one of the seven
changed source files with its Git blob identity, SHA256, length and mode. The
six files other than the runner have identical bytes in v2, v3 and v4. These
include the Rust harness, theorem, upstream checker, security contract, README
and sole development-plan addition. R1's existing `Cargo.toml`, `Cargo.lock`,
`tagged_sha3.rs` and `tagged_sha3_wire.rs` remain byte-identical to #795.

## Validation stages and their scope

| Stage | Native source commit and tree | Checks performed |
| --- | --- | --- |
| v2 complete focused gate | Commit `70293cec717416ed57a97b0d326909c4227963e6`; tree `2ae8517c1d8c386d4357bfed8fe6cb14a4a76023` | 158 Python tests, 79 Rust tests, release Clippy with warnings denied, fmt, doc tests, locked/offline Cargo graph, release build, native example, historical hash probe, evidence closure, source checks before and after. |
| v3 runner receipt review | Commit `e55f7f84fbaeda2a3a033edd294773db7be3a903`; tree `81962dcfac38dcf7b158d490588c5d2fe586b840` | Runner adds all 11 required test names and the new example's executable SHA256. Repeats 79 Rust tests, strict Clippy, fmt, native example, source and upstream identity checks. The 158 Python tests are not repeated. |
| v4 final exact-name delta | Commit `5747946c5e87ee601f20c640c0a4b0973f7f17b8`; tree `ae3ac43e02ee68d8adcb864b0cf4d21ef21864d7` | A single runner line changes substring matching to anchored full-line matching. Executes the actual required-name loop extracted from the final runner's AST against the original v3 log, then checks missing-name and prefixed-name negative inputs. Repeats preflight, source identity checks and the unchanged native example, and verifies the executable hash. Rust tests and the full focused suite are not repeated at v4. |

All three stages completed successfully with the scope shown. Their raw
receipts are preserved, rather than relabelling the v2 complete focused run as
a run at the final v4 source tree. The 79 Rust tests **include** the 11 new MMCS
tests. The report's 11 native rejection controls are a separate set of
malformed-opening checks, not an additional Rust-test count. The two v4 parser
negatives are derived strings used to test the log gate, not new Cargo output.
The older 56/68-test and 16-W1-execution records in the parent work remain
historical; this packet does not rerun or rename those W1 executions.

The 158 v2 Python tests comprise 50 repository negatives, 43 source-integrity
negatives, 10 historical hash-audit tests, 40 model-budget tests, six ordinary
path extractor tests and nine evidence-closure tests. This is the focused P3
gate, not an assertion that every repository CI workflow passed.

Readable receipts:

- [v2-focused-gates.json](v2-focused-gates.json)
- [v3-runner-review.json](v3-runner-review.json)
- [v4-runner-delta-review.json](v4-runner-delta-review.json)
- [v4-parser-review.json](v4-parser-review.json)
- [native-mmcs-report.json](native-mmcs-report.json)
- [upstream-source-identity.json](upstream-source-identity.json)
- [root-readback.json](root-readback.json)

The independent readback checked all 150 indexed archive files, the raw
stdout/stderr hashes in 42 command records, test counts, all three native
reports and the original commit-object hashes. It separately executed the
final runner's actual name-gate AST on the original log and both negative
inputs. This readback adds no new native execution or cryptographic
qualification.

## Native report and byte provenance

The native arm invokes `verify_batch_pruned`,
`restore_and_recompute_paths`, `verify_batch` and `ExtensionMmcs` from the
locked P3 dependency graph. The unchanged R1 leaf hasher and branch compressor
run under the actual SHA3 profile. Both configured components are checked on
mixed heights; each five-query batch includes a duplicate query, and each
restored path is independently accepted by the ordinary native verifier.
The extension-field check compares exact basis-width-two flattened rows.

Two deliberately colliding artificial oracles exercise witness extraction at
leaf and branch frames. Their report fields explicitly say `NOT-SHA3`,
`real_sha3_collision: false`, `w1_forgery: false` and
`actual_w1_forgery: false`. Their accepted synthetic openings are not a SHA3
collision or an accepted false W1 proof.

The theorem's `(q0 + q1)(h + 2k - 1) + 2` bound counts complete framed hash
calls for two verifier evaluations plus two independent collision rechecks.
It is not an adversarial quantum-query budget. Native comparison, path
restoration and diagnostic executions elsewhere in the executable are not
silently included in that reduction cost.

The pinned source checker compares each downloaded crate archive with its
`Cargo.lock` checksum, then compares the archived ordinary files with the
cached source actually selected by Cargo. It covers `p3-merkle-tree`,
`p3-commit`, `p3-field`, `p3-symmetric` and `p3-challenger` at 0.8.0, `sha3`
at 0.10.9 and `keccak` at 0.1.6. Receipts before and after agree. This is
byte provenance and API coverage, not a cryptographic qualification of those
primitives. The official challenger advisory applicability is separately
documented in [SECURITY_CONTRACT.md](../../SECURITY_CONTRACT.md).

The final Rust example has SHA256
`a1fc0496f4013879f859eaaa9a556ebd9cd308901e8bff2d56f8cfa796c1a22a`.
The measured native executable has SHA256
`10f18b7d11784d1dfdc72b9104f006460b144636ca810364fba90274a43136a4`.
The report has SHA256
`06f0ca48a869b2342cf08eb18fdd6dd69a02ccbc46d6044ca9994ccd81875606`.
The executable hash identifies the tested build; a different compiler or
environment is not required to reproduce identical executable bytes.

## Complete archive and source reconstruction

[native-evidence.tar.gz](native-evidence.tar.gz) is 132185 bytes with SHA256
`e8891904942de3c45d8c7d343876ff0a835f3857bd364eace28a92cca38aee0d`.
It has 151 regular-file members: 150 indexed files and the index itself.
[native-evidence-index.json](native-evidence-index.json) binds the exact bytes
of every indexed member. The archive retains each stage's stdout/stderr,
source receipts, full summaries, compiler/environment identity, native
reports, runner bytes at v2/v3/v4, full source patches and original local Git
commit objects. Compiled binaries are represented by their measured hashes.

The source patches live in the archive's `runner-review-v4/` directory. In a
disposable checkout of the #795 commit, `git apply --index` followed by
`git write-tree` can reconstruct each stage:

| Patch to apply in order | Expected tree after applying |
| --- | --- |
| `base-to-v2.patch` | `2ae8517c1d8c386d4357bfed8fe6cb14a4a76023` |
| `v2-to-v3.patch` | `81962dcfac38dcf7b158d490588c5d2fe586b840` |
| `v3-to-v4.patch` | `ae3ac43e02ee68d8adcb864b0cf4d21ef21864d7` |

The corresponding `v2-commit.txt`, `v3-commit.txt` and `v4-commit.txt` retain
the Git commit-object bytes, including tree and parent information. Their
Git object hashes reproduce the native commit identifiers above. The source
patches make the tested state reconstructible even when a reader cannot
access the operator host or its local branch.

For a fresh complete focused run, use the final source runner from the
repository root with an installed pinned toolchain and a populated locked
Cargo cache. `--help` documents its explicit output and target directories:

```sh
python3 formal/pon-nakamoto-v1/p3_shared_primitive_qualification/run_qualification_checks.py --help
```

Reproduction of these checks reproduces the recorded finite native observations
and byte provenance. The general structural statement rests on the argument in
[BINDING_REDUCTION.md](../BINDING_REDUCTION.md). The remaining concrete primitive, quantum
extraction, PCS, Fiat–Shamir, recursion and lifecycle obligations stay open.
