# PQ128 lifetime composition V2 — retained observations

Status: **HOLD_NO_GO**. This evidence accompanies the lifetime scope and conditional
AND arithmetic checker. It establishes executable review contracts, not a numerical
whole-chain lifetime security bound.

```text
actual_lifetime_failure_bound = null
composition_coverage_proved = false
whole_chain_hash_query_scope_closed = false
whole_chain_pq_qualified = false
production_activation = false
```

## Exact source identity

| Identity | Value |
| --- | --- |
| Parent / PR #837 base | `44330b91eb552fd20ef6f2e69bf5e6f1e8f5c0b0` |
| Frozen local execution commit | `cb56a6c37fe29235c1cc2376cd8d7978b028212d` |
| Published source commit | `1ab303e38b9cf7292bba8ab5026aa4bc46e5db0f` |
| Identical source tree | `25b45e6a3b6c58923e699b6e5dfaddb31b9d6aff` |
| Parent-to-source patch SHA-256 | `63b13f3bcc64e81084ff393be2d04f179860773eb55129f5bdde51791bb60f5d` |

The API source commit and the local execution commit have different Git author /
committer metadata. Their complete tree IDs match. The source change is retained as
[source-change.patch.gz](source-change.patch.gz); [source-identities.json](source-identities.json)
and the two raw commit objects record the distinction. Earlier CI/corpus suites ran
against the staged patch on the parent, not against an unmodified parent commit.
The evidence-only publication commit adds this directory after source validation;
it does not change the ten source/configuration/documentation files.

## Completed checks and limits

| Check | Result | Execution scope |
| --- | --- | --- |
| New composition suite | 36/36 PASS; includes 4,096 finite probability cases | Frozen local source commit |
| Retained legacy budget suite | 58/58 PASS | Frozen local source commit |
| Retained root register suite | 42/42 PASS | Frozen local source commit |
| Retained claim guard suite | 49/49 PASS | Frozen local source commit |
| Complete CI contract suite | 108/108 PASS after exact missing source was materialized | Staged patch with retained digest |
| Complete PQ source integration suite | 55/55 PASS | Staged patch with retained digest |
| Current CI contract inspector | PASS | Frozen local source commit |
| Current PQ source inspector | 775 exact blobs; `HOLD_NO_GO` | Frozen local source commit |
| Current composition inspector | Contract passes; actual bound remains null, `HOLD` | Frozen local source commit |
| Cargo metadata, locked/offline | 176 default / 181 all-feature graph packages; 26 workspace members | Frozen local source commit |
| `cargo fmt --all -- --check` | PASS | Frozen local source commit |
| Strict all-target/all-feature Clippy | FAIL (exit 101); see retained stderr | Frozen local source commit |
| Complete repository check | **exit 2; not passed** | Frozen local source commit |
| Changed-document Git target check | 329 local links, zero missing tracked targets | Two changed Markdown files only |

The original full repository check stopped at `docs/README.md` linking to
`evidence/pon-v1/README.md`. The target is tracked but not materialized in this sparse
checkout. The separate changed-document check verifies path presence in Git for the
new V2 document (5 links) and the sole plan (324 links). It does not validate external
URLs, fragments, historical file contents, or the full repository gate. 159 link
occurrences refer to 151 historical targets not materialized locally.

Clippy used the unchanged strict command:

```sh
cargo clippy --offline --locked --workspace --all-targets --all-features -- -D warnings
```

The first attempt used Rust/Cargo 1.95.0 and two build jobs, and exited 101 after
the node crate checker was killed with SIGKILL. It also recorded an unqualified
compiler-path warning from the SQLite boundary build script. The retained retry
uses one build job and the canonical real rustc/rustdoc binaries with the same
strict command, dedicated target directory, and observed OpenSSL 3.5.9 prefix.
The retry also exited 101 after SIGKILL while checking the node crate. Its stderr
retains a SQLite boundary UNQUALIFIED warning about the additional OpenSSL loader
directory. Neither attempt is a strict Clippy pass; the cause of SIGKILL is not
established by these logs. No strictness or source contract was relaxed.
This is source linting,
not execution of the previously failing native recovery campaigns. No prior native
failure or production qualification gap is marked repaired by this evidence.

## What the checker establishes

The legacy 15-path inventory and root 37-path register share one source path, so the
declared union has 51 distinct paths. Raw input manifests and their source inspectors
are checked. A shared path must agree. This is declared-source consistency, not an
atomic source snapshot, a complete dependency closure, or deployment identity.

SHA-256, SHA-512, SHAKE128, and SHAKE256 retain four common public primitive
identities across the two inventories. Their query budgets remain unknown. In
particular, SHAKE128 and SHAKE256 share a KECCAK permutation substrate; the mapping
from XOF use to permutation queries and a common oracle replacement remain unproved.
The declared query scopes explicitly include offline and failed/unpublished work,
preprocessing/advice, helper machines, recursive work, all keys/rosters/epochs and
shared/retired authority. Honest-node limits do not constrain attacker external work.

The arithmetic API keeps all six required declared terms. Given applicable bounds
in one common experiment and a proved project event relation, it reviews:

```text
min(1, common_failure + shared_game_loss
       + min(ml_event + ml_loss, slh_event + slh_loss))
```

Each family's reduction loss stays inside that family's complete bound before the
minimum. Common/shared losses stay outside. No independence or probability product
is assumed. Missing additive terms remain unknown. Matching labels and declared
references do not prove theorem applicability or the project event relation.
The 4,096 finite-space cases check probability arithmetic; they do not prove the
implementation-to-event mapping or cryptographic reductions.

The old eight-domain arithmetic remains separate from the root result. Root bounds
are neither substituted into the old signature term nor added as new disjoint terms.
Eight allocations of `2^-131` have zero target headroom at `2^-128`; placement of
additional common/reduction losses remains unproved. No general extra-loss budget
solver is implemented, and zero target headroom is not a measured actual failure risk.

## Retained failures and publication constraints

The first CI contract run retained four missing-file errors; the exact tracked fuzz
lockfile was subsequently materialized and the complete 108-test suite passed. The
first actual PQ corpus check likewise retained its missing-source failure before
exact blob retrieval and successful structural recheck. The initial formatting log
records missing fuzz support; the frozen formatting rerun passed after exact-byte
materialization. The full repository failure remains a failure. Nothing is erased or
reported as a full qualification pass.

The Mac HeptaRuntime publication route failed during its sparse checkout; later
status calls returned internal errors and the recovery job terminal state was not
observed. Publication uses the connected GitHub API. Transient local execution
transport disconnections are not treated as successful runs. No production service,
key, activation setting, protected branch, or unrelated working tree is changed.
Evidence staging subsequently encountered disk exhaustion. Only this task's
reproducible compiler target cache was removed after both Clippy attempts completed;
the source, execution records, and failed observations were retained.

## Reading and replaying the evidence

[qualification.json](qualification.json) gives machine-readable results and execution
identities. [observations-manifest.json](observations-manifest.json) records SHA-256,
byte length and storage encoding for every retained observation. Files larger than
128 KiB, the raw source patch, and observations with verbatim trailing whitespace
use deterministic gzip; their decompressed SHA-256 and size are also listed.
Run JSON files contain exact argv, identity, timestamps where captured, exit code and
log hashes. Older component records retain their original narrower metadata rather
than inventing unavailable timestamps.

With a complete checkout of the published source commit, run the documented tests
from the repository root, beginning with project preflight. The new entry points are:

```sh
bash scripts/project-preflight.sh
python3 scripts/ci/test_pq_lifetime_composition.py -v
python3 scripts/ci/pq_lifetime_composition.py --root .
python3 scripts/ci/check_ci_contract.py
python3 scripts/ci/check_pq_research_integration.py
```

The design and remaining proof obligations are in
[PQ128_LIFETIME_COMPOSITION_V2.md](../../docs/security/PQ128_LIFETIME_COMPOSITION_V2.md).
The five actual qualification fields above remain unchanged.
