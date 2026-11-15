# PQ continuation: original native execution evidence

These records close specific component execution gaps in existing Chain PR
[#698](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/698)
and Hepta PR
[#4729](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4729).
All six whole-chain PQ domains remain **UNQUALIFIED**. No production activation,
whole-state rollback coverage, independent deployed WAN acceptance, complete
quantum mining model, or precise whole-system PQ-128 claim is established.

The machine-readable [summary](summary.json) and
[source mapping](source-equivalence.json) separate executed commits from later
publication. The archives contain original commands, raw logs, source identities,
and retained failures. A later evidence-only commit is not a new native run.

## Chain source and actual results

X230 executed commit
`60dae3cf66d1e651af8e61eccf761abf43285e63`, tree
`38d77248282cec7c8fb96a5d9f681cbe6d6cd06c`, in durable job
`1a1a4739ef8-96a-7ab6`. Its terminal status is `succeeded`, exit 0.
All 55 command receipts have matching before/after source identity. The final
independent readback checked 7,986 tracked entries and 929,306,657 bytes.

| Check | Actual outcome and scope |
| --- | --- |
| Original-profile all-feature Node library build | Exit 0; real native OpenSSL 3.5.9 provider |
| Required exact native controls | 45/45 passed; original exact-name execution reader also 45/45 |
| Selector preservation | Original 43 remain in order; two retained-admission controls added |
| Node strict Clippy, library/tests/all features | Exit 0 with `-D warnings` |
| Frozen optional verifier release tests | 4 passed, 0 failed or ignored |
| Frozen verifier strict Clippy and release build | Exit 0 |
| Existing complete W1 receipt | `SAVED_FULL_SUCCINCT_STARK_VERIFIED` |

The two new controls check ordinary admission's reuse of the freshly
authenticated IMMEDIATE transaction and actual expiry retirement followed by a
new witness guard. They retain persisted-state, epoch and cold-reopen checks.
The original **250 ms** witness exchange deadline, four-second service condition,
and CPU budgets remain unchanged. This removes a redundant witness check from
ordinary admission; it does not establish a measured throughput improvement.

The full Node suite was **not** executed in this run. Earlier full-service,
capacity and invalid-input failures are not erased by these selected controls.
The retained witness diagnostic ring contains only its last eight records and
does not establish a complete latency distribution.

The optional verifier pins SDK 3.0.6, Poseidon2, and parameter digest
`ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013`.
It accepts one existing full succinct receipt under that profile, with
`independent_proof_trials:1`, `consensus_admission:false`, and
`production_tail_established:false`. It is not the Node consensus backend.
The Node retains its complete native PNW1 verifier. Neither unit tests nor
successful receipt verification prove quantum security or a proving-cost bound.

All five provider input hashes were revalidated after the run. Binary hashes
are post-run identity observations, not independent attestation of each process:

- Node test executable: `cd9befc6071b97d99e5f02cf63b110f7d3d410defff41ea6dd19d78036dbbb23`.
- Frozen verifier: `39daaf66e87d484ebc216aa4ea992fa2c577060d3ecd661866df8614f52afbc9`.

## Local checks and the later complete-cost reader correction

The initial local checks executed commit
`1257461dabde5cd0f2feddaf3c47617e07eaa5a0`. Its complete Git tree equals the
published `60dae3` tree. This is whole-tree source equivalence, not identical
commit identity.

- 99 controls passed: 34 source-integrity, 34 PQ source-integrity, 22 claim-guard,
  and nine provider controls.
- Strict complete-workspace Clippy with all targets/features and locked offline
  dependencies exited 0 under Rust 1.95.0.
- Workspace and verifier formatting, 384 source pins, CI contract, portability
  inventory and repository Markdown links passed.
- Locked workspace x86_64 and aarch64 graphs each resolved 26 workspace members
  and 138 packages; the fuzz x86_64 graph resolved one member and 106 packages.
  Graph resolution is not native ARM execution.

The later code commit
`30e0cd5940f8cd465636106933c3243f5df7cbd7`, tree
`f4169674698044b08e0a9f183e69407c9093e2c2`, changes only the existing campaign
reader, its controls, and the sole development plan. All native Rust, Cargo,
workflow, selector, provider, recorder and frozen-verifier inputs remain
unchanged from `60dae3`. Native execution is still attributed to `60dae3`.

The reader now rejects a known sum of disjoint setup/search intervals above the
complete acquisition denominator even if another interval is unknown. CPU and
wall clocks are checked separately; unknown values remain unknown. The original
fixed historical receipt fixture and command yielded **21/21** passing tests at
exact commit `30e0cd59`, with complete source verification before and after.
This fixes cost-accounting validation. It changes no consensus rule, mining
budget, observed historical rate, or quantum-security qualification.

## Hepta exact execution and later publication

The [Hepta summary](hepta-summary.json) records two separate executions of
`codex-hepta-contracts` on the configured Linux GNU x86_64 `main` host.

| Executed source | Test outcome | Original strict scoped Clippy |
| --- | --- | --- |
| Original `5fa90c21dbcd642ff9101951531c5758c683fdac`, tree `c7af3b5564cff487975cabd4ae0161340e864d3e` | 198 passed, 0 skipped, across four binaries | Exit 0 |
| Pinned local composition `2f04ecfde90a92b9c779540a2c1aa39f584d3e41`, tree `ee77993e4e94b4faf54d661653527605b222b77e` | 198 passed, 0 skipped, across four binaries | Exit 0 |

Both runs used separate complete checkouts and fresh targets, effective Rust
1.96.0 and Nextest 0.9.137, with the unchanged commands:

```sh
just test -p codex-hepta-contracts --locked
just clippy -p codex-hepta-contracts --locked -- -D warnings
```

Both added PQ entry tests executed successfully. They check every public
FinalUse entry's equality with the full revocation head captured at claim time,
while retaining explicit revocation precedence, consumed nonces and effect-guard
lifetimes. These are two executions of the package's 198 tests, not 396 distinct
controls or all Hepta authority paths.

Each original Nextest run emitted 14 scoped metadata warnings. Each original
Clippy run retained three warnings from unchanged, unreachable disallowed-type
configuration entries. Successful exit status is not a warning-free claim.

The executed local composition has ordered parents
`a6d8ce20bf8f5b6991d2dc5ef7313812944db060` and
`5fa90c21dbcd642ff9101951531c5758c683fdac`. During validation, the owner advanced
to `383a8c4150f4d620570a138b817f21960370e43f` with four macOS-only test-fixture
edits outside the scoped package. The complete comparison shows no changes to
the contracts package, Cargo inputs, just recipe, Nextest runner, Clippy
configuration, or inspected FinalUse production consumers.

Existing PR #4729 now contains
`ef5723af6a04c7c74fa8a32ab34acdfd49913233`, tree
`40ab7c559dc651a1ff3bd8f849a8fcbd6ec03925`, with ordered parents `[383a8c4,
5fa90c21]`. Its delta against `383a8c4` is exactly the four original PR files and
their tested blobs. **The complete published `ef5723` tree was not executed.**
The archive preserves the mapping to unchanged scoped inputs, not a third run
or qualification of the macOS fixture changes.

## Retained failed observations and transport limits

The X230 archive retains the initial disallowed-branch preflight failure before
native execution and the later successful canonical preflight. The local
archive retains the cost-reader regression failure and the fixture-copy `EXDEV`
errors; the same original command later passed with `TMPDIR` on the fixture's
filesystem. The Hepta archive retains the pinned checkout's missing-promisor-
blob preflight and exact acquisition before either package command.

The earlier Chain X230 job `1a1a2c21c48-96a-7515` was observed to stop at
formatting before native tests. The local executor's Unix-socket `EPERM` also
prevented runtime validation here. These historical session observations are
not passes; their original raw outputs are not in these archives. The retained
old PR descriptions are snapshots of their then-current state and must not be
read as the current result.

An additional Chain request to `main` sent only read-only inventory. The MCP
request timed out without returning a durable job id; inventory completion is
unknown. No native checkout, provider build, or test command was sent for that
additional route. It is not a second Chain native execution and does not alter
the separately completed Hepta results on `main`.

X230 archive creation acknowledged late after the archive already existed.
The identity was reconciled and version-pinned chunks were verified without
replaying creation or tests. The [transfer receipt](x230-transfer-receipt.json)
and [transport recovery](x230-transport-recovery.json) retain that distinction.

## Whole-chain qualification still required

| Domain | Remaining acceptance condition |
| --- | --- |
| Authorization roots | Migrate and qualify actual Hepta RunStart, HTTP automation, governance, release and recovery consumers; generic PQ-capable types alone do not qualify every composition. |
| Proof security | Establish a precise quantum-security argument for the complete native W1 relation and, separately, the exact optional succinct profile. |
| Quantum work and fork choice | Account for complete legal W1 construction, reversible oracle/uncomputation, amortization and effective work rate under equal budgets. |
| Migration and rollback | Extend beyond the three PNQ2 witness tables to a defined full Chain/Hepta protocol, separating reorg state from monotonic revocation, spent-use and effect state. |
| Capacity and invalid inputs | Complete original-budget full-service, CPU, History and business-confirmation acceptance; selected controls do not erase earlier failures. |
| Independent end to end | Independently deploy and qualify the composed configuration under WAN, faults and migration, with actual operational trust boundaries. |

## Archives and verification

| Archive | Bytes | SHA-256 |
| --- | ---: | --- |
| [Local checks and reader evidence](local-validation.tar.gz) | 168494 | `647287a163d25accb5849a2d96d6881b6be0431c963b4c66209cfe3d16a39bf4` |
| [X230 native evidence](pq-composed-60dae3-20261104-validation-evidence.tar.gz) | 172084 | `8c78b54131dff27ae99963aeea9e0b4de2cd605d972c00f91534ca63df5d2f69` |
| [Hepta package evidence](hepta-pq4729-native-20261104.tar.xz) | 783340 | `b8eb0d77e0befe411087152741bc5cf8f371bcdf77b36a4328d7f1f2689ea88f` |

The local archive contains 80 files checked against the
[local manifest](local-validation-manifest.json). The X230 archive contains 167
verified members; [local verification](x230-local-verification.json) records
55 successful command receipts and no integrity inconsistencies. The Hepta
archive contains 32 files and its own `verify-receipts.py`, raw logs, full source
manifests and publication comparisons. Archive hashes cover exact bytes;
[SHA256SUMS](SHA256SUMS) also covers the readable metadata here. Evidence excludes
keyfiles, credentials, source checkouts and build binaries.
