# Exact-source authority observations, with unresolved traces

**HOLD_INCOMPLETE_AUTHORITY_TRACING. Whole-chain PQ qualification remains false.**

The [source scanner](../../scripts/ci/pq_authority_surface_scan.py) inventories
signature indicators and selected owner boundaries. Its historical
`reviewed_roles_mapped` field counts the fixed pathname hints in `CRITICAL`;
it does not count completed authorization reviews. That field retains its
original meaning for compatibility. `mapped_role_hints` states the same count
explicitly, and `completed_authority_traces` remains zero.

The [bounded trace manifest](../../config/pon/pq-authority-traces-v1.json) records
six selected starting points: the classical network/profile boundary and the
legacy transfer, settlement, research-command, Hepta V1, and provider-discovery
surfaces. Each record names its observed profile, exact source anchors, possible
effect boundary, and unresolved obligations. Every record is `INCOMPLETE` and its
runtime validation is `NOT_RECORDED`. Named regression sources are locations to
inspect and execute; their presence is not a test result.

## Full source identity

The scanner now retains every Rust path and SHA-256 beneath
`trillionnium/crates`, including files with no recognized crypto primitive.
`source_inventory_sha256` hashes a domain-separated, canonically encoded,
sorted list of those path/hash pairs. Its identity therefore changes when a
nonmatching file changes, an indicator disappears, or a file moves without
changing its bytes or the source-file count. `--summary-only` omits the full
list but retains this digest.

This additive identity does not turn keyword matching into a call graph. The
same descriptor-bound source reader and its existing symlink, size, UTF-8 and
unstable-read refusals still apply. A scan is not an atomic snapshot against
a same-account writer. Qualification runs must freeze and identify their
actual source commit separately.

## What the trace checker verifies

[pq_authority_trace.py](../../scripts/ci/pq_authority_trace.py) requires all six
selected records. It refuses missing or duplicate records, wildcard paths,
unsupported fields, changed entrypoint classifications, stale source digests,
and missing or nonunique exact anchors. Updating only the full-corpus digest
does not update the individual source-anchor hashes. A selected effect owner
cannot be relabelled as a test fixture to remove its obligations.

The checker also binds the checked-in workspace Cargo manifest and lockfile,
all crate Cargo manifests and lockfiles, and the checked-in toolchain and
optional Cargo configuration files. Their digest identifies configuration
bytes; it does not establish the compiler binary, executed target, features,
environment, dependency provenance, or an actual build result. Ordinary edits
between inventory and anchor reads cause a refusal when the final identity
check detects them.

All new rooted source/build reads and the external manifest read reuse the
existing descriptor-anchored `pq_source_reader.read_regular` implementation.
The trace tests reuse its real-filesystem controls for leaf replacements,
ancestor symlinks, hardlinked leaves under replaced directories, in-place and
mapped writes, bounded growth, FIFO substitution, and descriptor cleanup.
No pathname-read fallback is introduced.

On success, `source_trace_integrity_passed: true` means those source bindings
are consistent. The result still reports:

```json
{
  "status": "HOLD_INCOMPLETE_AUTHORITY_TRACING",
  "whole_chain_pq_qualified": false,
  "all_authority_paths_traced": false,
  "completed_authority_traces": 0,
  "runtime_tests_executed": 0
}
```

The checker does not validate prose claims, infer reachability, execute tests,
authenticate an external root, or prove that an effect cannot be reached.
Its accepted schema cannot mark a trace closed or attach a runtime PASS.
Separate native receipts and a reviewed authorization argument are required
for those conclusions. The [whole-chain claim guard](WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md)
remains an independent gate.

The profile-boundary record also binds both public classical owner constructors
and their exact refusal regressions. These constructors now check the PQ account
profile before policy journals, reservations or required-owner markers can be
created. Their previous eventual profile refusal did not establish an absence of
earlier durable effects. Full indicator-file context reviews and these source
anchors remain separate from the native execution receipts and complete authority
tracing; all six selected records retain their incomplete status.

## Selected observations and boundaries

| Trace | Source observation | Remaining boundary |
| --- | --- | --- |
| Classical network profile | `authenticated_session` checks the configured account profile before constructing a classical session. The final listener guard independently checks account profile and backend; its new fault-injection control targets a mismatch already excluded by public constructors. | All alternate owners, transports, local invocations and actual effect paths still need composed native evidence. The redundant check is not evidence of a previously exploitable downgrade. |
| Legacy transfer | `TransferTx::validate_basic` accepts an Ed25519-labelled signature and returns a validation result. | A validation helper does not establish a current Node ledger consumer. Bind any consumer, profile, nonce and effect before treating this as a downgrade. |
| Legacy settlement | The separate settlement kernel verifies registered bilateral Ed25519 signers and computes settlement state transitions. | A local component transition does not establish a PQ Node import, live currency effect or deployed registration authority. |
| Research command | `SignedResearchCommandV1` validates the canonical statement, role and Ed25519 signature. | Locate any external consumer and its current key/nonce/effect owner; the command type's presence alone is insufficient. |
| Hepta V1 handoff | V1 verifies an Ed25519 signature and authority/context fields. Its receiving-owner comparison returns a result. | FinalUse, installation, current withdrawal and non-rewindable operation ownership remain separate obligations. |
| Provider discovery V1 | The legacy advertisement namespace uses Ed25519. PQ V2 has a separate record/directory verification path. | A retrieved advertisement or payload does not establish execution permission, selected-provider authority or complete discovery isolation. |

These observations neither prove six exploits nor close six end-to-end traces.
The existing unreviewed-indicator count is not reduced merely by adding these
records. Test files, fixtures, examples, support code and effect owners remain
in the full source identity. No filename-based exclusion is introduced.

## Run and review

Run from the repository root after the project preflight:

```sh
python3 -m unittest discover -s scripts/ci -p 'test_pq_authority_surface_scan.py' -v
python3 scripts/ci/test_pq_authority_trace.py -v
python3 scripts/ci/pq_authority_surface_scan.py --summary-only
python3 scripts/ci/pq_authority_trace.py --summary-only
```

An exit code of zero from the trace checker establishes source-record
consistency with HOLD. A malformed, stale or unsupported record exits nonzero.
The trace test script requires all 30 controls to execute and pass, with no
skips, expected failures or unexpected successes. Both CI owners invoke that
entry directly; discovery's successful exit alone is not accepted for this gate.
Retain the refusal before making any reviewed update; a later passing source
check does not retroactively pass a native run on an earlier commit.

After a source change, first inspect its effect on the selected observations
and all their dependencies. Update individual anchor hashes only after that
review. Refresh the full Rust and build-input digests only after reviewing the
complete relevant diff, including files without indicators. The scanner emits
the Rust digest; `build_inputs` and `build_inputs_sha256` in the trace checker
provide the corresponding checked-in build-input identity. There is no automatic
command that reclassifies or closes records when hashes are refreshed.

The focused negatives cover a changed unflagged file at the same file count,
new unknown crypto code, removed indicators, stale per-file evidence after a
corpus refresh, missing/ambiguous anchors, dropped/duplicate records, test-only
reclassification, wildcard paths, changed Cargo inputs, duplicate JSON keys,
symlinks and unsupported promotion. They test the evidence contract; they do
not replace the selected native owner regressions.
