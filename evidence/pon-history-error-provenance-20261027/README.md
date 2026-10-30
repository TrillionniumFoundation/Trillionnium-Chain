# Retained raw evidence bundle

All file names in the report below refer to the lossless raw bundle. Concatenate
`raw-parts/part-*.bin` in filename order to reconstruct
`history-error-provenance-raw.tar.gz`; verify its SHA-256 from `manifest.json`,
then unpack into an empty directory. Every member size/hash and every archive
part is listed. The original observations, including failed/mistyped/sandbox
attempts and the interrupted first full suite, are retained without replacement.
No binary is silently substituted: the executed ELF remains separately hash-bound
and is not advertised as embedded in this small evidence bundle.

# History owner error provenance regression

This candidate continues PR #518 at
`44601b92f786613194a6098158abe663296d4f3e`. It corrects error provenance at the
existing local CPU binding and authenticated remote-reply boundaries. It does
not enable a new History import, alter W1, issue a CPU allowance, migrate a
store, or qualify complete History recovery.

## Original failure reproduction

The actual retained original test executable has SHA-256
`e156ff105c01202323c38903ae70ca6512c16308bec8335a1b6c81537db27cc3`.
Its original build source was local commit
`1ee0c720b625fd5d80ce55089efdb8a9da4c29f2`, whose tree
`46d8951f366c3c2e04edc8597497db27432d6776` is identical to published #518.
The original binary was neither edited nor relabeled as a new build.

Three real failures were reproduced: an authenticated remote diagnostic retained
the local durable-History error code; rejection of a foreign CPU domain was
incorrectly classified as fatal both through a real second listener and before
metered native work. The original tests, diagnostics and assertions remain in
`parent-0.log` and `parent-corrected-0.log` / `parent-corrected-1.log`.

The first listener attempt was refused by the execution sandbox at `bind()`.
The permitted local loopback rerun reached the original failing assertion.
An initially mistyped Rust test selector ran zero tests. Its original log and
receipt are retained; it is **NOT_RUN**, not a passing control. The corrected
selector ran one actual test and reproduced the expected failure.

The previously uncollected #518 retained logs were also read through their real
terminal summaries: six CPU controls, seven V5 authorized-History controls, and
three original History controls passed. `parent-retained-readback.json` records
all five raw log hashes and their 16 actual passes. Those are earlier results,
not executions of this candidate.

## Correction

The default `OwnerPublicServiceCpuDomain` failure still stops its local owner.
Only the bound local owner can construct the separate request-local refusal
origin, after observing that its original accounting is available. A foreign
domain is refused before any reservation or native work. If the original
accounting is unavailable, the binding check returns the existing fatal
`PublicMutationCpuUnavailable` identity. A later local-integrity verdict still
overrides the request-local refusal. Display text and parsing cannot create the
exemption.

The remote-reply constructor retains diagnostic text but removes codes that
would identify this process's local fatal owner/storage failures. It retains
the nonfatal `UnknownParent` and `PublicMutationCpuBudget` identities used by
the existing authenticated bounded Submit recovery path. Authentication,
finite retry rules and native membership checks are unchanged.

The new native negative control abandons a real original CPU operation, then
supplies a foreign domain. It checks fatal refusal, unchanged native state,
zero foreign reservations, zero W1 replays and preservation of the original
bound unavailable domain. Error controls cover parsing, changed prose,
local-integrity override and the retained remote Submit identities.

## Validation records

Build, source-byte manifests, exact binary identity and actual test results are
recorded beside this file. `run_native_tests.py` verifies the bound binary and
source bytes, requires a nonempty exact test inventory, and retains complete
test terminal results. No remote CI status is used as a passing result.

The development preflight uses the original 25-package workspace. The existing
distributed source inventory passes its generator's `--check`; no native source
path was added. The 34 source-integrity negative fixtures and 16 project-boundary
negative fixtures passed locally.

This materialization inherits 3,162 absent historical evidence entries from
the original sparse source checkout. Every non-evidence tracked source path is
present and none is marked skip-worktree. The stricter whole-checkout raw Git
verifier is **not qualified** by that source-only materialization. The complete
remote parent tree retains all prior evidence. See
`source-materialization.json` for the exact distinction.

## Still open

Complete History P0 remains open. Partial multi-step detach/attach requires a
separately signed ReorgContinuation and checkpoints advanced atomically with
each original SQL step. Journal pending publication, the two-hardlink cut and a
durable frame not yet acknowledged by the external anchor require an explicit
publication/repair protocol and actual crash controls. Startup/close cuts,
physical power loss, all SQLite cuts and arbitrary historical process adoption
remain unqualified. Current V6 process observations retain their source-bound
thread-only fixture scope. These error-provenance corrections waive none of
those gates and grant no production, PQ, model-efficacy or release acceptance.

## Final candidate observation

| Gate | Actual result |
| --- | --- |
| Error identities, real second listener, foreign-domain negatives, Submit retry | 13 passed, 0 failed |
| Original V6 crash/cancel/reopen controls | 6 passed, 0 failed, 1 ignored subprocess helper |
| Complete Node suite, candidate's 741-test inventory | TIMEOUT at 1,200 seconds (exit 124); no complete terminal; gate remains OPEN |
| M01 / Node all-targets, all-features strict Clippy | Passed with warnings denied |
| Formatting and original locked 25-package graph | Passed |
| Source-integrity / project-boundary negative fixtures | 34 / 16 passed |
| Full source-only checkout repository check | Failed on inherited absent historical evidence link |

The full Node invocation selected all 741 tests, but its 1,200-second outer
deadline terminated it before a complete test summary. It is not a passing
full-suite observation. A separate post-timeout byte readback verified the
source, binary and runner were unchanged; those checks do not replace the
missing native terminal result. The 1,608 non-evidence files stayed identical
from the actual build through all native tests and strict Clippy. Counts from
separate invocations overlap; they are not additional unique full-suite tests.
The earlier full-node-01 run was interrupted and has no terminal acceptance.

See `final-validation.json` for exact terminal values and original build/source
provenance. This closes the three reproduced classification regressions, subject
to the recorded source and execution scope; it does not close whole History P0.
