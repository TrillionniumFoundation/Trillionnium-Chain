# C1 hosted evidence: exact source, preserved failures

This is an independent, offline evidence package for PR #901 at C1. It is
intended to be committed as `evidence/pq-closure-hosted-c09dbbe992/`.
It does not modify the earlier 241-control evidence, the static-validation
package, their execution counts, or the frozen native packet.

## Source and claim boundary

| Source role | Immutable commit |
|---|---|
| C1 head | `c09dbbe9921da12db8bf7240a8a95a0e9a789e50` |
| C1 prospective merge | `61589dddd13e7495369aaecad9212668049417c1` |
| PR base / earlier #894 | `31543fb6dde565b62b47436e0b1d399b6d0bd772` |
| Observed C1 head and merge tree | `f15a7ee4a0f5455eaf965db01dcd49e02a5f22b6` |

Head and prospective merge remain different source identities even when their
trees match. Earlier 315 observations do not qualify C1. C1 evidence does not
qualify C2 or any later evidence commit. The retained one-host experiments do
not establish whole-chain post-quantum security, WAN or independent-operator
qualification, quantum-mining security, lifetime composition, or activation.

Collection performed no native test executions, workflow reruns, source
mutations, budget changes, permission changes, or H requests. Only existing
GitHub responses and artifacts were read. Large original ZIPs are referenced by
their GitHub artifact identity, byte size, and digest; the compact packages retain
their complete member-hash inventories and original verification receipts.

## Actual C1 outcomes

| Observation | Exact run / jobs | Preserved outcome |
|---|---|---|
| Original 30-second campaign | run `42955583039`, job `130309763995` | Build/source/startup/finalization/upload succeeded. Three original executions exited 101. All nine phase criteria failed. |
| Cross-arch original four-second service | run `42955583052`, jobs `130309764639` / `130309764652` | Five named native invariant tests passed on each architecture; original confirmation report acceptance failed with `CONFIRMATION_TARGET`. |
| Fresh challenge, head / prospective merge | run `42955582893`, jobs `130309765098` / `130309765213` | Source/build/host succeeded. Original selector exited 0 but failed business report acceptance. Fresh selector actually ran and exited 101 at its original four-second/six-depth business assertion. |
| Local CodeQL six-cell grid | run `42955582992` | Actions/Python/Rust on head and prospective merge all completed, retained valid SARIF, and verified before/after exact-source receipts. Upload remained `never`. |
| CodeQL exact-source API exporter | run `42955582970`, job `130309764088` | All 39 retained polls had empty analyses and empty exact-source filtered CodeQL check results. Export remained incomplete and the PR gate unauthenticated. |
| C1 external readiness reader | run `42955583052`, head `130309764822`, merge `130309764799` | Each original suite reported 71 tests, 46 failures and 22 errors. The reader retained a stale selected-body binding after the account guard was added. This package retains that C1 failure and the separate historical proposal; it does not claim a C2 result. |

The 30-second baseline confirmed only one of three rounds in each run. Its three
`verifier_errors` arrays were empty. The six attack phases confirmed zero of
three rounds and reported `PUBLIC_REQUEST_DEADLINE`. All nine observers and
service outcomes completed, and the six attack phases had all 24 actors ready
and normally terminated. No attack phase observed the required paid-credit
depletion. The 600-second outer process timeout was not the failed business
deadline. See [the original native diagnosis](native/NATIVE_DIAGNOSTICS.md).

For both cross-arch four-second observations, the attack-free baseline confirmed
one transaction; 16-worker pressure confirmed zero. Native safety/accounting
invariants passed while the original business target failed. These are different
facts and remain separately recorded.

Fresh-challenge head and prospective merge each also confirmed one transaction
in the attack-free baseline and zero under 16-worker pressure. The fresh native
panic at `public_v3_from_zero/fresh_challenge.rs:244` explicitly says that the
original four-second/six-depth business target failed. Head's first replay
returned the deadline error at 4.001573117 seconds; merge's second replay at
4.050964404 seconds. `FRESH_NATIVE_PROCESS_REQUIRED` is the runner refusing that
actual nonzero native exit, not evidence that the process failed to start. The
original failure is preserved without extending the window or weakening depth.

## CodeQL execution, findings, and API result remain separate

The six local artifacts were downloaded and checked against GitHub size/digests.
Their actual source receipts bind head to C1 and merge to the prospective merge;
artifact filenames containing the event merge SHA are not used as head-source
proof. Each artifact's `step-outcomes.json` says
`code_scanning_upload: never`. Full original SARIF ZIPs are retained in the
bounded-readback package.

| Language | Results in each source lane | Rule |
|---|---:|---|
| Actions | 0 | No retained result rows |
| Python | 2 | `py/redos` |
| Rust | 857 | `rust/hard-coded-cryptographic-value` |

Successful local analysis does not mean zero findings. Head/merge repetitions
are not summed into a count of unique issues. The 857 Rust results have not been
individually triaged by this task.

The two Python findings point to historical evidence files:
`workflow_wiring_static.original.py:60` and `workflow_wiring_static.py:79`
under `evidence/pon-throughput-continuation-20261104/parent-and-tail/ci/`.
The separate [bounded Python review](reviews/py-redos-bounded-review.json)
records that both files have identical blobs at base315, C1 and C2, and that a
literal-reference search within current `scripts/` and `.github/` found no
match. This limited search is not proof of no dynamic reachability, and neither
finding was dismissed, resolved, or erased.

The 39-poll API exporter observation remains unchanged. Local SARIF is not
substituted for GitHub analyses/checks API data, and no PR security gate verdict
is inferred from the local grid.

## Frozen components and public allowlist

| Component | Bytes | SHA-256 |
|---|---:|---|
| [Original compact native packet](native/readback-1.tar.xz) | 1,850,508 | `90f8da399cda835849001e5c65a49d0d8cc2a4b09e191e6c8b73dddbfb275456` |
| [Additional bounded readback](bounded/bounded-readback-c09dbbe992.tar.xz) | 719,180 | `9f7f152885e9eb54725a5fe8909ce90ee5ac23a62facff20f39d0702d2fd22a8` |
| [Original API/readiness archive](api-and-readiness/api-and-readiness-c09dbbe992.tar.xz) | 257,600 | `d95c5b9cfff7ca64a29d2bed6a8d621c3f64b06d02bf2ae7e428e9435ac22fd3` |

The first packet is byte-for-byte unchanged. It retains the 30-second campaign
and two four-second cross-arch observations, full original member-hash
inventories, small raw logs/JSON, source and resource receipts, and explicitly
labelled report projections.

The additional packet contains raw API/tool responses, complete logs for the
new failures, the six original local CodeQL ZIPs, the two fresh-service ZIP
identities and complete member inventories, original manifests/logs, and labelled
report projections. It records the bounded status snapshot; Rust/protocol jobs
still running or queued at that snapshot remain uncompleted observations. No
further monitoring was performed to turn them into presumed passes. First-batch
exact start time was not recorded and is explicitly null; captured subsequent
API clock bounds and download timestamps are retained.

The API/readiness archive preserves all 47 files / 4,406,411 bytes from the
root-recovery frozen package, without rewriting them. Its original
`SHA256SUMS` digest is
`84dbae497200db31eb1476cfba34e34b3c63c3969392d8ce4d9601959deecf5e`.
It contains the original 208,483-byte CodeQL exporter ZIP with 205 members,
the 203-entry outer and 199-entry analysis manifests, the 39 poll responses,
QROM success readbacks, and the C1 stale-reader diagnosis/proposal. The proposal
remains a historical component, not a tested-current-source replacement.

The public allowlist is [FILES.json](FILES.json), mirrored by
[SHA256SUMS](SHA256SUMS). It covers every distributed file except the two index
files themselves. Private download transport and temporary signed URLs are
excluded. Absolute runner paths inside original observations remain provenance;
the verifier does not depend on those paths.

## Portable offline verification

From this directory:

```sh
python3 -B verify.py
```

The [portable verifier](verify.py) reads only this directory, uses the Python
standard library, makes no network calls, writes no files, and executes no
repository, archive, Cargo, or native code. It checks all distributed file
hashes, safe regular archive members, both compact manifests, the unchanged
47-file package, original local SARIF source receipts/results, original exporter
manifests and all 39 empty poll responses, and the preserved native failure
boundaries.

The large original campaign/cost/fresh ZIPs are not shipped here; this portable
run does not claim to rehash their omitted bytes. Their complete ZIP/member
verification is preserved in collector receipts, with immutable original digest
references. The original collector scripts and first verification receipt are
retained as provenance. Use this directory's `verify.py` for portable verification.

Useful standalone entries are [HOSTED_SUMMARY.json](HOSTED_SUMMARY.json),
[SCOPE.json](SCOPE.json),
[bounded status summary](bounded/bounded-refresh-summary.json),
[fresh-service summary](bounded/fresh-service-summary.json), and
[local CodeQL summary](bounded/local-codeql-summary.json).
