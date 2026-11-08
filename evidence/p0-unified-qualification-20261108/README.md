# Unified Chain / Hepta qualification evidence

This directory supports the single integration lineage requested on 2026-11-08.
It is an evidence index, not a second development plan. The governing plan is
`docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`.

**Qualification remains HOLD / NO-GO.** A source merge, a test process exit,
a collector exit, a successful component control, and production qualification
are different observations. No production activation, FinalUse approval, PQ
security-bit claim, or completed real learning/payment loop is granted here.

## Source inputs

The integration retains the complete ancestry of these exact source inputs.
Historical receipts keep their original source and build identities; they are
not added together as results for the eventual integration commit.

| Input | Frozen commit |
| --- | --- |
| Chain authority base, PR 796 | `01e2c4c010c3cf65d1cf094368961efc1abab445` |
| W1 / asynchronous owner, PR 782 | `4e007a87ceecbec8d265f6a70cfd71d512a514b5` |
| Full native path, PR 793 | `812589d9bb189b6abbf33b916a424121199dee75` |
| Joint timestamp / DAA / weight, PR 794 | `b16bae2824e6c8236ef2011fc93a74df3ac7f039` |
| Funded service / task, PR 787 | `e02126dabef04f13792dec45d96ac5d6916d0651` |
| Strong content commitment, PR 789 | `2ce6bc75adae7582b17607a389b0b38cab1eda53` |
| PQ claim / lifetime controls, PR 790 | `88568e2511fcf166e6824947ac97b06b72104385` |
| Cold packet observation / Cell, PR 791 | `9f54b05c643185a5041fc1f78cef77e95877f52a` |
| Separate SHA3 research profile, PR 795 | `1fe2f31c70977a030aec73b63fe0617f34d15a77` |
| QROM revision / encoding controls, PR 792 | `2e5150c41484a8b3196b33de2e997794145edd7c` |
| Hepta readback, PR 5341 | `f1785ca15e41e4e49509a5b211a659e3cbdbf60e` |

The Hepta source above does not contain the separate PR 5045 PQ Fleet input
`7758798f628ebe86e0cbf3c177559edab96cf5ab`. That branch's tests and its Chain
dependency cannot be borrowed into this pair.

The final tested Chain SHA is recorded by the external run receipts and source
observation after this directory is committed. Keeping those receipts outside
the checkout prevents a result-only commit from silently changing the tested
head. Reproduction must use that exact SHA, not a moving branch name.

## Integration corrections

1. Claim aliases are checked recursively: the five activation / production
   aliases must be strict JSON `false`; the five quantitative-security aliases
   must be JSON `null`. The original bypass controls are retained as failures.
2. The DAA evidence reader binds every head snapshot to the trace's actual
   network, parameters, genesis, inventory and event context. It also requires
   the original inactive / zero-authenticated-session scope. Full retained
   packet evidence remains required. Cross-context snapshot acceptance is not
   repaired by trusting a report header.
3. `capture_chain_hepta_identity.py` observes raw tracked bytes, Git modes,
   dependency locks, tracked / untracked / ignored state, and exact expected
   commits. A tracked symbolic link contributes its raw link-target bytes; it
   is not followed. Build, load, interpreter, library, environment and model
   identities stay null when they have not been observed.
4. `chain_hepta_qualification.py` keeps individual attempts and native versus
   collector exits. Unknown effects cannot be redispatched under a new ID for
   the same intent; a committed effect remains historically committed across
   later unknown, cancellation or revocation observations. This version has no
   complete native-result adapter and therefore always retains
   `RAW_OUTCOME_UNVERIFIED` and HOLD.
5. The release-bundle CI roster has an explicit v2 for Linux / Unix. It keeps
   the original 52 exact names and adds the three CCH1 content tests, for 55
   expected tests. The original v1 manifest and archived 32-command runner are
   immutable. A v1 collector rejecting a 55-test binary is retained as a
   collector-contract failure, separately from the native test exit.
6. The PR 791 cold observer and the current writer / PQ namespace / funded
   validation paths are combined without allowing a status query to run
   writer recovery. The PR 792 root-role decoder remains restricted to the
   existing four legal roles. Additional negative controls must adapt to that
   earlier rejection boundary, not widen it.

## Native execution and identity boundaries

Run the archived original helper first, then the supplemental helper, on one
clean final checkout and one explicitly named external Cargo target directory.
Do not run concurrent Cargo writers against that target. The target may contain
compiler cache; cached historical result files are never treated as new runs.

The original helper is
`evidence/pq-authority-preflight-20261108-9d315/authority-final-validation-runner.py`,
SHA-256 `d81437a1cef461666b9103cc3f9e8f8ab0c67a90903b5802f582d2c52cd82710`.
Its original command list, provider identity and timeouts are retained.

The supplemental helper is `run-extra-native.py`. See `EXTRA_NATIVE_RUNNER.md`
for its exact command roster, fresh-output rules and required actual native
targets. It runs the complete Chain workspace with all targets and features,
retains every harness result, and replays fresh DAA and joint-model exports.
It does not replace the original helper or turn its failure into success.

The supplemental parser was independently challenged. The first revision
could accept a unittest stream with both FAILED and OK, and could omit a failed
libtest row appended after the last complete harness. The retained first review
documents both counterexamples. The corrected parser requires a unique valid
unittest terminal outcome and conserves the complete workspace stream against
its harness records. The second review reuses the original probes unchanged.
`extra-parser-reviews.tar.gz` retains both complete frozen review directories,
including their helper dependencies and raw control logs. Reproduce probes in
a fresh extracted copy, since their historical script writes its result file.

Cargo artifact and dispatch records plus post-run file hashes identify observed
test executables. They are not an OS observation of the bytes mapped by a
production process. Where an OS loaded-image identity or model closure was not
captured, the receipt must say `NOT_OBSERVED`; it must not substitute a build
hash or source commit for a load hash.

## Hepta component run and missing production edges

The first Hepta run used the exact f178 source, its original nextest local
profile, original 60-second watchdog and original retry configuration. Twelve
unique selected controls passed: five readback, three unknown/restart and four
durable-effects controls. The combined registry had 796 cases; 784 were not
selected, including 60 ignored registry entries. Selected passing tests do not
make those cases executed.

The collector nevertheless failed independent review. The first two JUnit
files were overwritten before collection, a third actual executable was
produced by the operations-only scope, and the OS process observer captured no
loaded executable. Full stdout/stderr and the surviving original JUnit remain
retained. The initial `chain_sha` is null and must not be filled in retroactively.
Any corrected attempt is a new, separately numbered attempt.

The source trace distinguishes real implementations from the exercised bridge:
the V13 loader, model files, `Adapter.train` and evaluation machinery exist,
while the examined learning-iteration owner ports are test implementations and
the selected controls use synthetic training/evaluation receipts and a
synthetic successor task. A local journal reopen is not WAN cold fetch; a
current-root CAS is not payment; a Fleet executable installation is not the
loaded model closure. These observations do not complete the requested real
train / independently evaluate / pay / cold-fetch / install / load / next-task
chain.

## Gates that remain independent

| Gate | Evidence still required before qualification changes |
| --- | --- |
| P0 integration | Complete same-source locks and observed build/load/runtime/model identities; all actual failures and unexecuted cases retained. |
| P0 consensus | Lowest legal W1 cost, combined timestamp/DAA/weight behavior, and timely independent honest confirmation under the original constrained resource and hostile load profile. |
| P0 permissions | Deployed classical/PQ profile ingress-to-effect tracing, current revocation, content/load binding and nonduplicating recovery. |
| P0 Hepta | One real iteration with independent evaluation, payment readback, cold availability, actual model installation/load and successor task, including legal NoUpdate and all required interruptions. |
| P1 data | Version graph plus independently administered fault domains, custody/renewal, repair/recovery and the existing WAN qualification. Local Cell controls cannot establish these properties. |
| P2 throughput | CPU, network, disk, locks and queues measured under matching security, resource and adversarial conditions, with confirmed throughput and tail latency. Local examples are cost observations only. |
| P3 PQ | The eight specified risk interfaces, explicit lifetime/attack resources, full composition bounds, and independent cryptographic and implementation review. |

PR 795 uses a separate tagged SHA3-512 research namespace. Its earlier scope
assertion compares the runtime tree to the historical cc836 base; that assertion
will fail on a composed candidate containing separately authorized runtime
changes. Retain the actual failure. A separate observation records exact
runtime-tree equality in the resolved merge index before the source manifest
is refreshed; the subsequent plan-pin maintenance must be disclosed separately
as a manifest change. Do not describe that later configuration tree as byte
identical, rewrite the old scope guard, or promote the research profile into
production.

Original hosted resource qualification must run in its actual host environment.
Do not emulate its environment markers locally or relabel an engineering run
with more CPU or memory as the original business profile. The four-second
deadline and independent confirmation requirement are not relaxed.

## Result preservation

The audit attachment retains raw component logs, source manifests, merge
observations, parser counterexamples, prior failures and fresh run receipts.
Its index records exact sizes and SHA-256 values. Results are separated by
source commit, attempt and scope. FAIL, timeout, ignored, filtered, zero-test,
missing observation and unknown outcomes remain visible.

No amended receipt, retry, merge, successful reader, or passing local test can
erase a prior attempt or grant a qualification that its raw evidence does not
establish.
