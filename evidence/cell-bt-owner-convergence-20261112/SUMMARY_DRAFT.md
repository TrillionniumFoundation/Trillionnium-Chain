# Recovered local BT owner convergence evidence

This package preserves available local observations for frozen source
031d442dd0acb693afcfaf42f9cc4db446ba52cb (tree
a897ba4c74897a05ceb364f098b1bfe32c850213). It is a partial recovery of
the selected local evidence. It does not establish full campaign acceptance.
Both all_four_gates_passed and native_model_run_claimed remain false.

## What was recovered

The verified 610,195-byte archive contains 198 original files totaling
3,334,418 bytes. Of the previously selected 195 files / 3,958,339 bytes,
172 files / 2,626,924 bytes were recovered from that archive. The original
1,192-byte documentation patch was separately recovered from complete session
text and matched its prior SHA256. The resulting 173 available selected
original files total 2,628,116 bytes.

The originals retain their contents, timestamps recorded inside reports,
command paths and working directories. The old workspace was not recreated.

The [recovery gap report](recovery/recovery-gap-report.json) accounts for all
22 missing selected files / 1,330,223 bytes: 13 static-gate artifacts, seven
additional discovery artifacts and two setup artifacts. The three later
collection-audit files were also absent and are not part of the original
195-file count. Exact missing filenames are not invented where the original
per-file inventory was never written.

## Available results and retained failures

- The [frozen release DA output](cloud/frozen-candidate-01/da-complete.stdout)
  reports 789 unit tests passed, including the original higher-sequence test
  and all four added real-TCP controls. Its additional integration and doctest
  groups remain in the same original output.
- The [native default example](cloud/frozen-candidate-01/native-grouped-example-default.stdout)
  reports 14 passed. The separately required complete-selection case and
  original strict reader remain in the same campaign. These are fixture tests.
- The [dependency recheck](cloud/frozen-candidate-dependency-recheck-01/summary.json)
  passed both locked metadata graphs. Earlier missing-dependency failures
  remain in the original campaign.
- The [authority review](reviews/authority-current.json) and
  [corpus review](reviews/corpus-current.json) retain HOLD / HOLD_NO_GO scope.
- The [historical hosted log](discovery/original-hosted-job-130956234453.log)
  retains the 784-pass / 1-fail higher-sequence result. Its cause is not diagnosed.
  The [baseline debug failure](discovery/baseline-full-lib.log) is a separate
  PQ receipt-time-expiry failure. It is not relabeled as the same fault.
- The [controlled interruption](control/frozen-candidate-01-controlled-interruption.json)
  records repeated Node compiler SIGKILL and the stopped local campaign.
  The original campaign summary still says running / incomplete because it was
  intentionally preserved; this is not a claim that the process remains alive.
  Python control failures, native PQ compilation failures and strict-reader
  refusals remain in their original streams.

The [binding review](recovery/recovered-log-bindings.json) rechecks 90 completed
campaign streams, ten dependency-recheck streams, six discovery logs, the
hosted log and the preserved interrupted-summary hash. This checks evidence
integrity; no source test, compilation or model was executed during recovery.
The prior static Clippy success was observed before the outage, but its raw
artifacts are missing from this archive. Fresh raw verification must be a new,
separately identified observation.

## Model resource scope

The [original preparation manifest](model-preparation/prep-manifest.json)
remains unchanged and still records BLOCKED_HOST_AF_UNIX and no model run.
The [independent resource correction](model-preparation/resource-scope-correction.json)
corrects its early descriptive field
resource_owner.required_cgroup_for_this_research_route=false. The original
observer requires an actual outer memory.max=8589934592 and CPU quota equal
to four times its period. The original 300-second acceptance limits are
unchanged; later watchdog cleanup deadlines do not extend them. Torch uses
four intraop threads and one interop thread. Worker RSS or a wait4 peak is not
a whole-process-tree hard cap, and dependency preflight grants no CTS1/CHB1
admission or execution authority.

The [original observer](reviews/run_model.original-a67d83.py.txt) and
[reviewed candidate observer](reviews/run_model.candidate.py.txt) were recovered
from exact retained source text. Their only difference is the REPO path.
They are review support, not a model execution receipt. The
[documentation patch](pending-patches/documentation-resource-scope.patch)
contains the resource-scope wording correction and remains unapplied.

## Scope still pending

Remote exact-source tests, the release normal-main ELF and any fresh real-model
operation need their own actual receipts. This local package claims no FinalUse,
installation, production activation, independent operators or failure domains,
real service payment, or model-quality improvement.

[local-evidence-files.json](local-evidence-files.json) lists exact sizes,
SHA256 hashes, original source paths and recovery provenance of every included
file except itself. The manifest is create-only, and all existing destinations
must already contain identical bytes.
