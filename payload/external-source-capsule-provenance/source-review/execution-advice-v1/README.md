# External evidence lane: fixed-source execution review

This is a static execution and object-dependency review. No external lane, native campaign, qualification run, source edit, Git ref update, or ROG object import was performed.

## Result and remaining conditions

The original external-evidence-contract lane can use the already prepared ROG Python 3.12 environment with numpy 1.26.4 and cryptography 50.0.2. Its 30 original commands use Python validators and reference replays; the selected command lines do not invoke the retired native collection entry points. This is an execution-path finding, not a claim that the full lane passed.

The historical object database is a concrete remaining prerequisite. At the recorded ROG probe all 14 declared commits and all 14 declared root trees were absent. The Mac full-history database contains 11 of the 14 source roots, with 3,836 unique commit/tree/blob objects totaling 509,111,243 raw bytes. The other three roots remain unavailable after the retained fetch observations described below. Raw object bytes are not a prediction of pack size or transfer size. No parent history was traversed or represented as complete.

Architecture separately owns the selected-implementation fingerprint repair in the readiness reader and its original control suite. That repair and a fixed final ROG source checkpoint must be present before root runs the original whole lane. This review does not replace that real execution or hosted head/prospective merge gates.

## Fixed code context

The requested review checkpoint was e1bf4299a0c57ba797baf2cc50192321e8843b6b, tree 926c85beac7bd4faf4ba94a5b7558d8931d2cee3. During collection the root worktree was already at 308878245be0a8ece89447c78caf606a413e5434. The 57 statically reached Python source files were compared against the immutable requested checkpoint and were byte-identical. The initial head-fence refusal is preserved separately; a moving worktree was not silently treated as e1bf.

The original ci_job.sh SHA256 is 625e2b0da839618033638cb0b141f0daa146022d3d0527d46eb0164ef1e6010b. Its external branch has 30 Python commands, beginning with prepare_evidence_sources.py and ending with the historical four-priority work-cost verification. The original required workflow sets this lane to 45 minutes and performs source verification before and after it.

The original invocation, once source and objects are ready, is:

    bash scripts/ci/ci_job.sh external-evidence-contract

No command is removed, split into a substitute qualification, or moved to an optional lane by this recommendation.

## Environment and actual side effects

The existing ROG conformance interpreter is:

    /home/qian-qi/chain-final-consolidation-20261114-root/final-python312-env/bin/python

The read-only probe observed Python 3.12.3, numpy 1.26.4, and cryptography 50.0.2, matching formal/pon-nakamoto-v1/requirements.txt (SHA256 ae117e781e1420b46bfc2c4b9a550da3fe3f98ff9cbe868192036d34c342aed5). Packaging is not installed in this interpreter and is not a dependency of these selected external commands. The separately prepared runtime-release environment does not need to be substituted.

Use the workflow-equivalent clean environment and its Python on PATH. Imported native bridges are opt-in: nonempty inherited TRNM_NATIVE_WORK, TRNM_NATIVE_EXECUTOR, or TRNM_NATIVE_SESSION can select executable paths outside the intended default reference run. The selected lane does not set those flags; original supplement replay also clears its native selectors explicitly. No models or additional package installation are requested by these 30 command lines.

The lane is not filesystem-read-only. Tests and reference replays use temporary SQLite files and temporary fixture repositories. historical_evidence.measured_checkout creates a temporary detached worktree from each declared implementation commit, then removes only that owned worktree. This writes temporary files and shared Git worktree-registration metadata; it does not advance source branches or edit the main worktree. Whole recursive trees and blobs are required to create those worktrees.

prepare_evidence_sources.prepare first tests each exact commit. If absent it performs an explicit fixed-URL fetch with a 90-second per-command limit, no tags, and no FETCH_HEAD. GIT_NO_LAZY_FETCH does not disable this explicit fetch. Correctly supplying the exact objects beforehand permits the original materializer to report fetched=[] without changing its code or checks.

The original historical work-cost invocations all select --verify and --historical. They verify retained raw observations and may perform Python reference calculations; they do not select the separate collect/--run entry point that launches Cargo/native workloads. Historical source bytes, signatures, and package checks remain mandatory.

## Object closure and parent boundaries

The fixed declarations include 14 commit/tree pairs, listed in declared-source-map.json. Consumers use exact commit-to-tree checks, recursive tree/path enumeration, commit:path blob reads, and detached materialization. The reviewed selected paths do not traverse the old commits' parent chains. Parent names in raw commit headers are retained as provenance, but are not requested as extra source dependencies.

The available 11-root closure contains 11 commits (9,202 raw bytes), 488 trees (266,155 raw bytes), and 3,337 blobs (508,835,886 raw bytes). There are no gitlinks. The sorted fixed OID list and per-object type/size metadata are in available-object-closure-v2. No pack was created.

The missing roots are 242906bae4f281c738c60adbd2c053d2ded1eae5, 30b85c34d1be404dcccd9f415286bb43b00f64ea, and 50e158640d8278ca94dbecb6539dab96c6a9fb84. A new isolated bare repository was used for the authorized reads; the shared full-history database was not made shallow or promisor.

The first exact-three depth-one fetch reached its 90-second capture limit and retained UNKNOWN. The subsequent authorized narrower blob:none fetch had a 600-second transport bound but exited 128 after 3.23 seconds because repository.git/shallow.lock already existed. This is a local lock refusal, not evidence that GitHub lacks the objects or that the transport budget is insufficient. The preceding open-file observation found no process, the prior 966,655-byte temporary pack was unchanged, all three commit readbacks still failed, refs remained empty, and FETCH_HEAD remained absent. The lock and partial pack were preserved; no automatic retry or lock deletion occurred.

Until the three metadata trees are recovered, a complete 14-root OID union cannot be stated. The planned ROG reuse check will send only the final fixed OID list to an external create-only directory and run one no-lazy-fetch, protocol-disabled cat-file batch check. No import or source/ref mutation is authorized for this agent. Missing blob bodies and any object capsule remain explicit follow-up scope.

## Evidence

fixed-source-static-scope.json contains the exact 57-source texts, original command list, workflow excerpts, and requirement bytes. declared-paths-and-parent-consumers.json retains the path-level source-map requests and relevant consumer functions. available-object-closure-v2 records the available objects and their sizes. rog-readonly-pty.json and rog-readonly.stdout preserve the environment/object-presence probe. The fetch receipt directories preserve the prior failure states, exact argv, raw streams, timestamps, and readbacks.

All conclusions above are bounded to those observations. Neither the repository-truth result nor an external-evidence result is promoted to pass by this static review.
