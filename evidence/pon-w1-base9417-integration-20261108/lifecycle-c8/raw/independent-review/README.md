# Independent C8 lifecycle review

The pinned records are mutually consistent within this bounded read-only review. The four engineering gates remain **HOLD**.

Executed source: `4e007a87ceecbec8d265f6a70cfd71d512a514b5` / tree `19a4f1a6e1cec5c27e595fa555b97cddc4717a3c`. Provider operation: `a35153e046b91421e3d8d67c0d5f053b88a87f4f8ac8213f8e3ee09f5f1be1e9`. The main and independent cold jobs each have an original, complete, durable exit-0 record and one passing native test in their original stdout (122.68 s and 0.32 s). These are two actual executions of ignored entry points, separate from the 697 ordinary qualification executions; this audit runs zero tests.

## Ordering and identity

The original 120 s budget was selected at 1210569011653932, with deadline 1210689011653932. A live first-prove r0vm identity was recorded at 1210605351876087. The retained target terminated with `original-deadline`, exit -9 and sticky cancellation false at 1210689304224509: 292,570,577 ns after the original deadline. Typed M12 `Unknown`, consumed null and no cancellation was recorded at 1210691359119848; the explicit owner request was recorded 1,995,728 ns later. The accepted outcome has no independent timestamp and does not prove a new journal append. It records acceptance without releasing the reservation. Numeric ordering, matching original job/request/clock identities, and the source-bound lifecycle output support the reported natural-timeout-before-owner-request sequence.

The config matches every field of the pre-launch plan and adds only four declared clock/launch fields. Main and cold retained target objects match exactly. The same operation, statement, config, request, original deadline, worker identity and target instance remain bound throughout; there is no deadline extension or observed redispatch.

## Funds, fork and cold recovery

The original and restored Cancel readbacks are equal. The fork-removed and actual-cold-reopen readbacks are equal: Reserved with 1000 remaining and no refund claim. Restoration retains the original Cancel inclusion/wire/packet and returns the funding row to Cancelled with zero remaining; no new Cancel signature or transaction is recorded. The separate provider balance is recorded unchanged. This is the source-bound real Node test's evidence, cross-checked here against its successful raw output; this audit does not reopen the database or independently verify the signature.

The reported 1000 units are gross research principal from this deterministic fixture, not a net account delta or additional global funds to sum across C5/C6/C8. This review does not perform a binary cross-generation wire comparison. `Done` closes dispatch only. Original resource cap remains held, consumed resources remain null and GPU accounting remains unknown; positive provider payment and full resource settlement are not established. Independent cold reports zero new generation dispatches, zero native transaction submissions and zero target-cancel requests.

## Process and qualification limits

The already-recorded final observation checks the five original PID/birth identities (owner, worker, direct child, runner, r0vm) and two exact cgroups/units. Their later absence/inactivity is time-local; all historical descendant wait/reap remains null. The cold reader expressly does not claim fresh recursive process-scope qualification. This audit sends no signals, performs no new process probe, and reads no target database, private environment or ELF.

The preparation's exact gate hash and all eight component manifest pins match the earlier independent qualification review. All declared qualification attempts retain **77 commands, 697 ordinary executions, 696 PASS, 1 FAIL, 4 ignored**. Selected successful coverage is separately **73 commands / 665 PASS / 4 ignored**. The failed first staged attempt is not reclassified, and C7's Unknown launch is not replayed or recast. Copied caches remain fresh=false. No full proof, actual original winning-W1 Node admission, deployment budget/performance, or full protocol security qualification follows from this lifecycle result.

`payload.tar.gz` contains 18 exact original JSON files and four exact durable-job streams. `source-index.json` gives each original path/job, length and SHA256. `summary.json` contains the bounded conclusions and limitations. File acquisition was individually stable, not an atomic multi-file snapshot. The included `audit.py` reconstructs the assertions from the acquisition readset; it is audit tooling, not product source or a new test suite.
