# C8 bounded post-push CI observation

This directory retains one bounded, non-atomic observation of PR 782 after the C8 source push. It is a reading-completion record, not a passing CI qualification or a final status for still-running work. No CI rerun, workflow dispatch, source/guard edit, new base integration, or new operation was performed.

## Identity and window

- Candidate: 4e007a87ceecbec8d265f6a70cfd71d512a514b5.
- Fixed integrated base and actual base ref: 9417e495165865ef6c1288b39084856e31020634.
- Actual PR merge: a3b427a9f39e90176c9bfb48d85f9353fb2bd99b, with ordered parents [9417e495..., 4e007a87...] and tree 19a4f1a6e1cec5c27e595fa555b97cddc4717a3c.
- Observation window: 2026-11-08 10:22:55.303838857 UTC through 2026-11-08 10:24:36.474930938 UTC.
- PR was open and draft; final REST mergeable_state was unstable. REST fields, Git refs, actual merge object, comparison result, and literal event declarations are retained separately.

## Population and reading limits

| Population | Success | Failure | Skipped | In progress | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| Exact C8 check runs | 52 | 25 | 3 | 24 | 104 |
| Exact C8 workflow runs | 4 | 5 | 0 | 6 | 15 |

The 24 checks and 6 workflow runs were literally status=in_progress with null conclusion; neither enumeration contained queued entries. They may be described collectively as unfinished. Their eventual outcomes were not observed here.

Two PR GETs, two check pages (100 + 4), one workflow page (15), and six completed job samples were retained. All read commands exited zero. Checks/runs pagination, IDs, and exact C8 head identity were independently verified from retained records; both foreign-source lists are empty. Every sampled job was bound to its original check, job ID, run ID, head SHA and name. The later scope audit made zero new API calls and did not alter the original snapshot. The source review's result-side strictness gap and its explicit existing-record closure are retained in static-review.json.

## Sampled results and limits

| Sample | Observed result | Causal boundary |
| --- | --- | --- |
| W1 fresh challenge service, head | Execution step failed; source checks before/after succeeded | Inner service artifacts were not downloaded; specific verifier/budget cause is unknown |
| W1 fresh challenge service, prospective merge | Execution step failed; source checks before/after succeeded | Same limit; no C6 root cause is substituted |
| Cross-architecture cost, x64 | Native execution step failed; source checks succeeded | The printed Host-controller record is not inner business acceptance |
| Cross-architecture cost, arm64 | Native execution step failed; source checks succeeded | Inner cause remains unknown |
| Original native campaign, x64 head release | Three actual attempts returned 101; original_criteria_met=false and complete_success=false in all three | The complete top-level structured report is present in the raw job log; no per-round inner results are invented |
| CodeQL Python, prospective merge | Succeeded | An intermediate HTTP 504 warning recovered; it is not a failed job |

For the original campaign, the retained top-level report gives attempt durations 113.622614721, 113.402969263 and 113.315760288 seconds, each under its original 600-second outer cap. Original inputs remain 30-second phases, attacker counts [0, 24, 24], baseline/from-zero/late-product modes, 4 seed blocks, 1,024 seed transfers and 21 business blocks. A separate release build succeeded. Its reported failure is ORIGINAL_THREE_RUN_CAMPAIGN_FAILED. These are report facts, not an independent reconstruction of all process/resource accounting or inner confirmation predicates.

Exactly five of the 25 failed checks were sampled for first failed step/logs. The other 20 failure causes remain unclassified. failure-check-roster.json preserves all 25 names/IDs/URLs without inferring cause from names. No full workflow artifact archive was downloaded, and no full History workload was launched or waited for by this observer.

## Event tuple evidence

The two W1 fresh logs literally declare EXPECTED_BASE=9417e495..., EXPECTED_HEAD=4e007a87... and EXPECTED_MERGE=a3b427a9.... Their source guards succeeded. The head lane also declares SOURCE_KIND=head; the presence of EXPECTED_MERGE in its environment does not mean that lane executed a merge checkout.

CodeQL Python exposes the base declaration under EXPECTED_BASE_SHA, while the campaign exposes EXPECTED_HEAD. Unobserved literal fields remain null. Cross-architecture literal EXPECTED tuples remain null in this parser. Null does not mean other aliases or source checks were absent. No expected event value is inferred from REST base, actual merge parents or equal tree hashes. The matching actual merge tree is not a claim that all checks or business gates passed.

## Provenance

The observer job 1a1baae8b12-12894-1c7c and the retained-record audit job 1a1bab67341-12894-1cc3 both have authoritative succeeded/exit-zero, complete and durable terminal receipts in runtime-receipts/. The observer source, exact submitted source with declaration, original command records and public JSON/log bodies are retained. Credentials, private environment files, databases and binaries are excluded.

manifest.json binds every published member by relative path, byte length and SHA-256. summary.json links the original immutable snapshot, scope audit, observed event tuples, Host-controller projections and the campaign's actual structured log record. Original logs and read commands are not rewritten. Publication performs no additional GitHub/CI observation.
