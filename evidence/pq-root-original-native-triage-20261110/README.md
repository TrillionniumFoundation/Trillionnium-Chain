# Native original campaign: exact hosted artifact triage (2026-11-10)

**Verdict: HOLD.** Read-only diagnosis of fixed original 30-second native phases, with no alteration to the test, deadline, budget, input, eligibility or success predicate.

## Frozen identities and checks

- Stacked on [V4 Draft PR #837](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/837), delivery head 44330b91eb552fd20ef6f2e69bf5e6f1e8f5c0b0. The separate V4 local native component source was 0d99924005b70b1308bf3e62c53e9300fbb4aac4; this diagnostic does **not** relabel that component run.
- [Actions run 42592807143](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42592807143), job 129078225748: release build succeeded, original campaign **0/3**, three return codes 101, no phase startup errors.
- [Raw artifact 13661833423](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42592807143/artifacts/13661833423): 68,296,557 ZIP bytes. GitHub digest and independent downloaded-byte SHA-256 match exactly: f3eac6ef3040f889f83bf610e168944976a383c5e115996720da170d3b95ccdb. Provider expiration metadata: 2026-12-09 09:31:42 UTC. The ZIP is not copied into this branch.
- Original report member SHA-256s, all independently verified against their own run-N-result.json runner receipts: run 1 = 61caeb57dea7ba9d3cf991932952e7bbc5f2d9e38c9c39bca36267d103ac706b; run 2 = b03502f9d5f0c6988901360b97873f2daddaf647d3f971873097c7ee331231c6; run 3 = d190130c6917b2292261e8edaed569f59ae68957d4cb0508a92464c63af2836c.

## Nine observed phase-level failures

Every baseline ran three rounds; the first two reached depth-six confirmation inside the 30-second phase, while the third started around 29.61 / 29.81 / 29.79 seconds and had no confirmation observation before the deadline. Baseline receiver/client tips differ **only in run 1** (runs 2 and 3 equal); baseline verifier errors are empty.

Every attack phase had 24/24 actors ready and all actors reported successful completion without attempt-cap or forced kill. Every attack phase started one honest round, confirmed zero honest rounds, retained PUBLIC_REQUEST_DEADLINE, had receiver/client tip disagreement and did **not** observe paid CPU credit exhaustion. The recorded paid CPU refill nearly offset the paid debit, leaving approximately 2 seconds of credit in the final meter despite thousands of failed hostile work attempts.

| Run | Mode | Confirmed/started | Accepted/rejected full work | Equal tips? | Final paid credit (ns) |
|---|---|---:|---:|---|---:|
| 1 | baseline | 2/3 | 16/0 | no | 1,988,453,478 |
| 1 | from-zero | 0/1 | 7/1,631 | no | 1,999,893,630 |
| 1 | late-product | 0/1 | 7/1,523 | no | 1,999,653,661 |
| 2 | baseline | 2/3 | 15/0 | **yes** | 1,986,585,582 |
| 2 | from-zero | 0/1 | 7/1,642 | no | 1,999,887,869 |
| 2 | late-product | 0/1 | 7/1,517 | no | 1,997,783,112 |
| 3 | baseline | 2/3 | 15/0 | **yes** | 1,986,401,788 |
| 3 | from-zero | 0/1 | 7/1,638 | no | 1,999,887,493 |
| 3 | late-product | 0/1 | 7/1,515 | no | 1,997,377,475 |

**Possible causes to investigate independently:** deadline slack given roughly two 14–15-second confirmations, honest verifier latency under hostile traffic, replenishment preventing depletion, and stale client tip after incomplete confirmation. These are observations/hypotheses, **not independently proven unique root causes**. No acceptance relaxation is proposed.

## Reproduction and validation

Download the exact GitHub Actions ZIP and run the read-only tool scripts/ci/pq_root_original_native_campaign_triage.py, passing it the ZIP path and the required arguments: --expected-zip-sha256 f3eac6ef3040f889f83bf610e168944976a383c5e115996720da170d3b95ccdb --run-id 42592807143 --source-head 44330b91eb552fd20ef6f2e69bf5e6f1e8f5c0b0 --output triage.json.

Run the negative controls using python3 -m unittest discover -s scripts/ci -p test_pq_root_original_native_campaign_triage.py -v. The reader refuses ZIP/report SHA mismatches, missing/duplicated/reordered modes, inconsistent resource credit and false status promotion. It does not independently authenticate the host. Source and tests were fetched from GitHub commit 00193b5d2f041e3df492eea671855dd7f9c9b51f and executed on ai395 in /dev/shm: **6/6 passed**, py_compile passed. An earlier /tmp attempt had zero free inodes despite 55 GiB available bytes, so the source was not actually tested in that attempt; no unrelated /tmp files were deleted.

## Retained gates

As of the fresh 2026-11-10 read of the delivery head: 13 workflows completed, 8 success / 5 failure. Original campaign, priority acceptance, required baseline, W1 work security and CodeQL export failed. Independently retained fresh anchor/custody and common-restore exclusion, real M15/FinalUse/settlement effects, authorized algorithm migration, and whole-chain quantum lifetime/composition remain open. Keep HOLD, actual_lifetime_failure_bound=null, whole_chain_pq_qualified=false and production_activation=false.