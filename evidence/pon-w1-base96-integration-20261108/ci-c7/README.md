# C7 post-push CI and event identity observation

This is one bounded read-only observation after C7 was pushed. It is not a CI run, test execution, source change, merge, or workflow dispatch. The previously frozen pre-push observation is copied byte for byte under `prepush-observation/`, so its C6 105-check snapshot remains available alongside this later C7 readback.

## Observed identities

C7 is `40a3a45d6b8afc5c4706c5235fec47634f4aabbe`. The two permitted PR API reads both returned a null `merge_commit_sha`. The final API response reports head C7, base `96a241bf43f6a46d35dfb3d4ced9594ed8ceca75`, `mergeable=false`, and `mergeable_state=dirty`. These are observations at the recorded response times, not permanent branch properties.

Actual Git refs independently show target base `9417e495165865ef6c1288b39084856e31020634`, candidate branch and PR head C7, and the retained merge ref `7b4a63b6f08687e93270407772951aa71087ca3d`. The immutable object for that retained merge has ordered parents `[96a241bf43f6a46d35dfb3d4ced9594ed8ceca75, 2bdd252aa6c300b7431b9ee897b254b7953cf562]` and tree `d73e57c9e7a5764a1ab33540c97af587bb6e4a69`. Its second parent is C6, so this object is not treated as a C7 merge.

The exact immutable-base comparison reports `merge_base_commit=96a241bf43f6a46d35dfb3d4ced9594ed8ceca75`, status `diverged`, ahead 13 and behind 2. `06-base-vs-c7-compare-projection.stdout` is explicitly the recorded jq projection of that REST response; it is not a locally qualified merge tree.

## CI and expected event tuple

The exact-C7 check-run endpoint returns total_count 0 and no rows. The subsequent one-shot exact-C7 workflow-run query also returns total_count 0 and no rows. Both requests succeeded. Thus no new job log carrying `EXPECTED_BASE`, `EXPECTED_HEAD`, or `EXPECTED_MERGE` was available within these observations. The expected event tuple remains explicitly unknown/null.

The REST base field, current Git target ref, and old merge parents are separate observed facts. None is substituted for an unobserved CI event declaration. No source-identity guard was changed, no expected value was reconstructed from a merge, and no silent fallback or retry of CI occurred.

Zero observed C7 checks or runs is not a passing CI result. This observation does not establish a permanent absence of workflow events or a unique cause of the lack of visible runs. The API's conflict state is recorded without using it to invent missing events or job outcomes.

## Timing and retained evidence

`snapshot.json` is the original post-push readback, with independent nanosecond start/end times for its constituent commands in `read-commands.json`. The later workflow-run request has its own interval in `07-c7-workflow-runs.command.json`. These reads are not atomic. Exactly two PR API reads were made; no further polling was performed.

Raw API output, raw `git ls-remote` output, the immutable merge object, exact-head check list, workflow-run query, command receipts, read scripts, and actual completed helper witnesses are retained. `summary.json` and `event-tuple.json` distinguish observed identities from unavailable expectations. The nested pre-push snapshot and its original manifest are unmodified.

This archive makes no new C7 lifecycle, full-proof, merge-tree, resource, provider-payment, deployment, or production qualification claim. No experiment or operation was started by this reader.
