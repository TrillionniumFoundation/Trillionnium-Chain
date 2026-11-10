# Independent post-terminal audit candidate

Prepared for fixed S3 b6f39277b39e0b41e552ec4d32c5f8d354c8255b. It has not been
run against real-model output. It never launches a model, writes the repository,
opens an original SQLite database, or archives model payloads. The root must
first confirm the model job's authoritative terminal state and that its producers
have closed. Keep failed runs and all original logs.

The ordinary-main build record is:
/home/qq/work/chain-cell-native-shard-674c72-20261110-validation/checked-test-profile-s3/accepted-artifact.json

Its frozen ELF SHA256 is:
07b711687a223e670280e72c1397e628ef05e97183b60cb9decd66120631226e

The approved optimized test profile constructs an ordinary example binary:
profile.test=false, target test=false, opt-level 3, debug assertions and overflow
checks enabled. Cached dependencies remain disclosed as cached. This does not
establish a performance comparison with prior debug runs.

## Invocation, only after terminal notification

Copy these small scripts to an external control directory, then run:

~~~sh
python3 audit_model_run.py \
  --run-dir /ABSOLUTE/MODEL_RUN_OUTPUT \
  --audit-dir /NEW/EXTERNAL/AUDIT_DIRECTORY \
  --repo /home/qq/work/chain-cell-native-shard-674c72-20261110 \
  --build-record /home/qq/work/chain-cell-native-shard-674c72-20261110-validation/checked-test-profile-s3/accepted-artifact.json \
  --terminal-record /EXTERNAL/AUTHORITATIVE_MODEL_PROCESS_STATUS.json \
  --expected-job-id 1a1c420eb26-cf39-12d \
  --expected-operation 23120317a3cc20853fbcf0de37924311788e251d59395afc1816b4f6b2b7bbdc \
  --expected-source-input-sha 83e4ab28cd84813c1a489c4c53222764b6437edf0eaad8924776c0777ff61835 \
  --producer-closed
~~~

The terminal record must be the actual durable model job process_status result,
either its JSON body or its tool-content wrapper. The flag is an explicit parent
assertion that owners have closed; a JSON file alone cannot prove process liveness
or closure. A nonzero terminal result remains a failed observation.

## Checks and limits

| Evidence | Independent checks |
| --- | --- |
| Funding JSONL | 79 distinct original tag-2 wires; SHA256, fields, framed Task IDs, nonce uniqueness; five batches of at most 16; total 79,100 development units |
| Initial/final native rows | Original source set, exact owner/provider/amount/deadline, reserved status, null output, common anchor per observation; final deadline later than native height |
| Original M12 report | 79 sources, claims and budgets; source bijection; full amounts held; no pending effects or historical payment; initial 67 direct/storage claims |
| CGJ3 snapshot | Copy small DB and any WAL/SHM before opening only the copy; verify namespace, schema, context, record hashchain, snapshot, exact parent/child descriptors and receipts |
| Native recovery | 36 storage and 12 repair groups; 570 storage and 190 repair children; 760 Done; 190 original repair CPU receipts; 95 chunks across three pages |
| Version identity | Recompute TCV1, TCV2, CTS1 and CHB1 SHA512 domain pins from small wires; bind OP, worker, environment, parent and composition |
| Transport | All 30 canonical members, payload/count identity, actual loopback TCP complete readback; no WAN claim |
| Cold restore | Publisher/received/initial delivery/consumer caches and sidecars absent; four original slots 0–3; strong restored content; catalog still entirely zero |
| Two forwards | Exact request hashes, descriptor/content/parent binding, actual logits hashes, scores, positive execution intervals, original wait4/reap; under 300 s, 8 GiB and four threads |

Native funding rows are authenticated Node readback artifacts from the producer,
not a second independent ledger query. The stdlib funding auditor checks exact
signed wire/hash/Task identity and retains original native admission as the
signature-validation boundary. Small metadata pins are independently recomputed;
inner canonical owner parsers are not all reimplemented.

The journal reader cannot establish freshness against a coherent rollback of
both journal and external history. Provider destruction is historical: the audit
compares recorded destruction lengths with current original arena lengths and
actual 190 damage/repair observations; it does not archive a pre-repair payload
copy. Catalog zeroing can be checked directly.

The following are hard audit conditions:

- cold_restore.source_catalog_payload_repaired=false
- cold_restore.root_member_payload_current_readback_after_catalog_overwrite=false

TCA3 payload was deliberately destroyed and not rebuilt. Live funding and
historical Done cannot turn that damaged owner's payload into current complete
custody, future Positive evidence, payment eligibility or qualified settlement.

Every result retains HOLD for future retention/payment, independent operators or
failure domains, real money, WAN, efficacy, FinalUse and production activation.
PASS-HOLD means the listed local research observations agreed within these
explicit evidence boundaries.

The four-thread condition is the original execution grant/configuration, not an
independent measurement of peak operating-system thread count. The strict runner's
CPU/memory cgroup observations remain separate provenance.
