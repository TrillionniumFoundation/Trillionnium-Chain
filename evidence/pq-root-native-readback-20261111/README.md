# PQ Root original native ZIP independent readback — 2026-11-11

**Status: HOLD_NO_GO / DENY_ALL.** This is an independent verifier of retained bytes and reporting semantics, not a substitute for the original native campaign, real production FinalUse receipts, external custody, independent anti-rollback anchor, or a cryptographic proof.

## Exact original source and artifact

- Tested PR: #890; exact head **53e1b98a7955898b9feff4778f7136c0fd0199c8**, tree **094ccb0afc9e7ffbbcc83f85efb6ca4ad8d54aa0**.
- Original [Actions 43104547221](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43104547221), [artifact 13894656010](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43104547221/artifacts/13894656010).
- Artifact ZIP: **71,025,468 bytes**, SHA-256 **9a2c2250205c6a5fe18524451addf56115aafbf951d9a5c2fd3f6056988e437e**, independently matched to the Actions upload digest.
- ZIP: **1,766 members**, 1,765 manifest-pinned payloads, **522,609,424 uncompressed payload bytes**. Each size, SHA-256 and CRC matched, with source-before/after identity.
- The original three native tests each exited **101**; campaign **0/3**, full phases **0/9**, in-window confirmations **3/27**, receiver/client equal phases **0/9**.
- History RPC success **47/47** must not be confused with client import success: **41/47** native import successes, **6/47** failures.
- All three baseline round-zero confirmations reference **one identical fixed-fixture transaction** **c6ee62ac00fdec64b6823d4ddeece3106dc969616053730e52750ecdfb4ebf21**, with **finalized=false**, **execution_authority=false**. Three observations are not three unique externally paid effects.

## Reproduction

Run from the repository root with the unmodified original ZIP:

~~~sh
python3 scripts/ci/pq_root_campaign_readback.py /path/to/original.zip \
  --expected-head 53e1b98a7955898b9feff4778f7136c0fd0199c8 \
  --expected-tree 094ccb0afc9e7ffbbcc83f85efb6ca4ad8d54aa0 \
  --expected-artifact-sha256 9a2c2250205c6a5fe18524451addf56115aafbf951d9a5c2fd3f6056988e437e
python3 -m unittest discover -s scripts/ci -p test_pq_root_campaign_readback.py -v
~~~

The reader verifies exact source and archive identity; manifest coverage and payload digests; unchanged three 30-second phases, 0/24/24 adversaries, 21 blocks and seed inputs; original **0.25 CPU, 2 GiB, zero-swap and 256-PID** host limits and root-owned cgroup parent; original report digests; and the distinction between RPC acknowledgment, native import and finite confirmations. The reader deliberately outputs HOLD_NO_GO even if the bytes are internally consistent.

## Independent tests and limitations

The exact new GitHub code and thirteen synthetic negative controls were fetched and executed on the authorized Hepta host ai395: **13/13 passed**, exit 0. These are negative controls, not an original campaign or independently paid external operation.

The historical [V4 qualification record](../pq-root-continuation-v4-20261109/qualification-record.json) binds source **0d99924005b70b1308bf3e62c53e9300fbb4aac4**, not the present source. Its eight actual domain failure probability bounds are unknown. Independent operators and device/key backup, outside-the-common-restore freshness, native M15/FinalUse and real provider settlement/reorg responsibility, explicit secure migration, all-key/all-epoch and shared-oracle security reductions remain open.

No workload, deadline, criterion, verification safety check or production permission was changed. This PR is stacked on active #890 to avoid collisions. The test and artifact integrity do not close PQ Root qualification.
