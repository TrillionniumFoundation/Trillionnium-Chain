# Explicit paged model research route

Runtime source: `c57a384abe3edf88e79ca7ecbd0de645df4934c6`, tree `a3e6a456d9dd6ae1c6242413611ea1648f66fe46`.

The old and new example entries each passed 11 tests (six shared new research cases, not 22 independent cases). The 11 paged consumer cases, full DA 823 (773 library, 34 integration, 16 documentation), 44 native-PQ Node storage cases, locked/offline graph, strict Clippy/all targets, fmt, source-integrity negatives and repository/link checks passed. Start/end source manifests are equal. The earlier configuration/alignment, manifest-storage and CAS-key quota failures are retained with their own source identities and are not relabelled.

## Single real-model attempt: HOLD

A fresh operation used the original 280,269,602 bytes, 30 manifests and 95 chunks, preserving independently pinned TCV1, TCV2, CTS1 and BEP52 plan. The original clock remained 300 seconds, including catalog ACK, plan construction, repeated RS encoding and all staging/publication. Payload limit 512 MiB, worker RSS limit 8 GiB and four worker threads are unchanged.

The process exited 1 on the original retention deadline at 300.13 seconds, without the external cleanup watchdog firing. It consumed 291.289368 user CPU seconds and 1.870291 system CPU seconds; wait4 maximum RSS was 48,936 KiB for this failed pre-worker path. At exit, 57 chunks were staged and 338 of 570 target publications had observed readback; the next slot remained pending. Custody elapsed 134,350 ms, whole-operation elapsed 300,011 ms. No cold-provider reconstruction or sealed model forward occurred. A top-level legacy stage label remains at original TCA3 retention; the nested paged observation gives the precise failed publication stage.

No unavailable-slot isolation, catalog payload damage or source-cache deletion had occurred. All original partial provider effects, operation identifiers and pending responsibility remain retained. Zero restore callbacks do not mean zero work or a refund. The encoded wire total is 420,450,624 bytes; staging additionally reserves 155,040 manifest bytes and 36,480 CAS-key bytes, totalling 420,642,144 logical bytes. Each provider has 70,414,336 aligned capacity bytes versus 70,075,104 wire bytes.

Six local directories do not establish independent operators or failure domains. Consumer verification cannot settle the original catalog obligation. Paid lifecycle, WAN availability, ordinary Hepta FinalUse and production remain HOLD.

## Evidence identities

`qualification/` retains exact-source gate observations and raw logs for every retained source attempt. `real-model/` retains original inputs, native output, build and process receipts, and a post-terminal file inventory. Compilation and evidence packaging are separate from the original operation clock. Manifest SHA-256 values cover every evidence file except the self-excluding manifest. Source integrity gates remain unchanged.
