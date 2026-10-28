# Exact-source strict frozen-witness W1: actual complete proof

The hardened [run 40611562747](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40611562747)
completed successfully on #525 head
`febf622c7e4e919ad2ee4e0864230ab572f5d5b4`, tree
`f936a01b1391242c2014b162ea2d77ef18769e67`. Both fixed continuation shards
and the strict assembly job `122579832390` succeeded. This is separate
evidence from the earlier successful a54 run; neither run borrows the other's
source identity, proof bytes or measured costs.

The complete Composite receipt is 15,862,780 bytes, SHA-256
`f816a6265004ae1f35c75add10268687e9afd996d8e1eaee9ddc4efa815d32d5`.
All 62 segments preserve the original W1 image, full 49,640-byte public input,
13,364,385 guest cycles, frozen original witnesses and claim. Added PoW,
PoVW, development receipts and consensus authority remain false.

## Independent evidence closure

The original 104,925,197-byte hosted assembly ZIP, artifact `12785720980`,
was verified in memory against SHA-256
`e7a2a4e430c75321b7750eb0209fcfea63d683ff77fcf3fd1263bc39791a6264`.
Every one of its 2,766 members was read and hashed. All 315 retained original
members, including the 62 original witnesses, match the fixed source archive.
The actual original ELF and input compare byte for byte.

The independent reader sliced all 62 serialized segment receipts from the
actual complete receipt. The first 26 equal their original receipt bytes;
the new 36 match both current shard artifacts and the final assembly pool.
Frozen claims equal the claims reconstructed from the original witnesses.
The unchanged strict validation reader recomputed exactly the hosted
`actual_validation` result. Source-before/source-after/source-final agree
on all 6,479 tracked entries and 772,148,228 tracked bytes.

The actual native SDK helper verified the original 26 STARKs in each shard,
the 18 new STARKs in each shard, and **all 62 STARKs again before assembly**,
including exact original claim bindings. These five independent gate records
and their raw terminals are retained. Three native control runs each passed
the actual original-26 positive control and all ten native negatives. Final
official Composite verification and all 17 actual proof-negative controls
also passed. The local evidence reader performed no new cryptographic proof
or native verification; its result is a cross-check of those actual hosted
records and bytes.

## Measured cost and limits

| Observation | Actual measured value |
| --- | ---: |
| Complete native verification wall time | 0.855614899 s |
| Complete native verification process CPU | 0.855570610 s |
| Maximum tested invalid-input wall time | 0.821908140 s |
| Fixed-input native production median | 0.000381967 s |
| This run's two continuations plus assembly CPU | 18,992.254422 s |
| Above plus the original failed proof window | 32,885.624191 s |
| Above plus the separately retained old v1 refusals | 32,887.072672 s |
| All 73 measured outer phases of this strict run, once each | 20,658.740713 CPU s |

The last row includes this run's repeated tool downloads, builds, controls,
execution/export, helper verification, proving, assembly, verification and
audit phases. Internal segment/helper stage costs are already included in
their outer phase and must not be added twice. The earlier failed original
and v1 windows are outside that last row, as are checkout/provisioning,
artifact transport outside phase wrappers and the separately observed
loopback. Earlier a54 proof costs remain separately retained. None of these
figures is a complete from-zero W1 cost or a throughput guarantee.

The final all-62 helper gate itself took 0.829736377 seconds wall and
0.809385 process CPU seconds. Each shard repeated its original-26 gate and
its fresh execution/export; those costs are included, not omitted.

Actual IPv4 TCP loopback carried the complete 15,862,780-byte Composite
receipt plus 160 application-framing bytes. Transport took 0.181903647
seconds wall, with 0.080994 sender/receiver CPU seconds. Including two fresh
official native verifications, the observation took 2.048281335 seconds.
This transfer used a separately pinned local public input; it is a receipt
propagation observation, not a complete self-contained input-plus-proof
certificate or WAN/public-ingress qualification. The separate transparent
Succinct candidate sends its full `PWSR0001` certificate including all input
bytes. The current Composite still exceeds the existing 1 MiB packet cap.
Global worst invalid input, PQ-128/QROM qualification and consensus admission
remain outside this observation.

## Retained package

[manifest.json](manifest.json) identifies every selected member and all four
complete-receipt parts. Concatenate `receipt.bin.part000` through
`receipt.bin.part003` in order and verify the complete size/hash above.
[selected-readback.zip](selected-readback.zip) contains original job logs,
API terminal/artifact records, source identities, phase records/raw logs,
native controls, complete independent readback and its exact executed reader.
It is a new selected-evidence package, **not** the original hosted ZIP.

The full original ZIP was not saved locally because the shared disk was
below the unchanged native-build stop line; its full raw persistence remains
pending. The whole ZIP and every member were nevertheless actually verified
in memory, and the unique complete receipt is retained in full. A temporary
download-URL expiry produced an HTTP 403 on a later readback; that failure is
retained before the successful fresh-reference read. No proof was rerun.
