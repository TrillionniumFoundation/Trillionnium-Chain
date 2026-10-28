# First complete original W1 Composite STARK: observed a54 execution

[Run 40608715148](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40608715148)
completed successfully at source `a54dc7355f58f40784b5a71fe7e73c4062a14951`, tree
`74eb5ac1480096c213c17b72fc06513608f1d6cb`. This is the concurrent original-trace
repair, separate from the later hardened native frozen-claim helper at `febf622c`.

The full 62-segment Composite receipt is 15,862,780 bytes, SHA-256
`0a5336a797c51829ed25d4ec2f1a03f4f56fda4c737a230b493d4abbe96f0ec8`.
The unchanged full guest used 13,364,385 cycles. Actual archived witnesses and
receipts were checked byte-for-byte: the original 26 and the new 36 exactly
match assembly inputs; guest, input, session and final claim match the original
archive. All source-before/after/final records agree. Hosted official Composite
verification succeeded with no development proof, assumptions, PoVW or added
PoW. No cryptographic prover or verifier was executed during this local readback.
The original strict pure evidence reader was rerun and reproduced the hosted
validation result exactly. Details are in [complete-readback.json](complete-readback.json).

## Measured costs and limitations

Native full-proof verification took 1.263286953 seconds wall and 1.263229564
seconds process CPU. All 17 tested malformed or wrong-input cases rejected;
the maximum tested rejection, `last_seal_tamper_wire`, took 1.258724013 seconds.
This is a tested set, not a proof of the global worst invalid input. The fixed
input production native median was 632,993 ns, making full-proof verification
1,995.736 times that median on this host.

The two new 18-segment shards took 1,777.370241128 and 1,734.791377374 seconds
outer wall. Including the original failed 3,500.259693808-second attempt and
assembly, measured generation phases sum to 27,755.580198 process CPU seconds
and 7,014.289256222 independent phase wall seconds. The latter is not parallel
elapsed time. Build, controls, audit and loopback are additional costs. Prior
fresh-trace refusals and the later hardened v2 run are separate attempts, not
included in this subtotal. This does not measure a complete proof from zero.

The real localhost transfer moved the entire receipt plus 160 application
framing bytes in 0.164875764 seconds outer wall. Sender and receiver process CPU
sum to 0.112579 seconds. Including real cryptographic verification before and
after transfer took 2.957411661 seconds. Receipt bytes and hash matched at the
receiver. This is same-administrator IPv4 loopback; no WAN, TCP/IP wire-byte,
adversarial peer, production resource qualification or public-ingress claim is
made. Conditional SDK soundness estimates are retained with their original
model assumptions and do not establish 128-bit post-quantum security.

## Retained raw evidence and durable publication

The original assembly artifact `12784520070` is retained locally in full:
80,366,759 bytes, SHA-256
`bae22e7fab8f5475dc396a4225292f90e582a92558fecf1710e30da0b0d76ecc`.
All 1,684 archive members are inventoried by
[assembly-selected-index.json](assembly-selected-index.json). Selected root
records and logs are included here; they are not described as a full archive.
The original ZIP, standalone complete receipt, both original shard ZIPs, and
the exact full three job logs remain available. GitHub artifact expiration is
2026-11-27, so a temporary artifact URL alone is not durable retention.

The [original planning record](artifact-chunks.json) remains unchanged.
This tree now includes the [exact complete artifact parts and reconstruction
manifest](../pon-w1-complete-artifacts-20261028/README.md): all six original files,
with per-part and whole-file hashes. Construction streamed the unchanged
original bytes without another large local copy. The complete assembly ZIP and
standalone receipt occupy 24 parts; both shard ZIPs and both V3 architecture
ZIPs are retained too. The publication PR records remote byte readback against
the immutable commit; the older plan's status is historical.

An initial local reader refusal at its self-imposed 512 MiB artifact-copy floor
and an initial assertion that concurrent completion events were in numeric
order are preserved. The former was followed by explicit preservation of the
unique successful archive; the latter was corrected to the original runner's
set-based completion rule. Neither changes any proving resource gate or any
hosted run outcome. The original timeout and fresh-trace failures remain failures.
