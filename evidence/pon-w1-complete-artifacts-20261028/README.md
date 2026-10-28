# Exact complete W1 and solver artifacts

This tree retains all six original files in ordered 4 MiB ranges: the complete
80,366,759-byte assembly ZIP, the standalone 15,862,780-byte complete receipt,
both original shard ZIPs, and both legal-solver V3 architecture ZIPs.
[manifest.json](manifest.json) binds every exact range by byte count, SHA-256
and Git blob SHA, plus each complete file's original size and SHA-256.
All source files remain retained locally. Construction independently read and
hashed every complete source file and every published range without making a
second large local copy.

Reassemble by each object's ordered parts into a new output file, checking each
part's size and SHA-256, then the whole output's size and SHA-256, before opening
the reconstructed ZIP or receipt. The original assembly archive includes all
1,684 original members. Keep the ZIP intact; negative fixture paths must not be
blindly extracted into a live working tree.

These are original observations from source a54dc735 and the separately recorded
solver V3 source. They are not executions of this publication commit or of the
later hardened frozen-witness helper. The original timeout, trace mismatch and
any later run's result remain separate evidence. See the
[complete W1 readback](../pon-w1-complete-a54-20261028/README.md) and
[solver V3 readback](../pon-legal-ticket-v3-readback-20261028/README.md).

Remote commit/tree and byte readback are recorded in the publication PR after
the immutable commit exists. The earlier
[artifact-chunks.json](../pon-w1-complete-a54-20261028/artifact-chunks.json)
is the preserved original planning record, not this tree's live retention status.
