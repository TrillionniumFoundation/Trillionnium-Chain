# SP27-02 versioned native-window readback

V2 credits a confirmation only when its bound native observation is positive,
its original endpoint is strictly before the original window, and the original
final native gate is true. The old reader remains byte-identical for replay.
No native execution, Host contract, permission, or resource budget is changed.

The actual interface and field mapping are in
[CONTRACT_V2.md](CONTRACT_V2.md), with a byte freeze in
[CONTRACT_FREEZE.json](CONTRACT_FREEZE.json). Upstream code is pinned to Papers
`c49c769fb3b08ee8f60c993c8ca6be2a4600246f`; exact source paths and Git blob IDs
appear in the freeze. Those upstream files were independently read back using
the GitHub API and matched to their retained bytes.

## Reproduce the semantic checks

From the Chain repository root:

```sh
bash scripts/project-preflight.sh
python3 -B -m unittest discover \
  -s research/sp2027/02_receiver_liveness/reader_v2 \
  -p 'test_native_reader_v2.py' -v
```

The ten synthetic tests include the actual frozen SP27-06 analyzer as a consumer.
They are not native experimental observations.

## Consume the separate new CI pair

Obtain the original artifact ZIP from run `43052900246`, artifact `13871459353`.
Its required SHA-256 is
`8b21d753e0ac85ffdca7bc3e0a5f953d4dfffb24c7a10cc9ae394dcfe6590307`.
Point `--zip` at those unchanged bytes; the command validates size, ZIP digest,
source, retained binary, packet identities, report digest and Host readbacks.
Use a new output directory; existing outputs are refused.

```sh
python3 -B research/sp2027/02_receiver_liveness/reader_v2/consume_native_v2.py \
  ci-pair --zip /absolute/path/ci-43052900246-13871459353.zip \
  --out /absolute/path/sp27-02-ci-pair-v2-replay
```

The retained actual consumption is
[CONSUMER_RECEIPT.json](results/ci_pair_43052900246/CONSUMER_RECEIPT.json).
It has one confirmed baseline operation and zero confirmed pressure operations,
each with a planned denominator of one. The original baseline-then-pressure
order remains fixed. One pair does not identify an attack mechanism.

## Recheck the old raw corpus

Use the complete `research/sp2027/06_confirmed_goodput/inputs/native_archives_20261111`
directory from Papers `c49c769fb3b08ee8f60c993c8ca6be2a4600246f`, including
`native_originals.tar.xz` (21,175,420 bytes, SHA-256
`a95d5051d117adfec54bc1d6d47e04f851504234344c0cc076fd57607de3e7a0`).
The command checks every retained member and its origin receipt, then compares
V1/V2 re-derived events and executes the real 06 consumer:

```sh
python3 -B research/sp2027/02_receiver_liveness/reader_v2/consume_native_v2.py \
  historical-corpus --inputs /absolute/path/native_archives_20261111 \
  --out /absolute/path/sp27-02-historical-corpus-v2-replay
```

Without the capsule, raw-corpus impact is `UNKNOWN`; exported text events alone
cannot establish it. When the capsule is available, read the generated
`native_boundary_audit.json` for actual endpoint counts and any count changes.
The capsule contains retained raw report/source/identity members, not the six
complete original ZIPs, all databases, or their native binaries.

## Output authority and independence

Output directories contain the consumed `contract.json`, full `schedule.jsonl`,
`events.jsonl`, raw-boundary audit, consumer summary and per-operation CSV, and
an exact consumer receipt. The two batches stay distinct. Raw inputs are opened
read-only. Byte identities establish which observations were consumed; they do
not authenticate physical execution or prove external observer independence.

The current measurement subagent and current SP27-02 root owner exchange exact
freeze and consumer receipts. No earlier Agent 06 or coordinator acknowledgment
is invented. See [HANDOFF.md](HANDOFF.md) for the remaining coordination boundary.
