# Recovered V5 objects and a new, explicitly limited readback

After the unpublished workspace was lost, two already-uploaded Git blobs were
recovered on **2026-10-30 UTC**. Both downloads match their Git blob object ID,
compressed SHA-256, and decompressed SHA-256. They preserve the original raw V5
observations and executable bytes. **No new native campaign was executed.**

The unchanged hardened reader's row-validation functions accept the recovered
data in a **new readback**. This does not recreate the original full CLI verdict:
the original capture metadata, outer process receipt, full before/after source
guards, build logs/depfile, and original reader-process receipt are not recovered
here. No replacement receipts were manufactured.

## Exact recovered objects

| Object | Compressed bytes | Git blob object ID | Compressed SHA-256 |
| --- | ---: | --- | --- |
| [Native JSONL](objects/native-v5-stdout.jsonl.gz) | 4,637,185 | `581b49bfef116c952903c6519c9f179c4cdd6214` | `6781436c5acfc932df0aac3d46ee1f04c9e987158d87d74f107ed542529dbe7d` |
| [Native executable](objects/pon_legal_ticket_cost_v5.gz) | 3,574,029 | `93c4e04b5cbf8c4ae180f2258f26a4af06475f68` | `b876349e5f5c3dbebeb50f4c791cfaecc72911d59276383136d1b98b46cc2c9e` |

The JSONL decompresses to **12,493,662 bytes**, SHA-256
`7d2729358a669c56ef47c1056f1ec87b5f8b02a8cebdcf0ae6b7d65532c528fc`.
The executable decompresses to **10,344,808 bytes**, SHA-256
`e363b0c87ccca5a99567ce3fb2c4b759784ccfb724dd295b08e5fae132a3fbbe`.
The recovered executable was checked as data and was not executed. The raw rows
alone do not attest that executable's historical execution or complete build
provenance.

The actual successful retrieval receipts are
[raw attempt 2](retrieval/raw-attempt2.json) and
[binary attempt 2](retrieval/binary-attempt2.json). Earlier connector UTF-8 decode
failures and default-sandbox network refusals are also retained in `retrieval/`.
The subsequent public Git Blobs API downloads used the inherited proxy with
TLS verification and checked both object identities before saving. These are
recovered Git objects, not newly generated native observations.

## What the fresh readback verifies

[reproduce_readback.py](reproduce_readback.py) extracts the unchanged reader and
its seven configuration files from commit
`1d11f875493f8125e36b9adceacb342df108e5e5`, tree
`64b82137eebeb96b572abc62e5fce39af3593200`, into a temporary directory. It checks
the reader's SHA-256
`a8d6c0c48e044a1835b4eedabf5362872ef163ac85e09aa7b4f7d0a3a66d5b99` and invokes
its original `read_rows()` and `validate()` functions without altering them.
The raw begin record's compiled-driver and Cargo.lock hashes are checked against
those two files at the same pinned commit. This is a ten-file, explicitly bounded
readback-input binding, not the lost full native-build/source attestation.

The original fixed Settings/profile, target, template pin, every recorded nonce
challenge including misses, 49,508-byte winning packet length, pairing, roster,
timing, exhaustion and cold-recovery row predicates remain intact.

| Recovered observation | Count |
| --- | ---: |
| Complete JSONL records | 146: begin, 144 cohorts, terminal |
| Searches | 11,844 |
| Attempts | 22,590 |
| First native admissions reported by the raw records | 11,772 |
| Misses | 10,818 |
| Exhausted searches | 72 |
| Distinct packet IDs across paired cohorts | 654 |

These are fixed-parent sibling observations across fresh stores, with paired
fixture bytes repeated across methods and reuse arms. They are not 11,772
distinct chain blocks, chainwork credits, or active-chain rewards.

The raw begin record declares a **600-second native budget**. Its complete
terminal record reports **388.323648870 seconds**. These are retained original
program observations, not measurements made during recovery. The lost outer
capture's separate 610-second contract, elapsed time, exit observation, resource
totals and stable-binary before/after checks are not reconstructed or certified
by this readback. The raw records also do not embed a full commit/tree identity;
matching their driver/lock hashes is not proof of the entire execution source.

[reader/readback.json](reader/readback.json) contains the new scoped result and
all ten input hashes. [reader/process.json](reader/process.json) records the
actual new process: it ran at `2026-10-30T17:31:23.944943+00:00` to
`2026-10-30T17:31:25.121088+00:00`, exited zero, and emitted no stderr.
[reader/core-summary.json.gz](reader/core-summary.json.gz) preserves the full
newly derived core summary. The original reader CLI was not called with invented
capture or source-guard inputs. Its unavailable outer-provenance verdict remains
explicitly unreproduced.

No independent genesis/application replay, full native transcript replay,
hardware attestation, lowest-cost proof, throughput qualification, or production
security conclusion follows. The raw run declares `exclusive_host=false`; no
cross-source speedup is claimed.

## Separately recovered original CI refusal

The original [V5 workflow 40988668738](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40988668738)
was freshly queried after the reset. Both architectures passed their hosted
source guards and Rust 1.95.0 setup, and all **80 Python controls per architecture**
passed: 34 source-integrity, 8 V3 reader, 8 V4 reader, 22 V5 reader and 8 paired
diagnostic controls. Both then failed the module-ordering formatting check in
`trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs`.

Native controls, builds/Clippy, all three native campaigns, and the actual-output
reader were **skipped**. The hosted source guards belong to these hosted jobs;
they do not replace the missing local native-capture guards.

[original-ci/status.json](original-ci/status.json) records the source receipts,
step outcomes and log locations. Complete decoded [x64](original-ci/x64-123845534535.log)
and [ARM](original-ci/arm-123845534292.log) logs, parsed run/job/artifact metadata,
and actual retrieval times are retained. Artifact archive digests remain
**API-reported only**: no artifact ZIP was downloaded during this recovery.
The original CI remains a formatting failure with no CI native-cost result.

## Reproduce only this readback

From a repository containing the pinned commit's Git objects, use a new output
directory. This command does not execute the recovered binary or a new campaign.

```sh
trnm_cost_evidence=/absolute/path/to/evidence/pon-postpublish-recovery-20261030/cost
trnm_cost_review=$(mktemp -d)
PYTHONDONTWRITEBYTECODE=1 python "$trnm_cost_evidence/reproduce_readback.py" \
  --repository . \
  --raw-gzip "$trnm_cost_evidence/objects/native-v5-stdout.jsonl.gz" \
  --binary-gzip "$trnm_cost_evidence/objects/pon_legal_ticket_cost_v5.gz" \
  --output "$trnm_cost_review/result"
```

[files.json](files.json) binds all retained files in this directory, excluding
itself. The recovered raw/executable bytes retain their original Git object IDs;
the fresh readback, retrieval and CI reports have their own current identities.
