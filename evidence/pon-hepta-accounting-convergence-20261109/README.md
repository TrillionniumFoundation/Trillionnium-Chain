# Hepta accounting convergence: C1 evidence

**Qualification: `HOLD_NO_GO`.** This packet archives source provenance, the
completed validation, the interrupted gate attempt, and recovery of the
original records. It does not activate consensus credit or production behavior.

## Source identities

| Role | Commit or digest |
| --- | --- |
| C1 source / PR #832 | `e8f81ca15634d0393e7bc6257193b4dbe88d9b2e` |
| C1 tree | `563992ef5bd3db98d95b7e249ea67cbbec2e2978` |
| C1 parent / PR #824 source | `fd1cf356fcc557dbd2aee2318ffc524d17aa02f0` |
| Selectively reused PR #828 source | `3388a6810b5ae8f41f238f878d56bcc5669bc8b9` |
| Original retained native build source | `91dd3082633ea0b3a5ec9b0ed91f28603229be01` |
| Unchanged native tree | `1305c43ca8891f6a07fcec493c32f007679e2416` |
| Existing source-inputs.json SHA256 | `bc53319e019624efec86e8f8a4228035dd231b229dd9c61613349bc3f4a0c7c6` |

The inherited [source-inputs.json](source-inputs.json) is unchanged. It records
nine byte-identical selected files and explicitly sets `source_is_ancestor` to
`false`. This evidence child changes files only in this packet directory.

## Recovery and evidence classes

The execution workspace became unavailable during the final gate sequence.
During that interruption, the source and a reconstruction of observed results
were preserved on `ai395`. The workspace subsequently recovered, and the
original Python, native rerun, source-check and full-source records were copied
without rerunning those tests. Thirty original stdout/stderr hashes match the
hashes in their original summaries.

| Location | Meaning |
| --- | --- |
| [raw/local-original](raw/local-original) | Recovered original local records, including test streams and the incomplete initial gate receipt |
| [local-recovery-manifest.json](local-recovery-manifest.json) | Original/stored sizes, SHA256 values, compression mapping and recovered counts |
| [raw/remote-setup](raw/remote-setup) | Original h process payloads for failed and successful checkout/import/preflight preparation |
| [remote-recovery-manifest.json](remote-recovery-manifest.json) | Exact remote-file identities and packet paths |
| [observations-before-recovery](observations-before-recovery) | Byte-preserved closure pack, reconstructed summaries and draft description written while local logs were unavailable |
| [recovery-status.json](recovery-status.json) | Current recovery and gate status, superseding earlier availability statements |
| [packet-manifest.json](packet-manifest.json) | Hash inventory of the archived packet files |

The earlier summaries remain reconstructions of tool observations. They are not
relabeled as original local command receipts. Their statements that local raw
logs had not been transferred, that publication had not occurred, or that no
evidence child had been created describe the earlier snapshot. Current status
is recorded separately. Both failed and successful remote setup streams are
complete from offset zero to EOF; those records establish preparation only.

The two dependency-graph stdout files and four native stdout files are stored
as deterministic gzip files in the expanded packet. Their uncompressed SHA256
values match the original command summaries. The raw archive retains the four
native stdout files under their original names, including terminal blank lines.
The two prior runner scripts have `.py.txt` suffixes as archival text.

## Previously completed validation

| Validation | Actual observed result |
| --- | --- |
| C1 Python: fixed packet identity | 50 passed |
| C1 Python: offline fanout reanalysis | 21 passed |
| C1 Python: service / NoUpdate | 38 passed |
| C1 Python: legal strategies | 19 passed |
| C1 Python: low rank | 6 passed |
| C1 Python total | 134 passed |
| C1 Python using the retained actual grouped CLI | 14 passed, zero skipped |
| Retained native binaries: crypto / settlement / Node v2 / NoGain | 186 / 71 / 4 / 2 passed; 263 total |
| Locked offline default dependency graph | 26 workspace members, 176 packages |
| Locked offline all-features dependency graph | 26 workspace members, 181 packages |
| Rust 1.95 formatting, CI contract, distributed source inventory | Passed |
| Original full raw-source identity check | 26,132 tracked entries, 2,495,315,152 bytes verified against C1 |

The native binaries were originally built at `91dd3082633ea0b3a5ec9b0ed91f28603229be01`.
They were actually rerun after native Rust/toolchain source equality with C1 was
checked. `fresh_cargo_build` remains `false`; a new evidence commit does not
change that build provenance. Individual binary and stream hashes are retained
in [the original native summary](raw/local-original/unchanged-native-rerun/summary.json).

The earlier Python source manifests cover 4,890 materialized entries and record
the 21,242 historical evidence entries then omitted by sparse checkout. The
later [original full-source report](raw/local-original/full-source-before.json)
records the complete C1 identity check. That later identity check executes no
tests and does not change the scope of the earlier source manifests.

## Interrupted and resumed required gates

The initial recorder file for `source-negatives` remains `status: running`, with
`exit_code: null`. No initial log or terminal summary was recovered. Session
58416 could not be resumed. This incomplete attempt remains archived and does
not count as a successful gate.

| Resumed gate | Result on exact C1 | Original receipt |
| --- | --- | --- |
| Source-integrity negatives | 43 tests passed | [source-negatives.json](raw/resumed-required-local/source-negatives.json) |
| CI contract negatives | 164 tests passed | [ci-negatives.json](raw/resumed-required-local/ci-negatives.json) |
| Corpus negatives | 57 tests passed | [corpus-negatives.json](raw/resumed-required-local/corpus-negatives.json) |
| Corpus identity | 899 exact blobs and 6 upstream heads checked; qualification remains HOLD | [corpus-identity.json](raw/resumed-required-local/corpus-identity.json) |
| Repository links and boundaries | 6,000 local links checked | [repository-links.json](raw/resumed-required-local/repository-links.json) |
| Strict Clippy | Rust 1.95.0, locked/offline, workspace, all targets, all features, `-D warnings`: passed | [strict-clippy.json](raw/resumed-required-clippy/strict-clippy.json) |

All six resumed commands have original recorder receipts with matching complete
before/after C1 source identities: 26,132 tracked entries and 2,495,315,152
bytes. Strict Clippy ran in a new target on `ai395`; its durable process
`1a1be9e96a7-5e21-1b7` completed with exit zero and complete output. This actual
C1 lint build executes no native tests and does not reattribute the retained
native binaries. The resumed Clippy provider and original local native-rerun
provider are separately recorded with their actual SHA256 values.


Only the previously incomplete required gates were resumed in a new receipt
namespace. The 134 Python tests, 263 retained-native tests and 14 actual CLI
checks above were not rerun for this packet.

## Boundaries retained

Owner fences, zero consensus credit and `HOLD_NO_GO` remain unchanged. The
reference settlement metadata is in-memory state and does not establish a
durable native effect authority. Evaluated `NoUpdate` retains its qualified
base service fee; improvement bonuses and consensus credit remain separate.

The inherited public-readiness reader mismatch, QROM lifetime source pin,
QROM implementation fixture bound and resource-campaign gaps are preserved.
No historical pin is changed to make a check green. Cheapest legal classical or
quantum lifecycle cost, joint time/difficulty/credit, independent learning and
retention evaluation, real funding/effects, WAN/public service and independent
recovery qualification still require their own evidence. The retained factored
fixture is not a speedup or minimum-cost proof.

## Download and verify the raw records

The [raw-records.tar.gz](raw-records.tar.gz) archive contains 100 original
record files (186,041 compressed bytes). Its SHA256 is:

`cd71c0c6571e995cf8351c360bcb142a17c9b19fef0db66e8f33779384bd7798`

The [raw-archive-index.json](raw-archive-index.json) lists every archive member,
its stored byte count and SHA256. The recovery manifests retain the original
uncompressed graph hashes. The earlier PR draft is preserved as `.md.txt`
archival text with its original bytes and original link context.
