# Original Cell / Hepta controlled execution readback

This packet preserves the result of the **original** Cell workflow run
[40607183163](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40607183163).
It records actual controlled model execution and **no update**. It grants no
production installation, independent efficacy, whole-chain PQ, or independent
WAN acceptance. Local readback does not run any model, Rust binary, Cargo command,
or original test, and does not rewrite the original receipts.

## Exact source and export boundary

| Repository | Original source head | Original tested prospective merge |
| --- | --- | --- |
| Hepta | `50f4fe8089b43dfcea9e2dfce65dc1c042038918` | `6f390d3ebfaefcbd5e82648d5558c5dc2a9a0f72` |
| Chain | `73ffdd94f0b5461a2217a197a3d03a55b37117d5` | `6a84db64dd3b395038b201b6b2cdd9b2b1dbeecb` |

The original Hepta tree is `4318bc2f879a10e049db8d217a95d849c831af9f`;
the original Chain tree is `63b16e486bc78f8515e0925b6b20d033a83855cf`.
Each lane's candidate tuple and source-pair readback identify both repositories.
All thirteen original execution receipts in each lane retain identical clean
Hepta source identities before and after execution. Prospective-merge receipts
also retain the ordered base/head parents and recomputed merge tree.

The later read-only export ran on Hepta
`a3745f5485b87cf313b28a8368f6506994b2dd1b`, in
[40611414916](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40611414916).
Its actual command took **123.37712685 seconds**, exited zero, and did not time
out. That export source and the original tested source are different; this
packet does not qualify the later source by inheritance.

| Original artifact | Complete ZIP bytes | Complete ZIP SHA-256 |
| --- | ---: | --- |
| `12781984588`, source-head | 1,708,544,417 | `adbf3cd2247bb7907c1a5a03899a6953ccd4a3c3e9b7d449c3e0b6aa3dd521d2` |
| `12781233928`, base-merge | 1,708,544,504 | `8674e4291a07cfabbc450bb8addea7b12eb0a2b1a70d84bad082a2b337765997` |

The hosted exporter streamed, length-checked and hashed each **complete** original
ZIP, then independently rehashed its local copy before selecting receipt files.
Actual download durations were **28.801935191** and **91.12027722 seconds**.
Its stored observations preserve the full ZIP digests and byte counts. Each
original ZIP contains 317 inventoried members; 247 were selected from each.

The included export is **3,169,702 bytes**, SHA-256
`dd0a56247fcb72a18873247540ce49bce04cde72dad1fad88f3639c570fb3306`.
It contains 501 members totaling 11,289,064 uncompressed bytes. The local reader
verifies that complete export digest and the exact original length/SHA-256 of
**all 494 selected members**, totaling 11,117,010 bytes. The two original member
inventories, including every selected member's hash and every unselected
member's size/CRC, remain inside the ZIP. Their paths and digests are also in
the summary.

The two 1.7 GB original ZIPs and omitted tensors are **not** reproduced by this
small packet. Local readback verifies the exported original bytes and the hosted
complete-ZIP observations; it does not independently rehash omitted tensor bytes
or reconstruct the original full archives. This is CI evidence, not an
independently administered custody attestation.

## Native execution and all recorded denominators

| Original phase | Source-head wall seconds | Base-merge wall seconds | Actual target tests in each lane |
| --- | ---: | ---: | --- |
| Prepare training and publisher-offline retrieval | 154.843935760 | 160.392920460 | Preparation command; not counted as a native test |
| Original artifact owner publication/recovery | 3.769165725 | 3.570877860 | 1 passed, 0 failed |
| Original native query / FinalUse / terminal unload | 7.790673618 | 7.803219563 | 1 passed, 0 failed |
| Original future-task comparison | 29.463093772 | 30.802664813 | 1 passed, 0 failed |
| Original strict readback | 11.065056382 | 10.939181726 | Readback command; not counted as a native test |

The three original selectors are:

- `real_smollm_material_publishes_and_recovers_through_original_artifact_owner`
- `smollm_neural_read::tests::native::real_smollm_parent_query_original_control_final_use_and_terminal_unload`
- `real_gen2_gen3_forwards_score_only_after_original_holdout_consumption`

Each selector used `--retries 0`, ran one actual test, and has its own retained
execution receipt and log SHA-256. The reader checks the exact libtest success
line as well as the receipt count. The native query binary had **56 unselected
tests** in each lane; the packet retains that number and does not claim the
whole binary was tested.

Each lane has **13 execution receipts, 0 failed receipts and 0 timed-out
receipts**. Their reported test totals are **26 passed / 0 failed per lane**,
including twelve Python wrapper controls and the other named prerequisites.
Across the two lanes that is 26 execution receipts and 52 reported test passes;
the three selected model tests account for **6 actual executions** of that total.
These denominators apply to this original Cell workflow, not every workflow or
the separate native PoN pressure gate. Full commands, durations, source identities,
counts, log paths and digests are retained in `summary.json` and the original ZIP.

## Publisher-offline retrieval and actual model-owner use

Both lanes contain generation-2 and generation-3 transport observations. Each
release closure contains **11 Cells, 269 chunks and 272,190,131 payload bytes**.
The replica acquired all chunks. The publisher was then stopped, and a fresh
consumer with **zero cached chunks** acquired all 269 chunks from one replica
using **280 connection attempts**, with zero rejected responses. Each transfer
received 272,204,931 response bytes; the original full-file dependency checks
and matching pack/materialization digests are retained for all eleven members.
The explicit stopped-publisher negative returned exit 1 and no completion file.

The source profile is `one-host-controlled-native-TCL4-complete-model-and-LoRA-replica`:
loopback peers, one host, no independent operators, and no PQ authenticated
transport. The transport's install, selection, FinalUse and reward authorities
remain false. Content retrieval itself grants none of those permissions.

The original model preparation contains three actual CPU training generations,
each with ten steps, forty supervised tokens and 526 total training tokens.
Generation 2 reloads generation 1's actual artifact, and generation 3 reloads
generation 2's artifact. Full losses, costs, process peak RSS, byte counts and
source pins remain in the receipts. The reported FLOP counter is explicitly
`profiler-supported-operators-only-not-total-work`; it is not a work-hardness or
consensus-weight estimate.

After retrieval, the original `LearningArtifactOwnerService` acknowledged
publication, recovered its named owner and current material exactly, and
observed an idempotent publication retry. A separate controlled issuer exercised
the original native neural owner, three original FinalUse claims, cross-owner
and cross-body-generation refusal, exact journal reopening and terminal unload.
The comparison exercised **66** original FinalUse claims in each lane. These are
actual controlled original-owner executions, not production install authority.

## Measured outcome: no update

Each lane records 32 frozen task rows and the corresponding actual model forwards:

| Measurement | Source-head | Base-merge |
| --- | ---: | ---: |
| Baseline correct | 16 / 32 | 16 / 32 |
| Candidate correct | 16 / 32 | 16 / 32 |
| Identical baseline/candidate final choices | 32 / 32 | 32 / 32 |
| Different baseline/candidate score vectors | 32 / 32 | 32 / 32 |
| Frozen plan before decision before observed result | 32 / 32 | 32 / 32 |
| Original runner decision | `Ineligible` | `Ineligible` |
| Original adoption decision | `no-update` | `no-update` |

The reader independently recomputes correctness from each retained expected
action and actual selected action. Query hashes, unique decision identities,
the frozen task list and temporal order are checked. Raw forward rows and frozen
queries are included in the summary, and the original bytes remain in the ZIP.

The two lanes reuse the **same 32 unique query digests**, not 64 independent
future tasks. The tasks are controlled synthetic arithmetic questions with
synthetic cluster/unit labels. Execution after freezing establishes the recorded
temporal order; it does not establish independent prospective efficacy, broad
generalization, or an uncontaminated external task cohort. The unchanged
`binary-correctness` failure and no-update decision are retained even though the
test that checks this behavior passes.

All original `product_artifact_installed`,
`ordinary_cognitive_context_qualified`, `independent_accepted`,
`prospective_accepted` and `public_reward_eligible` flags remain **false**.
Controlled signer/issuer flags remain **true**. Whole work-package-4 acceptance
therefore remains false: this packet demonstrates the controlled loop and an
explicit no-benefit result, while production bootstrap/installation and
independent evaluation remain separate unfinished obligations.

## Reproduce this readback

Run from this directory with Python 3.10 or later:

```sh
python3 readback.py --output summary.json
```

The reader uses only the standard library. It opens the fixed archive read-only,
does no extraction, makes no network request and imports or executes no archived
code. `summary.json` is deterministic. Local validation consisted of the pinned
archive readback plus Ruff formatting/checks; no Rust, Cargo or model execution
was performed to create this packet.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `readback.py` | 20,182 | `d328edeccf7a93fc30c1b532bec100009b1bb0c545e2dd786524f65f01b124fb` |
| `summary.json` | 260,269 | `efcd5bd09c4b389c8837462423bcd4bd287155c4b4c44cb7a3366c3c504547dd` |

The full original member hash lists are inside
`cell-export/12781984588-members.json` and
`cell-export/12781233928-members.json`. The source archive and every failure or
negative result described above are retained without reclassification.
