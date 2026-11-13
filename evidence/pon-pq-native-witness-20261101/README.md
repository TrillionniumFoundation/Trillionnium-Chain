# Interrupted native PQ candidate: preserved evidence — 2026-11-01

**ARCHIVE ONLY. The native implementation was not delivered. All six whole-chain
PQ gates remain UNQUALIFIED.**

This branch is based on Chain `0e9eac5d2a8cdb0a6f0cc7920f84e290e0d5d0d0`.
It adds an [acceptance target](../../docs/security/WHOLE_CHAIN_PQ_ACCEPTANCE_TARGET_20261101.md)
and this recovery record. It changes no runtime source, dependency, source-corpus
pin, signed schema, budget or activation setting. Earlier local tests in this
archive do **not** qualify this branch's runtime.

## Delivery and interruption

An earlier unpublished local candidate combined the baseline above with research
commit `605af09da34ca72665f822200a2f3e75573e6052`, PNQ2 admission changes and a
native replay-witness experiment. Its complete modified source was not published
before the executor failure and has not been recovered. The archived test names
and partial edit instructions cannot substitute for that source.

The last sealed native test build exited **101** after **272.1876337528229 seconds**.
Subsequent publication writes and sandbox setup reported **ENOSPC**. A later
accessible executor had about 58 GiB free and the original task directory was
absent. The failed build's full stderr was not recovered, so the retained exit code
does not establish its complete compiler diagnosis. No final native acceptance
was run on the last sealed inputs. The
[transcribed observations](observations-transcribed.json) identify exactly which
metadata survived as tool-output observations rather than original receipt files.

Hepta was published before this loss: [PR #4552](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4552),
commit `7ff91a4368bc110c35da789b16916e046f79b42c`, tree
`09483e0039f8f900a403e38f791ca62576f46f38`. Its
[source-bound evidence](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/7ff91a4368bc110c35da789b16916e046f79b42c/qualification/pq-service-recovery-20261101/README.md)
remains available separately. Neither publication nor selected local successes
imply a passing complete CI run, completed ordinary Hepta integration or release.

## What is preserved

| Material | Integrity and interpretation |
| --- | --- |
| 49 exact compressed log files | 1,786,033 compressed bytes; 13,959,161 uncompressed bytes. The manifest records Git blob SHA-1, byte counts and SHA-256 for both representations. Includes failed, interrupted and repeated observations. |
| Six exact historical artifacts and their recovery manifest | Original bytes of the earlier target, two review revisions, build-input review, Cargo manifest and first witness receipt. Their recorded SHA-256 values are checked. They describe the earlier candidate, not this branch. |
| Four partial historical edit inputs | Verbatim tool-input text, with a separate hash manifest. They are incomplete instructions and are not a complete git diff, standalone patch or delivered implementation. |
| Transcribed observations | Explicitly reconstructed from surviving tool outputs; not represented as byte-identical copies of missing receipts. Includes the last exit 101, build identifiers and the environment-loss observation. |
| Current acceptance target | A specification of required system properties and evidence. It is not a security attestation or new activation process. |

The machine-readable entry point is [manifest.json](manifest.json). Original
Markdown/TOML artifacts are retained with a `.txt` suffix so their historical
relative paths and wording are not treated as active documentation or manifests.
Words such as “current”, “delivered” and “final” inside those archived bytes refer
to the earlier working state and **must not be read as present delivery claims**.

The documentation branch passed the repository/Markdown check and 56 existing
negative source controls: 16 claim-guard, 34 source-corpus integration and six
authority-inventory controls. Their [new execution logs and receipt](documentation-validation/source-checks.json)
are separate from the recovered native logs. The unchanged 346-entry PQ source
corpus still reports HOLD / NO-GO; these checks certify neither a native runtime
execution nor whole-system security. No Rust rebuild is claimed for this
documentation-only branch.

The review named `ROLLBACK_INDEPENDENT_REVIEW` is an internal cross-agent review.
It does not constitute an external independent security audit. The first 25-case
witness receipt concerns its recorded earlier binary, not the later corrected
binary or the failed last rebuild. Later phases never inherit that receipt's result.

### Earlier corrected candidate: 79 distinct selected controls

These results can be read from the seven preserved logs listed below. The exact
modified runtime source and executable are unavailable; they cannot be rebuilt
or reproduced from this archive. This is historical execution evidence only.

| Selection | Passed | Failed | Preserved log |
| --- | ---: | ---: | --- |
| PNQ2 | 18 | 0 | [log](build/native-corrected-pnq2.log.gz) |
| Canonical NPQ6 | 12 | 0 | [log](build/native-corrected-canonical-pq6.log.gz) |
| PQ History | 5 | 0 | [log](build/native-corrected-pq-history.log.gz) |
| PQ owner | 4 | 0 | [log](build/native-corrected-pq-owner.log.gz) |
| PQ startup | 14 | 0 | [log](build/native-corrected-pq-startup.log.gz) |
| Classical V2 refusal in the PQ profile | 1 | 0 | [log](build/native-corrected-classical-v2.log.gz) |
| Native witness experiment | 25 | 0 | [log](build/witness-native-corrected-final.log.gz) |

The manifest records all 79 distinct test names. Repeated runs and the earlier
first witness receipt are not added to this total. Earlier failed expectations,
builds and checks remain in the archive. This is not a full native test-suite run.

The recorded corrected-candidate binary SHA-256 is
`30564a0621de1df4e05e1585863c33d8e8584bac7b2bb68d0111e61c6acdd353`.
Its 1,082-entry Rust/Cargo input-manifest digest was
`6fc8df1713bc8ff1fd930dd3254ef5d6564f629c60dbb4e27d7d60b643187201`.
Both are transcribed identities; the executable and complete manifest bytes are
missing. A later formatting build was superseded after review identified additional
embedded source-corpus inputs. The final 1,132-entry sealed manifest digest was
`5bed9a0615675043eb38a3609491478b2d02fd9908bffdd89f6d88c31286a938`;
its full bytes are also missing and its build exited 101.

The native witness experiment covered only `pq_network_resource_v2`,
`pq_network_peer_v2` and `pq_network_request_v2`. Even a reproducible pass of those
controls would not establish whole-database rollback protection, independent
witness durability, service cold restart, private-data confidentiality or WAN.

## Original gates not executed

Both original selectors below remain **NOT RUN IN THIS TASK**. Their source and
parameters are preserved on the baseline; no reduced fixture or extended deadline
is substituted. Earlier historical successes from other branches are not results
for this interrupted candidate.

| Selector | Original input and limits | Result here |
| --- | --- | --- |
| `store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner` | Both backends; 2,100 explicit 4,080-byte custom-genesis cells; original signed transfers and complete readback. Original 10-second gate, 2-second CPU burst, 250 ms/s CPU refill, 100 ms start reserve and two workers. | NOT RUN |
| `store::native_authenticated_tests::native_inactive_page_parents_use_checked_material_without_early_activation` | 256-transfer seed; seven one-packet pages; depth-six confirmation; full State parity and cold reopen. Original 30-second page allowance and History CPU owner. | NOT RUN |

The full original pressure campaign requires its original four-core/16 GiB host
contract. The earlier executor exposed 8 GiB. That mismatch is recorded as
unqualified; it does not authorize changing the contract. Original pressure,
large-state, History, independent WAN and complete Hepta composition remain open.

## Missing material and qualification

The full native witness changes, final RW-10 implementation, PNQ2 source patches,
native binaries, complete source-input manifests and the last build's full stderr
were not recovered. No runtime patch can be authenticated from hashes alone.
Partial edit-input text must not be applied and represented as the tested source.

| Existing qualification gate | Status |
| --- | --- |
| Authorization | UNQUALIFIED |
| Proof PQ-128 | UNQUALIFIED |
| Quantum mining and fork choice | UNQUALIFIED |
| Migration and rollback | UNQUALIFIED |
| Capacity and invalid input | UNQUALIFIED |
| Independent end-to-end | UNQUALIFIED |

The [existing claim guard](../../docs/security/WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md)
and sole [development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
retain HOLD / NO-GO. This recovery branch supplies inspectable surviving evidence
and a concrete acceptance target; it does not complete the requested native repair.
