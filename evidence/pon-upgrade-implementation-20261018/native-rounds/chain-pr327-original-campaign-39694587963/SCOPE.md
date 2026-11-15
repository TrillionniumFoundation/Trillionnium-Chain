# Original three-run cloud campaign

Measured head: `9e705ccf75b7318dcc4bda4815956f58beb10e72`. Measured tree:
`521ae87a28060d545979069b189eebbc74a71fd8`. The original execution was triggered
by PR #327 against the then-frozen #323 candidate. Its later fast-forward into
#323 preserves that source identity; it does not turn the former PR's merge
checks into main-target prospective-merge checks.

[Workflow run 39694587963](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39694587963)
completed the three predeclared original campaigns. Artifact `12391561439` is
67,642,508 bytes with ZIP SHA256
`e6aa9b46dc0eaf06ba13615f8973637474eddf445d141bb0d3460cc62a03b7f0`.
The 8,471,112-byte Rust 1.95 release executable has SHA256
`efaeadc30b476271923af6b51b6149e71f882b0088f6fbdb7bc2609235aa7f61`.
Source and binary observations are unchanged before and after all attempts.
The AMD EPYC 7763 host reports four logical CPUs; inherited cgroup limits are
400% CPU, 16 GiB memory and nice 10. Limits are ceilings, not physical reservations
or evidence of independent operator custody.

## Fixed inputs and observations

Each complete attempt retains 1,024 signed seed transfers, four seed blocks,
21 business blocks per mode and the original baseline/from-zero/late-product
order. Each mode lasts 30 seconds with 0/24/24 requested attackers. No deadline,
load, credit budget, depletion threshold or assertion was relaxed.

| Observation | Retained result |
| --- | --- |
| Three complete campaign wall times | 98.1606, 98.4513, 98.4255 seconds |
| Original finite criteria | Passed in all three attempts and all nine phases |
| Timely honest block-submission observations | 189 / 189 |
| Timely depth-six confirmation observations | 27 / 27; latest 15.284647334 seconds |
| Hostile phases with original credit depletion | 6 / 6 |
| Hostile confirmation rounds overlapping an observed depletion interval | 9 / 18 |
| Hostile client calls | 18,596: 18,453 explicit WORK refusals, 143 errors, zero accepts |
| Receiver full-work failures | 18,459; a separate receiver denominator |
| Unique submitted body digests across repeated fixtures | 21 |
| Unique observed transaction and included-block identities | Three each |

The experiment resets chains and reuses fixed business identities. Submission
and confirmation observations must not be relabeled as globally unique
transactions. The total campaign wall time cannot convert those observations
into sustainable business TPS. Depletion overlap means a retained observed
sample interval falls inside a round; it does not prove continuous saturation
or that every hostile round completed under depleted credit. All confirmations
retain `finalized=false` and `execution_authority=false`.

## Retention and verification

[retention.json](retention.json) declares the exact retained subset and the
original complete file-list hash. Top-level original metadata/logs and all three
raw reports are retained without rewriting. Reports use lossless deterministic
gzip. The original 910-file manifest is retained; databases, the executable and
per-actor files remain in the complete original ZIP, rather than being duplicated
here. A subset read must not claim to have hashed those omitted bytes.

The reader checks declared lengths/hashes, bounded gzip decoding, original
source/resource/build identities, real command/test-result records and independent
phase derivation. It does not rerun the test, attest a host, replay consensus or
verify signatures. Its counterexamples mutate copies of real retained inputs;
they are parser tests, not additional experiments.

```sh
python3 scripts/read_original_native_campaign.py \
  --artifact-dir evidence/pon-upgrade-implementation-20261018/native-rounds/chain-pr327-original-campaign-39694587963 \
  --expected-manifest-sha256 12406cc156e57c130fa14af2b50b386031ec3640ce7f0234ed5bc9f0a700aac3 \
  --expected-head 9e705ccf75b7318dcc4bda4815956f58beb10e72 \
  --expected-tree 521ae87a28060d545979069b189eebbc74a71fd8 --retained-subset
```

Omit `--retained-subset` and point to an extracted complete ZIP to verify all
910 original files, including the executable bytes. Full-file verification
still does not supply independent custody, WAN, cryptographic hardness, model
efficacy, deterministic finality, current-source applicability or production
authorization. Earlier failed campaigns remain unchanged in their original
archives.
