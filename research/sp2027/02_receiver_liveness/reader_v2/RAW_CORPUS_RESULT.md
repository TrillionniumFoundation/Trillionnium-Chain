# Historical raw-corpus boundary audit: no count changes observed

The V1 inclusive endpoint predicate is a real semantic mismatch with the native
strict deadline and its later final clock check. **The six verified historical
archives do not contain a record that changes their credited count under V2.**
This conclusion was obtained from original ZIP members, not inferred from a
prior analysis summary or conversation.

## Verified scope and results

The direct audit independently rehashed all six original ZIPs, all six retained
native executable byte streams, and all 53 selected original source/report/
identity members (549,630,449 bytes). It reconciled source commit/tree identities
with the original native manifests, decoded the prepared business transactions,
and ran both reader versions before consuming the retained SP27-06 interface.

| Item | Actual result |
| --- | ---: |
| Original archives | 6 |
| Original retained native executables rehashed | 6 |
| Selected original members rehashed | 53 |
| Phase strata | 35 |
| Planned business operations | 93 |
| Recorded confirmation attempts | 45 |
| Positive native confirmation observations | 13 |
| Timely confirmed operations | 13 |
| Observed but unconfirmed operations | 32 |
| Unstarted planned operations | 48 |
| Recorded endpoints exactly at the cutoff | 0 |
| Positive observation below the cutoff with a false final gate | 0 |
| Missing native gates among recorded attempts | 0 |
| Phases whose credited count changes between V1 and V2 | 0 |

The phase/operation totals describe corpus coverage; they are not a pooled
success-rate estimate. Trials from different binaries, profiles and phases are
kept distinct. This readback executes zero new native experiments.

V1 and V2 regenerated identical complete planned schedules and event streams.
Their event stream also exactly matches the prior exported bytes, SHA-256
`6b042ec6f4abb6dcdfd6f59985c4aaae8aeb88b79018005c2eac96ede95a28ba`.
The schedule digest is
`96c7ccbc5edb58abb60cdbfa6e7258cf0f3f0fb31c0809e4c7f569bd86bff0c7`.
The actual SP27-06 consumer's summary digest is
`28902d688c6d81147aac2a0940dea8a1f4c268b52e9374248ea5513718a6b5eb`.

The complete receipts and phase-level records are:

- [Consumer receipt](results/historical_original_zips_v2/CONSUMER_RECEIPT.json),
  SHA-256 `de75103e48dc41839b34b4aec8cb7fe0d6649c3fcbd652624dd065e2ee3ce71d`.
- [Raw boundary audit](results/historical_original_zips_v2/native_boundary_audit.json),
  SHA-256 `66ef6c396457f4bac102acf1a11f5058c75ba957f3cee90a3843b64c26f659de`.
- [Per-operation consumer ledger](results/historical_original_zips_v2/consumer/operations.csv).

## What the repair establishes

The old standalone predicate uses `endpoint <= T`. Its full pair/campaign
readers additionally require agreement with the original native final flag.
Therefore a coherent native observation with `endpoint < T` but final
`gate=false`, or an endpoint exactly at `T` with `gate=false`, could cause the
old reader to refuse analysis. It is inaccurate to state that a historical
overcount was measured. No such affected row was found in this audited corpus.

V2 retains the endpoint and original gate separately, requires `< T` and
`gate=true` for timely credit, and accepts a coherent false final gate as zero
credit. A contradictory positive gate at/after `T` remains refused. The
synthetic controls exercise these distinctions and the actual retained 06
consumer; they remain separate from native data.

The unchanged original reader, the two-phase new-CI sample, and its root ACK
remain intact. The new pair's baseline `1/1` and pressure `0/1` are a separate
fixed-order batch. Neither this corpus audit nor the endpoint repair establishes
the cause of its service failure.

## Reproduction from original ZIPs

The direct route needs the six filenames and digests recorded in the consumer
receipt, plus the original text inputs from Papers
`c49c769fb3b08ee8f60c993c8ca6be2a4600246f`. It does not require the reconstructed
XZ capsule. Run from the Chain root with a new output directory:

```sh
bash scripts/project-preflight.sh
python3 -B research/sp2027/02_receiver_liveness/reader_v2/audit_original_zips_v2.py \
  --zips /absolute/path/historical-ci-zips \
  --inputs /absolute/path/native_archives_20261111 \
  --out /absolute/path/historical-original-zips-v2-readback
```

The exact supplemental reader digest is recorded in the result's
`input_identity.supplemental_reader_sha256`. The original
[contract freeze](CONTRACT_FREEZE.json) remains
`fd063440ee6d10ccaaf28ca70a0fc371e1a1a77cd67ac52f95f1cef885863920`;
this supplemental archive route does not alter it.

The earlier [exported-only attempt](results/historical_exported_events_replay/EXPORTED_ONLY_RECEIPT.json)
is retained. Its creation-time raw-corpus `UNKNOWN` describes the then-missing
capsule and is superseded for boundary-impact coverage by this direct original-
ZIP audit. No earlier result file was relabeled as a raw replay.
