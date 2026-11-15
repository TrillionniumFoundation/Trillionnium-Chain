# BT convergence curated source-lock review

This is a source-consistency review, not cryptographic, availability, model-use
or production qualification. The original seven routes, 44 source paths,
validation algorithm and all false qualification flags are retained.

## Fixed inputs and actual old refusal

- Old reviewed source: `0f0592ace4b08a1d39e1ffad31beee76ddc4fd66`.
- Storage baseline: `040fb0cf460a6db568f0b4ec5ba581add3f2d2ba`.
- Reviewed runtime commit: `8dc744e03d95b0adcf65fc87471b41e89f1287c3`.

All 44 old Git blobs match the old manifest's SHA-256 values. The baseline
checker actually refused with `source lock hash mismatch:` for
`trillionnium/crates/trnm-data-availability/src/cell/discovery/pq.rs`.
That historical failure is retained; it is not a passing check on the baseline.

Forty-one files are identical across all three inputs. One difference already
exists in the storage baseline, and two are introduced by this continuation:

| Path suffix | Change and retained boundary |
| --- | --- |
| `trnm-data-availability/src/cell/discovery/pq.rs` | Historical V3 `auth` / `epoch` / `epoch_directory` modules and exports. Original V2 bodies and V1/V2 CLI dispatch are unchanged. The new modules' full dependency closure is outside this 44-path register. |
| `trnm-data-availability/src/cell/discovery/transport.rs` | Same-path failure observations and test-only phase diagnostics. Original admission/verification ordering, network session, budgets, deadline and directory/cache effect scope are unchanged. |
| `trnm-pon-node/src/store.rs` | Linux-gated grouped V3 reexports. Original account authentication, persistence and release-finality implementation is unchanged; no FinalUse or account-transfer authority is added. |

The grouped implementation uses the existing `native_budget` owner. It does
not attach to the separately registered portable bilateral consumption
settlement owner. Pinning a reexport file is not a proof of its complete call
graph, dependency closure or runtime reachability. Those coverage limitations
remain explicit in the original register.

## Exact reviewed values

The new table is computed from the 44 exact Git object bytes at the reviewed
runtime commit, not from an uncommitted working tree. The table digest is
SHA-256 of canonical JSON containing that source revision and the file map:

```text
921d25105565e9464d164c4985c7c7da839e7ad69aa7249938d8497d96115e4a
```

The three changed SHA-256 values are:

| Path suffix | SHA-256 |
| --- | --- |
| `cell/discovery/pq.rs` | `e51a5e9777578dfa378dbd17db3d79850822c5a5da31dbc99b11936f0cbd48c1` |
| `cell/discovery/transport.rs` | `ce9efc2dc6160bcd1fc47163167deffb5b1f51926e98405bba7f7344fbdf179e` |
| `trnm-pon-node/src/store.rs` | `ae9602b648ceadbc6c8b786fae74048e172572d18bfce41ecceab65728f2bdac` |

The [manifest](../../config/pon/pq-authority-effects-v1.json) keeps all 44 paths.
The [checker](../../scripts/ci/pq_authority_effect_register.py) continues to
require the fixed table, actual regular files, exact route categories and
false qualification fields. Original negative controls remain, with explicit
rejection of the old reviewed revision and the two uncomposed storage branch
revisions added to the existing revision-drift control.

A successful check must still report `status: HOLD`, seven curated routes,
`source_consistency: PASS` and `source_revision_binding:
fixed-reviewed-file-lock-only`. It must not claim complete coverage,
authenticated provenance, a proved call graph, native test execution,
whole-chain PQ security or production activation.
