# PoN standalone research source — reproducibility record

**Status:** historical research-only source; NOT active consensus; not a release or a security/production qualification.

Recovered on 2026-11-03 from the exact ChatGPT Library root file snapshots. 14 source/test fragments were transferred by raw byte-preserving Base64 Git blob upload. Each returned Git Blob SHA matched the original file SHA. This directory lives on an isolated recovery branch; no installed consensus module or production path is modified.

## Execute self-contained local checks

From `source/` (Python 3 and system SQLite required):

```bash
python3 -m py_compile *.py
python3 sqlite_pre_read_probe.py
python3 sqlite_postwrite_reproducer.py
python3 -m unittest -q test_daa_equal_work_recovery.py
```

Observed in the recovery sandbox (not the native Chain repo): SQLite pre-read 8/8 predicates PASS; two SQLite post-write reproduction cases completed; 11 equal-work research unit tests OK. These tests use a synthetic/local research oracle, not live W1 network, native protocol-verifier acceptance, production signed leases, or hostile network reorg.

Several `*_append.rs` items are context-dependent Rust fragments requiring integration into the historical codebase and validation under the correct imports/feature flags. `test_c_asert_differential.py` also depends on external fixtures/tools; the commands above do not assert its completion. Reproducibility therefore applies only to the named locally executed checks, with explicit additional prerequisites for everything else.

## Original full Git blob SHA and byte sizes

| File | Git Blob SHA | Bytes |
|---|---|---:|
| `asert_property_audit.py` | `7afabbd3ba6ea8a937462b18b4fd638db0b2c373` | 1499 |
| `check_native_side_effects.py` | `85f4c2db9ac8e464be56bd320ab11388f3f9102e` | 5713 |
| `daa_equal_work_recovery.py` | `c750081fdf9685e9a5df725a44170626774c97fc` | 11362 |
| `next_rust_continuity_32slot_append.rs` | `26bb80b5fbdcdb90ac7137b5bba0d21703435c2b` | 4068 |
| `next_rust_q4_32slot_append.rs` | `1639da89ef122d09dc9f6b2e2f6bd13b846ddc1c` | 4996 |
| `pon_research_v2_rust_daa_incremental_append.rs` | `8c71cfe6a790a9187532bddcf23df2c5ddfb5d92` | 13040 |
| `q4_cold_audit_smoke.py` | `2b529a04c4a8007c4e7500ca4bf57437f333489b` | 5595 |
| `rust_consensus_append.rs` | `12a08ab3d373e9bbf5edbc52c22d124bbe7f6bde` | 9368 |
| `rust_continuity_append.rs` | `e0375bb82a3d89d52ba281e48a2c7074a1d575a4` | 4694 |
| `rust_daa_incremental_append.rs` | `4cb9706e4790b147f97a0a1873ff8371b69ec25f` | 13080 |
| `sqlite_postwrite_reproducer.py` | `cb707e8ebbb5d7badeade9d4668fdf87e3db0f6b` | 2640 |
| `sqlite_pre_read_probe.py` | `4346208638e7620a3b0a3c1941da3425bf0ab129` | 2639 |
| `test_c_asert_differential.py` | `6c7db228a8d178d7373049b1332103b0721d2f90` | 3813 |
| `test_daa_equal_work_recovery.py` | `66da64123d310cdd7001dd50e1b18eb29d1efab8` | 7318 |

## Recovery boundary

- Parent commit: `362accd5e3a647d4537fb5d71672c80671597ec2` on `recovery/library-w1-daa-20261103` before recovery.
- Raw research logs, model weights, runtime caches and private evidence were **not** uploaded.
- Do not interpret source presence as scientific or security acceptance.
- Do not delete original Library files until all other source candidates and dot-host unpushed commits have been audited and remotely verified.
