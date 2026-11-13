# Historical PQN4 / W1 source preservation (2026-11-03)

**DRAFT · RESEARCH ONLY · DENY_ALL / HOLD.** This is a code-and-reproduction-only backup of three exact standalone ChatGPT Library originals. It does **not** modify production Chain, consensus, client authorization, release gates or defaults.

## Byte-for-byte source manifest

| Original Library basename | Size (bytes) | SHA-256 | Git blob SHA-1 |
| --- | ---: | --- | --- |
| `pq_cell_native_verify.c` | 11671 | `13ef40ffdaed08bcf5b29d947efc81c38c0d6d9e480ba8ce842727cdf7f3420d` | `95daaadb18b998e6c1b594dd0b02ae43f91c42ac` |
| `test_pq_cell_native_verify.py` | 12301 | `0b3e6f2c173b9f54fe1a1e0394c4d4239048b1c6503359ba689967e8b218aca7` | `61b1e9688d4db9a3b4e0e04f7721674ed8033931` |
| `w1_four_replay_measurement_20261027.py` | 3974 | `7a88af109a675de394d81c4b8aea22e747c3f0ff63c540ee966e704907369e5a` | `4108b436837f20f11097818da3763b7641db0189` |

The GitHub branch was created from Chain `main` commit `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`. Each uploaded blob was immediately read back and compared with the exact original Git blob hash, including final newline.

## Reproduce without modifying the product

Requirements: Python 3.13+, C11 compiler, OpenSSL **3.5+** (with ML-DSA-65 key generation, signing and verification), POSIX environment, and libcrypto development headers. From **this** directory:

```sh
sha256sum pq_cell_native_verify.c test_pq_cell_native_verify.py w1_four_replay_measurement_20261027.py
git hash-object pq_cell_native_verify.c test_pq_cell_native_verify.py w1_four_replay_measurement_20261027.py
python3 -m py_compile test_pq_cell_native_verify.py w1_four_replay_measurement_20261027.py
python3 -m unittest -v test_pq_cell_native_verify
python3 - <<'PY'
from w1_four_replay_measurement_20261027 import run
result = run()
assert result['production_activation'] is False
assert [case['nonce'] for case in result['cases']] == [0, 1, 2, 3]
assert all(case['full_transcript_tiles'] == 512 for case in result['cases'])
assert all(case['error'] == 'TRANSCRIPT' and not case['verified_work'] for case in result['cases'])
print('W1 independent local false-ticket rejection: 4/4, no Chain node run')
PY
```

The W1 module's historical `__main__` branch writes a report under `/mnt/data` with exclusive create. Import and call `run()` as shown to avoid that host-specific path. The native C test creates temporary ML-DSA-65 key material and uses a real OpenSSL `pkeyutl` signature and Python canonical-wire oracle; no private keys are included in this archive.

## Observed local checkpoint (not hosted CI)

On 2026-11-03, Linux x86-64 / Python 3.13.5 / Debian GCC 14.2.0 / OpenSSL 3.5.5:
- Python syntax compilation: PASS.
- C verifier with 12 full native `unittest` cases: **12 passed, 0 failed** (approximately 3 seconds). Includes 176 signed-header and 217 challenge-byte mutation cases, non-PQ-key denial, unsigned frame/tamper, identity/time and symlink guards, with real ML-DSA-65.
- Independent W1 arithmetic: **4 forged tickets rejected** as `TRANSCRIPT`, 512 full trace tiles per case. This is a Python mathematics reproduction, not native Node/History/reorg validation.
- Original SHA-256 and Git blob hashes matched the manifest; the 3 GitHub stored blobs were independently read back and matched.

## Closure boundaries and hazards

The C tool requires an externally authenticated expected provider, release, catalog and requester identity. Passing its local fixtures does not qualify trust-root distribution, on-chain semantic authorization, custody correctness, symlink-safe ancestor traversal, resource-exhaustion/WAN DoS, external key revocation, W1 proof security, whole-chain PQ-128, final-use or production activation. The W1 replay script does **not** invoke the native Chain node or test honest service against 16 hostile producers.

No system blocker is closed from this preservation PR. Retain the original Library sources and any unsynced dot-host worktree until the **entire** Library and active-branch inventory has been compared, including archives and non-project assets. Do not merge/activate solely on this isolated result.
