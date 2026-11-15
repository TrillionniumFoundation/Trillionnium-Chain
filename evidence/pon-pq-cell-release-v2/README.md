# Post-quantum Cell release rev2: no synthetic authority carrier

Previous [v1 evidence](../pon-pq-cell-release-v1/README.md) remains immutable
for its original exact source blobs. This revision strengthens the result
type: `ResearchObservation` returns only manifest and observed reviewer
identities and counts. It has **no adoption_authorized, release authority,
independent acceptance or Final-use property at all**. Tests explicitly
reject the old assumption that a digest/signature check could issue one.

**Executed exact Git blob sources** (checked with local `git hash-object`):

| File | Git blob SHA-1 |
|---|---|
| `pq_envelope.py` | `27e40b04ac8eaa381ad4dc017f23f226f99f3f41` |
| `pq_transaction.py` | `c8ac18136ef447eaa958111392eee05f92819aac` |
| `test_pq_transaction.py` | `9b7a5a8e469db90f1ba8ce8c694b133521fb3fd2` |
| `pq_cell_release.py` | `6ac001369795b84c0cbad23daa0842225e617a3d` |
| `test_pq_cell_release.py` | `9b3df51ce6bb48ce07346a67223baa86277de1f3` |

Actual local command: `python3 -m unittest -v test_pq_transaction.py
test_pq_cell_release.py`, Python 3.13.5, OpenSSL 3.5.5, Linux x86_64.
**23 tests passed, 0 failures, 5.033 seconds**.
[Unmodified raw run](combined-regression.log), Git blob
`fb54027eac17e9b44023d45cbfe8b72bfa341495`, matches the original
local execution bytes. This remains an offline, locally controlled
OpenSSL experiment; no Rust toolchain or full repository checkout was
available. No deployed secret, external evaluator, public P2P network,
Chain generation-fenced replay, independent audit, or PoN quantum-work
hardness/security acceptance is claimed.
