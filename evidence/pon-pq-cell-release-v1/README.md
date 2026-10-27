# PCB1 — real OpenSSL ML-DSA signed Cell release research

Development-only, stacked on QTX1 and TPQ1 research. The procedure does
not change the installed Chain/Hepta runtime, signatures or live release
authority; no public peer network, persistent Cell custody or independent
source-owner/evaluation provenance was used.

On isolated Linux x86_64 / Python 3.13.5 / OpenSSL 3.5.5, using **the exact
SHA-identical Git blob content** of the three modules listed below:

| Exact file | Git blob SHA-1 |
|---|---|
| `pq_envelope.py` | `27e40b04ac8eaa381ad4dc017f23f226f99f3f41` |
| `pq_cell_release.py` | `ced847d3047ff93907ad82dd2ec1f0df7bfe19a5` |
| `test_pq_cell_release.py` | `12925f4696d438bcf15a4bf008820a1c952b3dfd` |

Run `cd formal/pon-nakamoto-v1 && python3 -m unittest -v test_pq_cell_release.py`.

**Observed: 11 tests, 0 failures, 1.384 seconds.** The 358-byte manifest
sample has SHA-384-domain manifest ID
`b6ee54065376c13e85afc5bd518606ff33a2567d48aaa1518faff84fe3f092ea9a558649bf2bbd86ea1c38f9036cb068`.
A manifest + two review TPQ1 frames + one release TPQ1 frame is 10,819
bytes before any public keys or content; this is **not** a production
transaction size, signed evaluator quorum or deployment benchmark.

[Raw log](local-unittest.log) and [machine report](local-qualification.json)
are included. The five fresh test keypairs and the allowlist have one local
test owner; their independent administrative identities, task outcomes and
model value are **not** established. The `ResearchObservation` explicitly
does not authorize adoption. Production and quantum security gates stay open.

## Combined exact-blob regression

The same five exact Git source blobs (`pq_envelope`, `pq_transaction`,
`test_pq_transaction`, `pq_cell_release`, `test_pq_cell_release`) were
executed together with `python3 -m unittest -v test_pq_transaction.py
test_pq_cell_release.py`: **23 tests / 0 failures / 3.144 seconds**.
[The combined original log](combined-regression.log) has Git blob
`c969bd607505f8dea9fbe1797fca1790c2b09353`. This only confirms
offline test composition, not native consensus or independent product
qualification.
