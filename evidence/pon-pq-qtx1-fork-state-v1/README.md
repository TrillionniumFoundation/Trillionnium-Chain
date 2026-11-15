# PQL1 research-only QTX1 fork-state regression evidence

These records preserve the executed local unit result, exact source Git blobs and
explicit limitations. The executed files match the copies pushed to the research PR.
No current main, native consensus, work profile, difficulty, Hepta final-use, chainwork,
signer authority or production activation setting was changed.

Command: `PYTHONWARNINGS=error::ResourceWarning python -m unittest -v test_pq_branch_execution`
from the staged `formal/pon-nakamoto-v1` source directory containing the inherited
exact `pq_envelope.py` and `pq_transaction.py`. Result: **16 passed, 0 failed**, real
OpenSSL 3.5.5 ML-DSA-65, Linux x86_64 overlayfs, SQLite WAL/FULL, eight independent
spawned local processes, and process exit after SQLite COMMIT before ACK.

The simulated branch `observe_selected_tip()` is a readback/generation CAS, **not**
consensus fork-choice. Genesis account roster, timestamps and the selected branch are
caller-supplied observations, not network-certified authority. This package does not
satisfy Rust native integration, physical power-loss, independent operator, PQ HSM,
W1 quantum-cost, public WAN or product Hepta admission requirements.

`local-qualification.json` identifies the frozen bytes and environment;
`local-unittest.log` is the raw subprocess result. Documentation and evidence
publication after the measured source is not a new test run.
