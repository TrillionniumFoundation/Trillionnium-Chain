# PCS1 bounded PQ Cell swarm: executed local evidence

**Research only; HOLD_NO_GO. Not a production node or proof of whole-Chain quantum security.**

Parent exact commit: 5396fb177fef3b15aa325573f06b45a26bddc738 (#440). This branch adds one downloader, one test file, this evidence and its security contract. It reuses the original exact ML-DSA-65 TPQ1 and PCR1 modules; no consensus, existing QTX1 or Hepta authority is changed.

Executed command from formal/pon-nakamoto-v1:

    PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_cell_custody.py test_pq_cell_swarm.py

**Result: 30 PASS, 0 FAIL.** 15 new test methods and 15 inherited. Linux x86_64 / overlayfs; Python 3.13.5; OpenSSL 3.5.5; SQLite 3.46.1. Exact code blob hashes and raw command output are retained in local-qualification.json and local-unittest.log. Three separate OS processes represented one malicious and two honest providers, all under one administrator; each signature was a genuine OpenSSL ML-DSA-65 operation. Malformed, alternate-model, stale, spoofed-key and truncated packets were rejected. Complete model bytes were verified against a caller-pinned PCB1 SHA-384 content ID before immutable output publication.

A first local exploratory test exposed one real flow-control bug: four in-flight client requests exhausted a two-slot provider. The downloader now bounds client concurrency by actual provider count. This was corrected before the final clean run.

There is no WAN service, no independent operators, long-term custody, geographic replication, erasure repair, production HSM, native Rust blockchain signature deployment, quantum PoN work security proof, stable historical account migration, normal Hepta owner/final-use, paid retention or independent cryptographic acceptance. The only claimed security property is the specifically tested local download's pinned content and signature checks. Do not promote production flags.
