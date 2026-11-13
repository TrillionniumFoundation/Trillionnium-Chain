# Public-table, LDE and MMCS stage diagnostic

Measured instrumented source 0512570ceeffa078522eb2009c92a0f18c67aa64 extends the isolated diagnostic641de.
Exact original uni-stark and FRI crate archives were checked against Cargo.lock
before separate path copies. Timers preserve original computations; cache-event
logging was removed. Both independent setups/PCS, fresh challengers, charged
fresh owner and native replay remain.

| Stage | Degree bits or LDE shape | Seconds, one observation |
| --- | --- | ---: |
| public_table | 13 | 0.001837113 |
| lde | [(32768, 139)] | 0.012502113 |
| mmcs_commit | [(32768, 139)] | 0.101948035 |
| public_table | 14 | 0.004117890 |
| lde | [(65536, 180)] | 0.026524660 |
| mmcs_commit | [(65536, 180)] | 0.259868835 |

Public-table covers air.preprocessed_trace only. LDE covers the PCS iterator,
coset extension, bit reversal and row-major materialization. MMCS commit covers
Merkle row hashing, tree construction, allocation and retained prover data; it
is not pure hash instruction timing. The three timers are separate scopes.
Do not add phase medians or nested receipt times. These are single instrumented
observations, not an ABBA comparison, causal speedup or statistical estimate.
Timers/logs affect time; the original217-method/32-receiver result on9c/f2ad
remains separate and unchanged. This adds one retained-proof probe, zero new
complete W1 proofs and zero formal ABBA samples.

The instrumented source passes27 adapter tests, strict Clippy, formatting,
original source43/repository50 controls, repository links and equal complete
source receipts. It is not a prospective merge or original service acceptance.
Index binds listed raw logs/manifests. Original ELF stays on ai395 at suffix
-diag-1138/target/release/w1-node-adapter-research with SHA-256
a22f7ab62ebf1850cd33d849460633697a2550caa4e663e04cc790f0482949ef; executable bytes are excluded.
Owner/receiver database directories and targets are also excluded explicitly.
These files do not authenticate remote execution.

Use this diagnostic to choose the next equivalence-preserving algorithm change,
then require exact commitments/proof checks and fresh complete-receiver ABBA.
No proof-only dispatch, native replay removal, new work credit, whole-chain gain,
original four-second service or WAN/ACK qualification follows. HOLD_NO_GO.
