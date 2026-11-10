# Request-local DFT sharing: retained negative result

Tested candidate: 9c7da5551d48bac6e7e79d62e31fc8b6a6cc2e4a,
tree 08cfcdf690cdf20f2f4f627873de1bd826e46572.
Fixed baseline: 9133a2218890cfca837df34e7d6b892cec780868.
The complete receiver observations do not establish a benefit from sharing
request-local DFT tables. Both independent setups, both PCS verifications,
fresh component challengers, durable proof-start accounting and original native
replay remain paid. No production dispatch, security parameter or original
reader is changed.

## Observed whole-process costs

Each cell is a median of eight fresh receiver processes for that source and
variant. Wall time is fork through wait4, including pre-exec kernel readback,
exec, input reading, receiver work, reporting and teardown. CPU is user plus
system; peak RSS is wait4 KiB. These are separate measures, not sums of nested
phase medians.

| Source and receiver | Wall seconds | CPU seconds | Peak RSS KiB | Application payload bytes |
| --- | ---: | ---: | ---: | ---: |
| Baseline A native | 0.013459408 | 0.006726000 | 17,722 | 49,508 |
| Candidate B native | 0.012686325 | 0.006629500 | 18,014 | 49,508 |
| Baseline A proof plus native | 0.515773328 | 0.874163500 | 126,168 | 4,023,864 |
| Candidate B proof plus native | 0.527050337 | 0.878571500 | 126,650 | 4,023,864 |

Proof-plus-native candidate medians are descriptively 2.19% higher in wall,
0.50% higher in CPU and 0.38% higher in RSS. Payload is unchanged.
This short shared-host observation is a negative optimization result, not a
causal regression estimate or a statistical claim. Native timings also vary.
Do not convert internal primitive timing to TPS or whole-chain speedup.

Outer ABBA contains four batches, each with the unchanged NPPNNPPN order:
32 receiver attempts, 16 retained complete-W1-proof replays, one input task,
and zero newly generated complete W1 proofs. All receivers have fresh Node
directories. All four original comparison summaries are PASS with no errors.
PASS means the original local evidence contract was met, not that proof
verification was cheaper. Eight separate owner init/status process measurements
are retained and checked; owner provisioning is separate from receiver time.
Repeated fixtures are not independent tasks or new proof generations.

The user-owned systemd unit used affinity [0,1], two Rayon threads, actual
cpu.max of 200000 100000, memory.max of 2147483648, memory.swap.max of 0,
and pids.max of 256. Original per-child and ancestor kernel observations are
retained. The host was not exclusive, OS caches were not flushed, and the
per-child timeout was 120 seconds. This does not qualify the original
quarter-CPU, 2-GiB, four-second service contract, production owner, hostile
service, independent operators, WAN traffic or final ACK latency.
The owned unit subsequently read inactive/not-found with MainPID zero.

## Exact-source validation and failures

Fresh candidate validation completed 217 methods: adapter 27, P3 80,
receiver Python 17, source-integrity controls 43 and repository controls 50.
Both crate locked/offline default and all-feature graphs, formatting and
strict all-target/all-feature Clippy passed. Original complete source receipts
before/after are equal; all three Cargo lock digests are unchanged.
These results belong to the tested source above, not a prospective merge.

Preserve the initial baseline metadata/cache miss and separate successful
locked-fetch/build continuation; candidate linker ENOSPC (exit 101, no tests);
the first combined controller selecting a historical failed baseline receipt;
and continuation03 rejecting sparse hidden tracked files. The successful
baseline receipt is baseline-records/resume-manifest.json; historical
manifest.json remains failed. At diagnosis, /tmp had zero free inodes despite
free bytes. Exact v2 only provisions private home temporary storage and
TMPDIR/TMP/TEMP; flags, locks, profiles and required counts remain unchanged.
Continuation04 disables only these two owned sparse views, verifies unchanged
common Git config digests, then runs original complete source guards.
No source guard was relaxed, and no other user's /tmp was cleaned.

Successful ai395 durable pipeline: job 1a1c4c528bb-cf39-435, exit zero.
Its complete stdout/stderr, subprocess logs and terminal manifests are retained.
This is an observed local record, not execution authentication or build
attestation.

## Archive and reproduction

[manifest.json](manifest.json) binds [index.json](index.json) and
[records.tar.gz](records.tar.gz): 634 files, 287 distinct content objects.
Archive: 1,370,330 bytes; SHA-256
3aca567efab17e47a3100e5108c60f4bb21f7d2f70fdc6eff2a07270060d33de.
Four immutable fixture blobs are referenced by exact path, byte length, Git
blob ID and SHA-256 at the fixed baseline and resolved from Git.

The index records all five explicit group paths. Baseline and source-freeze
groups are audit mirrors, not a claim that original directories were archived
without exclusions. All terminal logs are retained. Original ELF executables,
build targets, dependency caches and private temporary files are excluded.
The retained p3-checks-and-precommit-observations/omitted-originals.json records
both ELF omissions with actual ai395 paths, mode0555 and uid1000.

| Original executable still on ai395, relative to task prefix | Bytes | SHA-256 |
| --- | ---: | --- |
| -baseline-records/w1-node-adapter-baseline-9133a221.elf | 8,393,464 | b9bb1767a402837c5a1924a1e797f2b23e8b1910d20f33e7119706983c2e569d |
| -candidate-binaries/w1-node-adapter-candidate-9c7da5551d48.elf | 8,399,712 | e693a7416eae5ad710e7b91b6f91888452fe75df523c850b00c07ed5903fd06e |

Task prefix: /home/qq/work/w1-dft-resume-20261110-035f.
ELF originals are not supplied by this archive.

After repository preflight, from its root:

    python3 -B formal/pon-nakamoto-v1/w1_node_adapter_research/evidence/dft-sharing-20261110-ai395/verify_retained.py --repo .

[verify.stdout](verify.stdout) records binding verification of 634 files, all
32 raw receiver stdout/stderr pairs and embedded receipts, eight owner
measurements, and recomputation with the unchanged original reader.
[Independent analysis](independent-analysis.json) retains per-batch medians and
original decisions. Retained-byte verification is not execution authentication.

## Remaining receiver-cost research

Keep this negative result; table sharing has no established optimization gain.
Next inspect actual transform-shape keys and separately measure public-table
generation, polynomial extension and commitment hashing on a frozen diagnostic
build. Such probes cannot replace these formal samples. Evaluate a narrowly
specified preprocessing algorithm change only with full commitment/proof
equality, unchanged independent setup semantics and new complete-receiver
comparisons. Request-local table ownership alone may share no key across these
component shapes. No verifier-key cache, accepted-result cache, proof-only
dispatch or native replay removal follows.

Whole-chain gain, proof-only production dispatch, original service acceptance,
WAN/ACK, actual legal-work minimum cost and complete cryptographic qualification
remain independent HOLD gates. Production activation is false; **HOLD_NO_GO**.
