# W1 receiver evidence: exact receipt-layout binding

This change closes a reader-side evidence classification gap on source
`c16507147b65285ea94dead22d3b93c5db7295af`. The old reader required a purported
last-seal mutation to lie after byte 420. It did not establish that the byte
belonged to the last word of the final segment. It also accepted arbitrary
nearby zeroing as verifier-parameter corruption and trusted bounded declared
shape counters. A coherently rebound record could therefore misdescribe the
input associated with a reported receiver cost. This was not an acceptance
bypass in the native STARK verifier.

## Change and retained boundary

The independent Python reader now parses every supported length and enum branch
before accepting the original receipt layout. It binds exact first/last seal
word positions, the entire first-segment parameter digest, declared segment
dimensions, and the outer journal to the supplied original bytes and input.
All original resource caps, W1 arithmetic, ticket/target rules, native verifier,
eight case names and receiver timing boundaries remain unchanged.

The output uses the new `pon-w1-receiver-case-binding-v2` namespace. Its true
layout/mutation flags describe byte reconstruction. Proof authentication, SDK
dispatch reexecution, independent time measurement, minimum-work qualification,
public-ingress qualification and consensus authority are not established by
this reader. In particular, this fix does not solve expensive rejection or
demonstrate sustained honest service under attack.

## Retained observations

The same seven regression assertions fail against the exact, hash-pinned old
reader, with no execution errors; the complete fixed control suite passes
26 tests. The tests retain the earlier metadata controls and add exact mutation
positive controls, hostile length/variant cases, all truncated prefixes of the
synthetic layout, trailing data and aggregate padded-cycle overflow. Synthetic
seal words are invalid proof material and are never submitted as proof evidence.

The actual historical input and receipt have SHA-256 digests
`4babd290b10f7a68be27c2adf3b97448bb7bef04dba8bcb97f914acf4ac69020` and
`0a5336a797c51829ed25d4ec2f1a03f4f56fda4c737a230b493d4abbe96f0ec8`.
All eight original c165 case records pass both the old and new byte/source
readers without rewriting those records. The new parser finds 62 segments,
16,252,928 declared padded cycles, maximum po2 18, and last-seal word byte offset
15,862,034 in the 15,862,780-byte receipt.

The retained adversarial record changes byte 424 and recomputes its case hash,
while keeping the `last_seal_tamper` label. The old reader accepts it; the new
reader rejects it with `exact last seal word offset`. This record is explicitly
forged metadata derived from an authentic historical record. Its inherited
native timings are not measurements of the forged input, and no host execution
or new proof is claimed for it.

- [Raw baseline regression failures](results/red.stderr.log)
- [Raw fixed controls](results/green.stderr.log)
- [Source hashes, original record hashes, exact layout and outcomes](results/actual-layout-recheck.json)
- [Adversarial metadata, never a fresh host observation](results/forged-early-as-last.case.json)
- [Original historical observations](../pon-pure-security-20261030-rebuild/complete-w1/actual-cases/local-summary.json)

## Reproduce

Use a checkout containing the exact baseline commit and the retained fixture
objects. Each output directory must be new. This script runs only Python
metadata/layout readers and their tests, never a prover or native verifier.

```sh
bash scripts/project-preflight.sh
python3 scripts/ci/prepare_w1_audit_one_fixture.py \
  --objects evidence/pon-pure-security-20261030-rebuild/complete-w1/fixture-objects \
  --out /new/explicit/w1-fixture
python3 evidence/pon-w1-receiver-layout-20261031/recheck.py \
  --fixture /new/explicit/w1-fixture --out /new/explicit/layout-results
```

The original W1 receiver workflow already runs the expanded control file and
feeds each newly executed native case through this reader. That workflow
remains the separate source of fresh native verification/cost observations;
the results in this directory are a recheck of retained historical bytes.
