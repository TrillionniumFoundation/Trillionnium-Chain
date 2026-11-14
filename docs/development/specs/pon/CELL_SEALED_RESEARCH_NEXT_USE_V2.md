# Sealed research next-use V2

Status: explicit single-operator research entry. This specification does not
claim real-model execution. Compilation or synthetic tests cannot establish
that the actual 269,060,552-byte model completed the path. The actual run must
retain its native, worker and supervisor observations.

## Continuous operation

The [V2 entry](../../../../trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_next_use_v2.rs)
uses one original operation and absolute deadline throughout:

1. Verify the independently pinned source JSON, Python and inputs. Capture
   model/environment bytes into a new publisher CAS using the original 4 MiB
   TCM1 chunks. Construct one complete TCV1 and TCV2.
2. Construct TMT1/TMA1 from those captured safetensors headers, CTS1 from the
   same TCV1, and every storage-to-BEP52 mapping from the actual captured bytes.
   Form one complete release plan over the canonical manifest union.
3. Create one release session per endpoint, using explicit partitions of one
   global network allowance. Transfer all members over actual loopback TCP to
   an empty second CAS and verify the complete received bytes. Members and
   cache-deduplicated continuations never create another session or deadline.
4. Acknowledge TCA3 retention **from that received CAS**, with the same TCV1 and
   its TMA1. Save the independent CVA3 anchor, close the retained owner and
   remove the operation's publisher and BEP52 receiver CAS/sidecars.
5. Reopen the retained owner against its anchor and restore into an empty third
   CAS. Verify the original CPV4/TCV2, prepare both closures and call
   `admit_local_release_snapshot` with the original CTS1/context. This parses
   the actual recovered dense tensor containers.
6. Seal both bundles, bind CHB1 to the same version/content, remove the third
   CAS and use the unchanged sealed-FD worker/supervisor for two fresh forwards.
   The worker checks its actual architecture, tokenizer, parent/LoRA, loaded
   parameters and runtime before emitting its original receipts.

This is **TCA3 complete physical retention and anchored catalog recovery**. It
is not CRR2/CRG2 native erasure/shard recovery. Those require separate evidence.
The transport plan binds TCV1 and mappings; CTS1 is held and admitted by the
same operation's release owner, not implicitly included in the transport plan.

Existing bounds remain: at most 300 seconds, 512 MiB complete captured payload,
8 GiB declared runtime RSS, four threads, eleven model files and at most 32
environment files. Original inputs and the retained owner are preserved. Only
this operation's new CAS paths are removed. The original V1 entry is unchanged.

Both TCP endpoints are loopback on one host, under one operator. This does not
establish independent operators/failure domains, public swarm interoperability,
prospective acceptance, M12 funding, Hepta FinalUse, installation or production
activation.

## V2 source inputs

Keep the complete original independently pinned source fields, change schema
to `trnm.cell-sealed-research-source.v2`, use a fresh nonzero operation and a
fresh absolute output path that does not exist. Add the two required objects
below. Unknown fields and omitted endpoint grants are refused. This fragment
is not a complete source document.

```json
{
  "network": {
    "schema": "trnm.cell-sealed-research-network.v2",
    "request_timeout_ms": 30000,
    "total": {
      "max_connections": 256,
      "max_received_bytes": 2147483648,
      "max_sent_bytes": 2147483648,
      "max_messages": 2000000,
      "max_readback_bytes": 1073741824,
      "max_readback_chunks": 4096,
      "max_readback_attempts": 2
    },
    "publisher": {
      "max_connections": 128,
      "max_received_bytes": 1073741824,
      "max_sent_bytes": 1073741824,
      "max_messages": 1000000,
      "max_readback_bytes": 536870912,
      "max_readback_chunks": 2048,
      "max_readback_attempts": 1
    },
    "consumer": {
      "max_connections": 128,
      "max_received_bytes": 1073741824,
      "max_sent_bytes": 1073741824,
      "max_messages": 1000000,
      "max_readback_bytes": 536870912,
      "max_readback_chunks": 2048,
      "max_readback_attempts": 1
    }
  },
  "snapshot": {
    "schema": "trnm.cell-sealed-research-snapshot.v2",
    "model_loader": "sealed-smollm2-dense-v1",
    "environment_loader": "sealed-python-runtime-snapshot-v1",
    "tensor_codec": "safetensors-dense-f32-f16-bf16-v1",
    "quantization": "none",
    "composition_file": "adapter/target-contract.json",
    "composition_profile": "sealed-smollm2-parent-lora-v1",
    "material_profile": "current-contract-v1",
    "worker_sha256": "INDEPENDENT_LOWERCASE_64_HEX_SHA256"
  }
}
```

The worker pin must equal both the original environment worker pin and
`context.runtime`, and the exact
[worker source](../../../../scripts/llm_cell_sealed_worker_v1.py)
compiled into the entry. A mismatch fails; do not silently repin an old input.
The snapshot material profile must equal the top-level material profile. The
supported values are the existing worker's `current-contract-v1` and
`smollm2-public-v2-material-runtime-bridge-v1`; the latter still requires its
original pinned material-plan environment member. The example does not select
which profile is appropriate for a particular set of inputs.

### Global network accounting

For every allowance field, the checked publisher-plus-consumer sum must fit
`total`. Zero/omitted endpoint grants, overflow and excess aggregates fail.
Each endpoint is also admitted by the bounded V2 release constructor. Both
sessions keep the same original operation/deadline across all members.

Reports contain actual connection attempts, receive/send bytes/messages,
refusals and readback reservations per endpoint and in total. These application
wire counters exclude TCP/IP overhead. Publisher send and consumer receive
are separate endpoint charges. Failed/partial I/O and failed readback
reservations are not refunded. The publisher's complete-readback allowance is
admitted by its constructor but unused by this entry and not reassigned.
Cross-member dedup may avoid a later connection; the whole-version readback
still checks that member's original full-file hash.

### Dense tensor and composition binding

The input names a closed actual worker/interpreter profile. Profile identifiers
commit its kind/name, material profile and worker pin under
`TRNM/Cell/SealedResearchLoader/v2\0`. Arbitrary opaque compatibility claims
are refused. CTS1 covers the same original TCV1, TMA1 and the exact
`adapter/target-contract.json` composition member; the model closure also
covers base configuration, tokenizer and all original dependencies.

Captured safetensors headers are bounded to 1 MiB. Duplicate fields,
unsupported tensor-record fields, unknown dtype, invalid shape, gaps/overlap
and incomplete data coverage are refused. Only dense F32/F16/BF16 is admitted.
Unsupported quantization/compression metadata or base configuration fails;
the parent contract must retain float32 storage/accumulation and quantization
`none`. TCA3 retains TMA1 with TCV1; the independent CTS1 artifact/pin remains
with the operation owner. Final CTS1 admission checks the recovered actual
tensors, and the unchanged worker still checks exact architecture, LoRA
modules/rank/alpha, tokenizer and the actual loaded parent. CTS1 alone does not
prove semantic compatibility or either forward.

## Tests, execution and observations

Use the repository preflight, required toolchain and explicit PQ provider.
The focused example tests are:

```sh
cargo test --locked --offline --jobs 2 -p trnm-data-availability \
  --example cell_sealed_research_next_use_v2
```

The five tests cover aggregate allowance refusal, old/partial network schemas,
real synthetic loopback transfer with cross-member dedup, the closed worker
profile and fail-closed dense header admission. The synthetic fixture is
explicitly not a model run.

After saving the complete independently pinned V2 source, calculate its new
independent SHA-256 and run:

```sh
cargo run --locked --offline --jobs 2 -p trnm-data-availability \
  --example cell_sealed_research_next_use_v2 -- \
  /absolute/source-v2.json INDEPENDENT_SOURCE_SHA256
```

| Artifact | Meaning |
| --- | --- |
| `original-source-inputs.json` | Exact independently pinned request |
| `bep52/owner-version.tcv1`, `owner-plan.json`, `*.cbm2` | Original version, plan pin, complete members and actual mappings |
| `owner-release-snapshot.cts1` | Original complete version, dense schema and composition |
| `independent-catalog-anchor.cva3` | Original retained-catalog anchor |
| `owner-content.tcv2`, `owner-authorization.cpv4`, `owner-handoff.chb1` | Complete-content authorization and sealed handoff |
| `native-result.json` | Stage, actual endpoint/aggregate counters, error and operation status |
| `next-use-result.json`, supervisor stdout/stderr | Original worker and supervisor observations |

`bep52.complete_readback` requires full received-byte verification.
`snapshot.typed_snapshot_admitted` requires actual resident CTS1 admission.
`snapshot.composition_worker_executed` and `actual_model_run` equal to
`observed_two_forwards` require two fresh forward receipts and the original
reaped-child observation. `passed` additionally requires completion before the
original deadline. Compilation, synthetic tests and stage-local success must
not be reported as real-model end-to-end evidence.

Related: [complete version V1](CELL_COMPLETE_VERSION_V1.md),
[typed release snapshot V1](CELL_RELEASE_SNAPSHOT_V1.md),
[V2 support](../../../../trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_v2/mod.rs),
[complete TCP owner](../../../../trillionnium/crates/trnm-data-availability/src/cell/bep52_peer/release.rs).
