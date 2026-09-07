# Trillionnium Chain module specifications

`TRNM_MODULE_TECHNICAL_REFERENCE_V1.md` is the stable M00-M17 authority index.
The files below are implementation-level supplements for modules whose prior
entry was not sufficient to build and audit the complete operational boundary.

| Module | Supplement |
|---|---|
| M04 | `M04_P2P_TECHNICAL_SPEC_V1.md` |
| M05 | `M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md` |
| M08 | `M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md` |
| M14 | `M14_CLIENT_PLATFORM_TECHNICAL_SPEC_V1.md` |
| M15 | `M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md` |
| M16 | `M16_CONTROL_PLANE_TECHNICAL_SPEC_V1.md` |
| M17 | `M17_EVIDENCE_SECURITY_TECHNICAL_SPEC_V1.md` |

The shared [foundation operation contracts](TRNM_FOUNDATION_OPERATION_CONTRACTS_V1.md)
bind selected M02/M03/M04/M08/M15 operations to concrete source functions,
error and recovery obligations, and executable source regressions. The
[operation catalog](../../config/documentation-operations-v1.json) explicitly
remains incomplete; its integrity checks do not grant independent acceptance.

The [native signed Vote replay contract](TRNM_NATIVE_SIGNED_VOTE_REPLAY_CONTRACT_V1.md)
specifies M15's laboratory readback of an already signed historical Vote. Its
cross-store checks grant no new signing or recovered-runtime authority.

These documents are contracts, not completion claims. Implementation,
production and activation require exact-source tests, accepted evidence,
protected review and every applicable external gate.
