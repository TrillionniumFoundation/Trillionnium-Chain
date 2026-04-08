# TEE Attestation Contract v0

This document defines the feature-gated TEE attestation contract used by `trnm-pouw` when `real-tee-backend` is enabled.

## Purpose
The current goal is **not** to ship a production SGX/TDX/SNP verifier yet.
The goal is to freeze the backend handoff surface so future real attestation backends plug into a stable fail-closed contract.

## Receipt envelope
TEE receipts continue to use the bound envelope form:

```text
TEE:task_id=<u64>,worker=<id>,proof_type=tee,result_hash=<hex>,attestation_target=<token>,measurement=<value>,report_data_hash=<hex>,<evidence-field>=<value>[,<target-specific-verifier-metadata>]
```

The semantic verifier still owns:
- envelope prefix validation
- `task_id` / `worker` / `proof_type` / `result_hash` binding

The feature-gated real TEE backend additionally owns:
- `attestation_target` canonicalization
- target-specific measurement slot validation
- target-specific evidence kind validation (`quote` vs `report`)
- required attestation fields
- target-specific verifier metadata validation
- `report_data_hash` ↔ task `result_hash` consistency

## Canonical attestation target matrix

| target | adapter | verifier kind | evidence field | measurement prefix | required verifier metadata | downstream bundle shape | executor path | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `sgx-dcap` | `SgxDcapAdapter` | `quote-verifier` | `quote` | `mrenclave:` | `collateral`, `cert_chain`, `issuer` | `IntelQuoteCollateralBundle` | `verify_intel_quote_bundle(...)` | Intel SGX DCAP-style quote path |
| `tdx-qgs` | `TdxQgsAdapter` | `quote-verifier` | `quote` | `mrtd:` | `collateral`, `cert_chain`, `issuer` | `IntelQuoteCollateralBundle` | `verify_intel_quote_bundle(...)` | Intel TDX QGS quote path |
| `sev-snp` | `SevSnpAdapter` | `report-verifier` | `report` | `measurement:` | `vcek`, `cert_chain`, `report_signer` | `AmdSnpSignerBundle` | `verify_amd_report_bundle(...)` | AMD SEV-SNP report path |

Unknown values must fail closed before any cryptographic verification attempt.

## Required fields
All targets require:
- `attestation_target`
- `measurement`
- `report_data_hash`

Target-specific evidence is also required:
- `sgx-dcap` → `quote`
- `tdx-qgs` → `quote`
- `sev-snp` → `report`

Target-specific verifier metadata is explicit:
- quote-based targets (`sgx-dcap`, `tdx-qgs`) require:
  - `collateral`
  - `cert_chain`
  - `issuer`
- report-based targets (`sev-snp`) require:
  - `vcek`
  - `cert_chain`
  - `report_signer`

Cross-family metadata must fail closed:
- quote-based targets must not rely on `vcek` / `report_signer`
- report-based targets must not rely on `collateral` / `issuer`

Missing or empty values are malformed receipts.

## Backend handoff contract
The scaffold canonicalizes TEE receipts into an intermediate `TeeVerifierHandoff` with these fields:

- `attestation_target`
- `verifier_kind` (`quote-verifier` or `report-verifier`)
- `measurement_field` (`mrenclave` / `mrtd` / `measurement`)
- `measurement`
- `report_data_hash`
- target-specific evidence (`quote` or `report`)
- structured verifier metadata

A target-specific adapter then turns that handoff into one of two concrete verifier inputs.

### Quote verifier input
Used by SGX DCAP and TDX QGS adapters.

```text
{
  attestation_target,
  verifier_kind: "quote-verifier",
  measurement_field,
  measurement,
  report_data_hash,
  quote,
  intel_collateral: {
    collateral,
    cert_chain,
    issuer
  }
}
```

This vendor-shaped bundle is intended to match the seam a future Intel quote verifier would consume.

### Report verifier input
Used by SEV-SNP adapter.

```text
{
  attestation_target,
  verifier_kind: "report-verifier",
  measurement_field,
  measurement,
  report_data_hash,
  report,
  amd_signer: {
    vcek,
    cert_chain,
    report_signer
  }
}
```

This vendor-shaped bundle is intended to match the seam a future AMD SNP report verifier would consume.

## Executor seam
After adapter construction, `real-tee-backend` now dispatches concrete verifier inputs into a dedicated executor trait:

- `verify_intel_quote_bundle(&QuoteVerifierInput, ...)`
- `verify_amd_report_bundle(&ReportVerifierInput, ...)`

The default executor is now provider-backed rather than directly fixture-bound.
It delegates to vendor-specific provider traits:

- `IntelQuoteVerifierProvider`
- `AmdReportVerifierProvider`

Each provider now delegates one step further into a client seam that models the external verifier call boundary:

- `IntelQuoteVerifierClient`
- `AmdReportVerifierClient`

Client requests now also carry an explicit transport/config seam:
- `mode` (`mock` today, `external` reserved as placeholder)
- `endpoint`
- `timeout_ms`
- optional `auth_scheme`
- optional `auth_ref`

Transport config is no longer hard-coded at the provider callsite.
Providers now obtain transport settings from a dedicated config source seam:
- `VerifierTransportConfigSource`
- `StaticVerifierTransportConfigSource::mock_defaults()`
- `StaticVerifierTransportConfigSource::external_defaults()`
- `EnvVerifierTransportConfigSource::from_env(...)`

This gives the scaffold a stable place to swap from mock profiles to future real external verifier profiles without changing adapter or provider request shapes.
The env-backed source currently supports per-vendor overrides for mode / profile / endpoint / timeout / auth ref / retry policy.

Transport retry behavior is now grouped into an explicit policy object:
- `RetryBackoffPolicy { max_attempts, backoff_ms, strategy }`
- current scaffold strategies: `fixed` and `exponential`

Client requests also now carry explicit external-call metadata:
- `request_id`
- `telemetry_scope`
- `attempt`
- `retry_policy`

This freezes a minimal request-observability / retry scaffold before any real outbound verifier integration is added.

Request-side telemetry is now explicit via a `RequestPrepared` event.
Response-side telemetry is also explicit via a `ResponseReceived` event returned in the client response payload.
These events carry:
- `request_id`
- `telemetry_scope`
- `transport_mode`
- `profile`
- optional `backend_id`
- optional response `status`
- optional `detail`

Client responses are normalized into a mock external verifier response schema with:
- `status` (`verified | invalid | unavailable | malformed | internal`)
- `backend_id`
- optional `detail`
- optional `telemetry_event`

Mock and future external clients are expected to converge on the same response decode contract.
The scaffold now includes a unified JSON codec seam:
- `encode_mock_verifier_response_json(...)`
- `decode_mock_verifier_response_json(...)`

Provider logic is responsible for two fail-closed validations before mapping the response:
1. **auth/profile validation** on the transport config
   - external mode must provide non-empty `profile`, `auth_scheme`, `auth_ref`
   - external mode must use `https://...` endpoints
   - mock mode must use `mock://...` endpoints
   - retry policy must have `max_attempts >= 1`
2. **telemetry coherence validation** on the decoded client response
   - response telemetry must exist
   - response telemetry `request_id` / `telemetry_scope` must match the request metadata
   - response telemetry kind must be `ResponseReceived`

Only after those validations does provider logic map client response status into backend semantics:
- `verified` -> backend success
- `invalid` -> `InvalidProof`
- `unavailable` -> `Unavailable`
- `malformed` -> `MalformedProof`
- `internal` -> `Internal`

The current fixture-backed path therefore has five explicit layers:
1. receipt parsing / normalization
2. target-specific request shaping
3. executor dispatch
4. vendor-specific provider verification
5. external verifier client call seam

The current implementation uses fixture-backed clients behind client-backed providers, but a future real backend should mainly replace the client layer (or swap providers if vendor orchestration itself changes).

## Pluggable HTTP client / provider adapter skeleton
The scaffold now also includes a thin HTTP transport skeleton behind the client layer.

### Generic HTTP transport seam
A future external verifier integration can plug into:
- `VerifierHttpTransport`
- `HttpVerifierRequest`
- `HttpVerifierResponse`

This seam is intentionally vendor-agnostic.

The scaffold now also includes a retry executor seam above raw transport:
- `VerifierHttpRetryExecutor`
- default stub: `PolicyAwareHttpRetryExecutor`

The current retry executor is intentionally thin: it retries retryable transport failures / `5xx` responses according to `RetryBackoffPolicy`, without yet adding real sleep/backoff execution. That keeps the policy surface stable while leaving actual wall-clock retry behavior pluggable.

### Provider -> HTTP adapter path
The scaffold now includes HTTP-backed client implementations for both vendor paths:
- `HttpBackedIntelQuoteVerifierClient`
- `HttpBackedAmdReportVerifierClient`

These adapters are now explicitly layered behind two additional seams:
- `VerifierProfileResolver`
- `VerifierAuthInjector`

The profile resolver seam is no longer just a placeholder. The scaffold now includes:
- `RuntimeVerifierProfileRegistry`
- `RegistryBackedVerifierProfileResolver`
- `VerifierProfileRegistrySource`
- `StaticVerifierProfileRegistrySource`
- `FileJsonVerifierProfileRegistrySource`
- `EnvJsonVerifierProfileRegistrySource`

This lets the system validate that a named transport profile actually exists, matches the expected transport mode, and matches the expected endpoint family before any outbound call is attempted.
It also gives the scaffold three explicit runtime-loading paths:
- static/builtin registry defaults
- file-backed JSON registry overlays
- env-injected JSON registry overlays

Current overlay order is:
1. builtin defaults
2. optional `TRNM_TEE_PROFILE_REGISTRY_PATH` file overlay
3. optional `TRNM_TEE_PROFILE_REGISTRY_JSON` inline JSON overlay

That means env JSON can still override file-backed entries when both are present.

This lets the scaffold separate:
1. runtime profile / endpoint resolution
2. auth header injection
3. HTTP transport execution
4. response decoding

The default HTTP-backed adapter path is therefore now:
- provider -> registry-backed profile resolver -> auth injector -> HTTP request encode -> retry executor -> transport -> response decode

A fail-closed `RealVerifierHttpTransport` stub is also present now. It intentionally returns `Unavailable` until a real outbound HTTP implementation is wired in.

That transport stub is now internally split into three explicit seams:
- `VerifierHttpRequestExecutor`
- `VerifierHttpResponseBodyReader`
- `VerifierHttpTimeoutHook`

The request-executor layer is itself now split into two lower-level seams:
- `VerifierHttpRequestPlanner`
- `VerifierHttpClientAdapter`

And the client-adapter layer is now also split into two explicit seams:
- `VerifierHttpClientConfigResolver`
- `VerifierHttpClientHandle`

The client-handle layer is now further split into runtime request/response seams:
- `VerifierHttpClientRuntimeRequestBuilder`
- `VerifierHttpClientRuntime`
- `VerifierHttpClientRuntimeResponseAdapter`

And the runtime layer is now also split into session / connection seams:
- `VerifierHttpClientSessionFactory`
- `VerifierHttpClientSession`

And the session layer is now further split into per-request execution / readback seams:
- `VerifierHttpClientSessionRequestExecutor`
- `VerifierHttpClientSessionResponseReader`

And the session-request-executor layer is now further split into wire-level seams:
- `VerifierHttpClientSessionWireRequestBuilder`
- `VerifierHttpClientSessionWireExecutor`
- `VerifierHttpClientSessionWireResponseParser`

And the wire-executor layer is now further split into call-level seams:
- `VerifierHttpClientSessionCallBuilder`
- `VerifierHttpClientSessionCallExecutor`
- `VerifierHttpClientSessionCallResponseParser`

And the call-executor layer is now further split into transport / raw-I/O seams:
- `VerifierHttpClientSessionTransportRequestBuilder`
- `VerifierHttpClientSessionTransportAdapter`
- `VerifierHttpClientSessionRawIoResponseParser`

And the transport-adapter layer is now further split into socket / byte-stream seams:
- `VerifierHttpClientSessionSocketRequestBuilder`
- `VerifierHttpClientSessionSocketAdapter`
- `VerifierHttpClientSessionByteStreamResponseParser`

And the socket-adapter layer is now further split into connection / byte-channel seams:
- `VerifierHttpClientSessionSocketConnectionOpener`
- `VerifierHttpClientSessionSocketByteChannel`

And the byte-channel layer is now further split into frame-level seams:
- `VerifierHttpClientSessionFrameEncoder`
- `VerifierHttpClientSessionFrameIoAdapter`
- `VerifierHttpClientSessionFrameDecoder`

And the frame-I/O layer is now further split into protocol-level seams:
- `VerifierHttpClientSessionProtocolRequestCodec`
- `VerifierHttpClientSessionProtocolTransportExchange`
- `VerifierHttpClientSessionProtocolResponseCodec`

And the protocol-transport-exchange layer is now further split into bytes/envelope seams:
- `VerifierHttpClientSessionProtocolBytesEncoder`
- `VerifierHttpClientSessionProtocolBytesTransportExchange`
- `VerifierHttpClientSessionProtocolEnvelopeParser`

And the protocol-bytes-transport layer is now further split into chunking / assembly seams:
- `VerifierHttpClientSessionProtocolByteStreamChunker`
- `VerifierHttpClientSessionProtocolChunkTransportExchange`
- `VerifierHttpClientSessionProtocolByteStreamAssembler`

The default wiring remains fail-closed:
- `AdapterBackedVerifierHttpRequestExecutor`
  - `DirectVerifierHttpRequestPlanner`
  - `HandleBackedVerifierHttpClientAdapter`
    - `StaticVerifierHttpClientConfigResolver`
    - `RuntimeBackedVerifierHttpClientHandle`
      - `DirectVerifierHttpClientRuntimeRequestBuilder`
      - `SessionBackedVerifierHttpClientRuntime`
        - `StaticVerifierHttpClientSessionFactory`
          - `ExecutorBackedVerifierHttpClientSession`
            - `WireBackedVerifierHttpClientSessionRequestExecutor`
              - `DirectVerifierHttpClientSessionWireRequestBuilder`
              - `CallBackedVerifierHttpClientSessionWireExecutor`
                - `DirectVerifierHttpClientSessionCallBuilder`
                - `TransportBackedVerifierHttpClientSessionCallExecutor`
                  - `DirectVerifierHttpClientSessionTransportRequestBuilder`
                  - `SocketBackedVerifierHttpClientSessionTransportAdapter`
                    - `DirectVerifierHttpClientSessionSocketRequestBuilder`
                    - `ConnectionBackedVerifierHttpClientSessionSocketAdapter`
                      - `StaticVerifierHttpClientSessionSocketConnectionOpener`
                        - `FrameBackedVerifierHttpClientSessionSocketByteChannel`
                          - `DirectVerifierHttpClientSessionFrameEncoder`
                          - `CodecBackedVerifierHttpClientSessionFrameIoAdapter`
                            - `DirectVerifierHttpClientSessionProtocolRequestCodec`
                            - `BytesBackedVerifierHttpClientSessionProtocolTransportExchange`
                              - `DirectVerifierHttpClientSessionProtocolBytesEncoder`
                              - `FramedBytesBackedVerifierHttpClientSessionProtocolBytesTransportExchange`
                                - `DirectVerifierHttpClientSessionProtocolByteStreamFramer`
                                - `ChunkedByteStreamBackedVerifierHttpClientSessionProtocolByteStreamExchange`
                                  - `DirectVerifierHttpClientSessionProtocolByteStreamChunker`
                                  - `FramedChunkBackedVerifierHttpClientSessionProtocolChunkTransportExchange`
                                    - `DirectVerifierHttpClientSessionProtocolChunkFramingPolicy`
                                    - `WindowedChunkBackedVerifierHttpClientSessionProtocolChunkFrameExchange`
                                      - `DirectVerifierHttpClientSessionProtocolChunkSequenceWindowPlanner`
                                      - `AckedWindowBackedVerifierHttpClientSessionProtocolChunkSequenceWindowExchange`
                                        - `DirectVerifierHttpClientSessionProtocolChunkAckPolicy`
                                        - `BudgetedRetransmitBackedVerifierHttpClientSessionProtocolChunkRetransmitExchange`
                                          - `DirectVerifierHttpClientSessionProtocolChunkRetransmitBudgetPlanner`
                                          - `ConvergingAckBackedVerifierHttpClientSessionProtocolChunkRetransmitBudgetExchange`
                                            - `DirectVerifierHttpClientSessionProtocolChunkAckConvergencePlanner`
                                            - `OutcomeProjectedVerifierHttpClientSessionProtocolChunkRetransmitTerminationExchange`
                                              - `DirectVerifierHttpClientSessionProtocolChunkTerminationOutcomePlanner`
                                              - `VerdictBackedVerifierHttpClientSessionProtocolChunkTerminationOutcomeExchange`
                                                - `DirectVerifierHttpClientSessionProtocolChunkTerminationVerdictPlanner`
                                                - `StatusNormalizedVerifierHttpClientSessionProtocolChunkTerminationVerdictExchange`
                                                  - `DirectVerifierHttpClientSessionProtocolChunkTerminationStatusPlanner`
                                                  - `ClassifiedTerminationStatusBackedVerifierHttpClientSessionProtocolChunkTerminationStatusExchange`
                                                    - `DirectVerifierHttpClientSessionProtocolChunkTerminationClassificationPlanner`
                                                    - `CategorizedTerminationBackedVerifierHttpClientSessionProtocolChunkTerminationClassificationExchange`
                                                      - `DirectVerifierHttpClientSessionProtocolChunkTerminationCategoryPlanner`
                                                      - `LabelProjectedTerminationBackedVerifierHttpClientSessionProtocolChunkTerminationCategoryExchange`
                                                        - `DirectVerifierHttpClientSessionProtocolChunkTerminationLabelPlanner`
                                                        - `TokenNormalizedVerifierHttpClientSessionProtocolChunkTerminationLabelExchange`
                                                          - `DirectVerifierHttpClientSessionProtocolChunkTerminationTokenPlanner`
                                                          - `FragmentAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenExchange`
                                                            - `DirectVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentPlanner`
                                                            - `SliceAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentExchange`
                                                              - `DirectVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSlicePlanner`
                                                              - `ShardAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceExchange`
                                                                - `DirectVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardPlanner`
                                                                - `UnitAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardExchange`
                                                                  - `DirectVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitPlanner`
                                                                  - `CellAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitExchange`
                                                                    - `DirectVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellPlanner`
                                                                    - `AtomAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellExchange`
                                                                      - `DirectVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomPlanner`
                                                                      - `FailClosedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomExchange`
                                                                      - `PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizationUnitAdapter`
                                                                    - `PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionUnitAdapter`
                                                                  - `PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizationShardAdapter`
                                                                - `PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionShardAdapter`
                                                              - `PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizationAdapter`
                                                            - `PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionAdapter`
                                                          - `PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizer`
                                                        - `PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionResolver`
                                                      - `PassthroughVerifierHttpClientSessionProtocolChunkNormalizedVerdictProjection`
                                                    - `PassthroughVerifierHttpClientSessionProtocolChunkNormalizedOutcomeMapper`
                                                  - `PassthroughVerifierHttpClientSessionProtocolChunkVerdictNormalizer`
                                                - `PassthroughVerifierHttpClientSessionProtocolChunkOutcomeMaterializer`
                                              - `PassthroughVerifierHttpClientSessionProtocolChunkSettlementProjection`
                                            - `PassthroughVerifierHttpClientSessionProtocolChunkTerminationValidator`
                                          - `PassthroughVerifierHttpClientSessionProtocolChunkAckSettlementValidator`
                                        - `PassthroughVerifierHttpClientSessionProtocolChunkAckValidator`
                                      - `PassthroughVerifierHttpClientSessionProtocolChunkIntegrityValidator`
                                    - `PassthroughVerifierHttpClientSessionProtocolStreamReassemblyValidator`
                                  - `PassthroughVerifierHttpClientSessionProtocolByteStreamAssembler`
                                - `PassthroughVerifierHttpClientSessionProtocolEnvelopeNormalizer`
                              - `PassthroughVerifierHttpClientSessionProtocolEnvelopeParser`
                            - `PassthroughVerifierHttpClientSessionProtocolResponseCodec`
                          - `PassthroughVerifierHttpClientSessionFrameDecoder`
                    - `PassthroughVerifierHttpClientSessionByteStreamResponseParser`
                  - `PassthroughVerifierHttpClientSessionRawIoResponseParser`
                - `PassthroughVerifierHttpClientSessionCallResponseParser`
              - `PassthroughVerifierHttpClientSessionWireResponseParser`
            - `PassthroughVerifierHttpClientSessionResponseReader`
      - `PassthroughVerifierHttpClientRuntimeResponseAdapter`
- `Utf8HttpResponseBodyReader`
- `NoopVerifierHttpTimeoutHook`

This freezes a future real transport path as:
- timeout hook -> request executor -> request planner -> client adapter -> client config resolver -> client handle -> runtime request builder -> client runtime -> session factory -> session -> session request executor -> wire request builder -> wire executor -> call builder -> call executor -> transport request builder -> transport adapter -> socket request builder -> socket adapter -> connection opener -> byte channel -> frame encoder -> protocol request codec -> bytes encoder -> byte-stream framer -> byte-stream chunker -> chunk framing policy -> chunk sequence window planner -> chunk ack policy -> chunk retransmit budget planner -> chunk ack convergence planner -> chunk termination outcome planner -> chunk termination verdict planner -> chunk termination status planner -> chunk termination classification planner -> chunk termination category planner -> chunk termination label planner -> chunk termination token planner -> chunk termination token fragment planner -> chunk termination token fragment slice planner -> chunk termination token fragment slice shard planner -> chunk termination token fragment slice shard unit planner -> chunk termination token fragment slice shard unit cell planner -> chunk termination token fragment slice shard unit cell atom planner -> chunk termination token fragment slice shard unit cell atom exchange -> chunk verdict projection normalization unit adaptation -> chunk verdict projection resolution unit adaptation -> chunk verdict projection normalization shard adaptation -> chunk verdict projection resolution shard adaptation -> chunk verdict projection normalization adaptation -> chunk verdict projection resolution adaptation -> chunk verdict projection normalization -> chunk verdict projection resolution -> chunk normalized verdict projection -> chunk normalized outcome mapping -> chunk verdict normalization -> chunk outcome materializer -> chunk settlement projection -> chunk termination validator -> chunk ack settlement validator -> chunk ack validator -> chunk integrity validator -> stream reassembly validator -> byte-stream assembler -> envelope normalizer -> protocol envelope parser -> protocol response codec -> frame decoder -> byte stream response parser -> raw io response parser -> call response parser -> wire response parser -> session response reader -> runtime response adapter -> raw response -> body reader -> normalized `HttpVerifierResponse`

So the scaffold now separates:
1. HTTP request planning / profile + auth resolution
2. retry policy execution
3. client-facing request planning
4. adapter-level client config resolution
5. client-handle request shaping
6. runtime session / connection setup
7. session-level request execution
8. wire-level request assembly
9. call-level request shaping
10. transport-request shaping
11. socket connection setup
12. byte-channel exchange
13. frame encoding
14. protocol request coding
15. protocol bytes encoding
16. byte-stream framing
17. byte-stream chunking
18. chunk framing policy
19. chunk sequence window planning
20. chunk ack policy
21. chunk retransmit budget planning
22. chunk ack convergence planning
23. chunk termination outcome planning
24. chunk termination verdict planning
25. chunk termination status planning
26. chunk termination classification planning
27. chunk termination category planning
28. chunk termination label planning
29. chunk termination token planning
30. chunk termination token fragment planning
31. chunk termination token fragment slice planning
32. chunk termination token fragment slice shard planning
33. chunk termination token fragment slice shard unit planning
34. chunk termination token fragment slice shard unit cell planning
35. chunk termination token fragment slice shard unit cell atom planning
36. chunk termination token fragment slice shard unit cell atom exchange
37. chunk verdict projection normalization unit adaptation
38. chunk verdict projection resolution unit adaptation
39. chunk verdict projection normalization shard adaptation
40. chunk verdict projection resolution shard adaptation
41. chunk verdict projection normalization adaptation
42. chunk verdict projection resolution adaptation
43. chunk verdict projection normalization
44. chunk verdict projection resolution
45. chunk normalized verdict projection
46. chunk normalized outcome mapping
47. chunk verdict normalization
48. chunk outcome materialization
49. chunk settlement projection
50. chunk termination validation
51. chunk ack settlement validation
52. chunk ack validation
53. chunk integrity validation
54. stream reassembly validation
55. byte-stream assembly
56. envelope normalization
57. protocol envelope parsing
58. protocol response decoding
59. frame decoding
60. byte-stream response parsing
61. raw-I/O response parsing
62. call-level response parsing
63. wire-level response parsing
64. session-level response readback
65. runtime-response adaptation
66. timeout/guard hook behavior
67. body decoding / normalization
68. verifier response decode + backend mapping

### HTTP payload skeletons
The current adapter layer freezes two JSON request shapes:
- `IntelQuoteVerifierHttpPayload`
- `AmdReportVerifierHttpPayload`

These carry the already-normalized verifier input plus request metadata and retry policy.

### HTTP response handling
The adapter currently expects the HTTP body to decode into the same normalized verifier response schema used by mock clients.
This means mock and future HTTP-backed clients share the same response contract, while transport-level failures remain isolated at the HTTP seam.

### Telemetry sink seam
Provider-backed clients now also support a telemetry recorder seam:
- `VerifierTelemetrySink`
- default sink: `NoopVerifierTelemetrySink`
- recorder adapter: `JsonEncodingTelemetrySink`
- recorder backend trait: `VerifierTelemetryRecorder`
- writer/backend adapter trait: `VerifierTelemetryRecordWriter`
- newline-delimited recorder: `JsonlTelemetryRecorder`

The provider layer emits three event stages into the sink:
1. `RequestPrepared`
2. `ResponseReceived`
3. `ResponseMapped`

This makes request/response telemetry observable without coupling the transport or provider layers to a concrete logging backend.
The scaffold can now serialize those events into recorder-friendly JSON and also adapt them into newline-delimited record streams via the JSONL recorder adapter.

## report_data_hash binding
`report_data_hash` must match the task `result_hash` carried by the bound envelope.
This keeps the future attestation path aligned with the task result binding already enforced by the semantic verifier.

## Current implementation scope
With `real-tee-backend`, `trnm-pouw` registers a fixture-backed `real-tee-backend` implementation.
It validates the contract above against embedded fixture vectors for:
- SGX DCAP quote verifier input
- TDX QGS quote verifier input
- SEV-SNP report verifier input

This is a **readiness scaffold**, not a production verifier.
