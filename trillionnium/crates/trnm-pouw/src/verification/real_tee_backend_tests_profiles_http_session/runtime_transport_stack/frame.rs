pub(super) use super::*;

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionFrameEncoder {
    requests: Mutex<Vec<VerifierHttpClientSessionFrameRequest>>,
}

impl VerifierHttpClientSessionFrameEncoder for RecordingHttpClientSessionFrameEncoder {
    fn encode_frame(
        &self,
        _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
        socket_request: &VerifierHttpClientSessionSocketRequest,
        _transport_request: &VerifierHttpClientSessionTransportRequest,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionFrameRequest, BackendExecutionError> {
        let frame_request = VerifierHttpClientSessionFrameRequest {
            method: socket_request.method,
            url: socket_request.url.clone(),
            headers: socket_request.headers.clone(),
            body: socket_request.body.clone(),
            timeout_ms: socket_request.timeout_ms,
            profile: socket_request.profile.clone(),
            transport_mode: socket_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(frame_request.clone());
        Ok(frame_request)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionFrameIoAdapter {
    requests: Mutex<Vec<VerifierHttpClientSessionFrameRequest>>,
}

impl VerifierHttpClientSessionFrameIoAdapter for RecordingHttpClientSessionFrameIoAdapter {
    fn exchange_frame(
        &self,
        frame_request: &VerifierHttpClientSessionFrameRequest,
        connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
        _socket_request: &VerifierHttpClientSessionSocketRequest,
        _transport_request: &VerifierHttpClientSessionTransportRequest,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionFrameResponse, BackendExecutionError> {
        self.requests.lock().unwrap().push(frame_request.clone());
        assert_eq!(frame_request.profile, connection_config.profile);
        assert_eq!(
            frame_request.transport_mode,
            connection_config.transport_mode
        );
        assert_eq!(frame_request.timeout_ms, connection_config.timeout_ms);
        Ok(VerifierHttpClientSessionFrameResponse {
            status_code: 216,
            headers: BTreeMap::from([("x-frame".to_string(), "ok".to_string())]),
            body: b"frame-ok".to_vec(),
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionFrameDecoder {
    responses: Mutex<Vec<VerifierHttpClientSessionFrameResponse>>,
}

impl VerifierHttpClientSessionFrameDecoder for RecordingHttpClientSessionFrameDecoder {
    fn decode_frame(
        &self,
        frame_response: VerifierHttpClientSessionFrameResponse,
        _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
        _socket_request: &VerifierHttpClientSessionSocketRequest,
        _transport_request: &VerifierHttpClientSessionTransportRequest,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionSocketByteStreamResponse, BackendExecutionError> {
        self.responses.lock().unwrap().push(frame_response.clone());
        Ok(VerifierHttpClientSessionSocketByteStreamResponse {
            status_code: frame_response.status_code,
            headers: frame_response.headers,
            body: frame_response.body,
        })
    }
}

pub(super) struct RejectingHttpClientSessionFrameIoAdapter;

impl VerifierHttpClientSessionFrameIoAdapter for RejectingHttpClientSessionFrameIoAdapter {
    fn exchange_frame(
        &self,
        _frame_request: &VerifierHttpClientSessionFrameRequest,
        _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
        _socket_request: &VerifierHttpClientSessionSocketRequest,
        _transport_request: &VerifierHttpClientSessionTransportRequest,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionFrameResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session frame io adapter rejected byte exchange".into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionFrameDecoder;

impl VerifierHttpClientSessionFrameDecoder for PanicHttpClientSessionFrameDecoder {
    fn decode_frame(
        &self,
        _frame_response: VerifierHttpClientSessionFrameResponse,
        _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
        _socket_request: &VerifierHttpClientSessionSocketRequest,
        _transport_request: &VerifierHttpClientSessionTransportRequest,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionSocketByteStreamResponse, BackendExecutionError> {
        panic!("frame decoder should not be called when frame io adapter fails")
    }
}
