use super::*;


#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedVerifierHttpClientSessionConfig {
    profile: String,
    transport_mode: VerifierTransportMode,
    timeout_ms: u64,
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionFactory: Send + Sync {
    fn open_session(
        &self,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<Box<dyn VerifierHttpClientSession>, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSession: Send + Sync {
    fn execute_session(
        &self,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRuntimeResponse, BackendExecutionError>;
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifierHttpClientSessionRequest {
    method: HttpMethod,
    url: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    timeout_ms: u64,
    profile: String,
    transport_mode: VerifierTransportMode,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifierHttpClientSessionResponse {
    status_code: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionRequestExecutor: Send + Sync {
    fn execute_request(
        &self,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionResponse, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionResponseReader: Send + Sync {
    fn read_response(
        &self,
        session_response: VerifierHttpClientSessionResponse,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRuntimeResponse, BackendExecutionError>;
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifierHttpClientSessionWireRequest {
    method: HttpMethod,
    url: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    timeout_ms: u64,
    profile: String,
    transport_mode: VerifierTransportMode,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifierHttpClientSessionWireResponse {
    status_code: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionWireRequestBuilder: Send + Sync {
    fn build_wire_request(
        &self,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionWireRequest, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionWireExecutor: Send + Sync {
    fn execute_wire(
        &self,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionWireResponse, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionWireResponseParser: Send + Sync {
    fn parse_wire_response(
        &self,
        wire_response: VerifierHttpClientSessionWireResponse,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionResponse, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) struct DirectVerifierHttpClientSessionWireRequestBuilder;

impl VerifierHttpClientSessionWireRequestBuilder
    for DirectVerifierHttpClientSessionWireRequestBuilder
{
    fn build_wire_request(
        &self,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionWireRequest, BackendExecutionError> {
        Ok(VerifierHttpClientSessionWireRequest {
            method: session_request.method,
            url: session_request.url.clone(),
            headers: session_request.headers.clone(),
            body: session_request.body.clone(),
            timeout_ms: session_config.timeout_ms,
            profile: session_config.profile.clone(),
            transport_mode: session_config.transport_mode.clone(),
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifierHttpClientSessionCallRequest {
    method: HttpMethod,
    url: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    timeout_ms: u64,
    profile: String,
    transport_mode: VerifierTransportMode,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifierHttpClientSessionCallResponse {
    status_code: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionCallBuilder: Send + Sync {
    fn build_call(
        &self,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionCallRequest, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionCallExecutor: Send + Sync {
    fn execute_call(
        &self,
        call_request: &VerifierHttpClientSessionCallRequest,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionCallResponse, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionCallResponseParser: Send + Sync {
    fn parse_call_response(
        &self,
        call_response: VerifierHttpClientSessionCallResponse,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionWireResponse, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) struct DirectVerifierHttpClientSessionCallBuilder;

impl VerifierHttpClientSessionCallBuilder for DirectVerifierHttpClientSessionCallBuilder {
    fn build_call(
        &self,
        wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionCallRequest, BackendExecutionError> {
        Ok(VerifierHttpClientSessionCallRequest {
            method: wire_request.method,
            url: wire_request.url.clone(),
            headers: wire_request.headers.clone(),
            body: wire_request.body.clone(),
            timeout_ms: wire_request.timeout_ms,
            profile: wire_request.profile.clone(),
            transport_mode: wire_request.transport_mode.clone(),
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifierHttpClientSessionTransportRequest {
    method: HttpMethod,
    url: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    timeout_ms: u64,
    profile: String,
    transport_mode: VerifierTransportMode,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifierHttpClientSessionTransportRawResponse {
    status_code: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionTransportRequestBuilder: Send + Sync {
    fn build_transport_request(
        &self,
        call_request: &VerifierHttpClientSessionCallRequest,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionTransportRequest, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionTransportAdapter: Send + Sync {
    fn send_transport(
        &self,
        transport_request: &VerifierHttpClientSessionTransportRequest,
        call_request: &VerifierHttpClientSessionCallRequest,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionTransportRawResponse, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionRawIoResponseParser: Send + Sync {
    fn parse_raw_response(
        &self,
        raw_response: VerifierHttpClientSessionTransportRawResponse,
        call_request: &VerifierHttpClientSessionCallRequest,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionCallResponse, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) struct DirectVerifierHttpClientSessionTransportRequestBuilder;

impl VerifierHttpClientSessionTransportRequestBuilder
    for DirectVerifierHttpClientSessionTransportRequestBuilder
{
    fn build_transport_request(
        &self,
        call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionTransportRequest, BackendExecutionError> {
        Ok(VerifierHttpClientSessionTransportRequest {
            method: call_request.method,
            url: call_request.url.clone(),
            headers: call_request.headers.clone(),
            body: call_request.body.clone(),
            timeout_ms: call_request.timeout_ms,
            profile: call_request.profile.clone(),
            transport_mode: call_request.transport_mode.clone(),
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifierHttpClientSessionSocketRequest {
    method: HttpMethod,
    url: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    timeout_ms: u64,
    profile: String,
    transport_mode: VerifierTransportMode,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifierHttpClientSessionSocketByteStreamResponse {
    status_code: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionSocketRequestBuilder: Send + Sync {
    fn build_socket_request(
        &self,
        transport_request: &VerifierHttpClientSessionTransportRequest,
        call_request: &VerifierHttpClientSessionCallRequest,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionSocketRequest, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionSocketAdapter: Send + Sync {
    fn execute_socket(
        &self,
        socket_request: &VerifierHttpClientSessionSocketRequest,
        transport_request: &VerifierHttpClientSessionTransportRequest,
        call_request: &VerifierHttpClientSessionCallRequest,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionSocketByteStreamResponse, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionByteStreamResponseParser: Send + Sync {
    fn parse_byte_stream(
        &self,
        socket_response: VerifierHttpClientSessionSocketByteStreamResponse,
        transport_request: &VerifierHttpClientSessionTransportRequest,
        call_request: &VerifierHttpClientSessionCallRequest,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionTransportRawResponse, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) struct DirectVerifierHttpClientSessionSocketRequestBuilder;

impl VerifierHttpClientSessionSocketRequestBuilder
    for DirectVerifierHttpClientSessionSocketRequestBuilder
{
    fn build_socket_request(
        &self,
        transport_request: &VerifierHttpClientSessionTransportRequest,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionSocketRequest, BackendExecutionError> {
        Ok(VerifierHttpClientSessionSocketRequest {
            method: transport_request.method,
            url: transport_request.url.clone(),
            headers: transport_request.headers.clone(),
            body: transport_request.body.clone(),
            timeout_ms: transport_request.timeout_ms,
            profile: transport_request.profile.clone(),
            transport_mode: transport_request.transport_mode.clone(),
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedVerifierHttpClientSessionSocketConnectionConfig {
    profile: String,
    transport_mode: VerifierTransportMode,
    timeout_ms: u64,
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionSocketConnectionOpener: Send + Sync {
    fn open_connection(
        &self,
        connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
        socket_request: &VerifierHttpClientSessionSocketRequest,
        transport_request: &VerifierHttpClientSessionTransportRequest,
        call_request: &VerifierHttpClientSessionCallRequest,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<Box<dyn VerifierHttpClientSessionSocketByteChannel>, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionSocketByteChannel: Send + Sync {
    fn exchange_bytes(
        &self,
        connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
        socket_request: &VerifierHttpClientSessionSocketRequest,
        transport_request: &VerifierHttpClientSessionTransportRequest,
        call_request: &VerifierHttpClientSessionCallRequest,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionSocketByteStreamResponse, BackendExecutionError>;
}
