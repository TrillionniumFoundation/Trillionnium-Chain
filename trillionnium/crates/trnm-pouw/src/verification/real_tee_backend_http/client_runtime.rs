use super::*;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RawHttpVerifierResponse {
    status_code: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[allow(dead_code)]
trait VerifierHttpRequestExecutor: Send + Sync {
    fn execute_request(
        &self,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError>;
}

#[allow(dead_code)]
trait VerifierHttpResponseBodyReader: Send + Sync {
    fn read_body(
        &self,
        raw_response: RawHttpVerifierResponse,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpVerifierResponse, BackendExecutionError>;
}

#[allow(dead_code)]
trait VerifierHttpTimeoutHook: Send + Sync {
    fn before_execute(
        &self,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError>;

    fn after_response(
        &self,
        http_request: &HttpVerifierRequest,
        raw_response: &RawHttpVerifierResponse,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError>;
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifierHttpClientRequest {
    method: HttpMethod,
    url: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    timeout_ms: u64,
}

#[allow(dead_code)]
trait VerifierHttpRequestPlanner: Send + Sync {
    fn plan_request(
        &self,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRequest, BackendExecutionError>;
}

#[allow(dead_code)]
struct DirectVerifierHttpRequestPlanner;

impl VerifierHttpRequestPlanner for DirectVerifierHttpRequestPlanner {
    fn plan_request(
        &self,
        http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRequest, BackendExecutionError> {
        Ok(VerifierHttpClientRequest {
            method: http_request.method,
            url: http_request.url.clone(),
            headers: http_request.headers.clone(),
            body: http_request.body.as_bytes().to_vec(),
            timeout_ms: http_request.timeout_ms,
        })
    }
}

#[allow(dead_code)]
trait VerifierHttpClientAdapter: Send + Sync {
    fn execute(
        &self,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError>;
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedVerifierHttpClientConfig {
    profile: String,
    transport_mode: VerifierTransportMode,
    timeout_ms: u64,
}

#[allow(dead_code)]
trait VerifierHttpClientConfigResolver: Send + Sync {
    fn resolve_config(
        &self,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<ResolvedVerifierHttpClientConfig, BackendExecutionError>;
}

#[allow(dead_code)]
struct StaticVerifierHttpClientConfigResolver;

impl VerifierHttpClientConfigResolver for StaticVerifierHttpClientConfigResolver {
    fn resolve_config(
        &self,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<ResolvedVerifierHttpClientConfig, BackendExecutionError> {
        Ok(ResolvedVerifierHttpClientConfig {
            profile: http_request.profile.clone(),
            transport_mode: http_request.transport_mode.clone(),
            timeout_ms: client_request.timeout_ms,
        })
    }
}

#[allow(dead_code)]
trait VerifierHttpClientHandle: Send + Sync {
    fn execute(
        &self,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError>;
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifierHttpClientRuntimeRequest {
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
struct VerifierHttpClientRuntimeResponse {
    status_code: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[allow(dead_code)]
trait VerifierHttpClientRuntimeRequestBuilder: Send + Sync {
    fn build_request(
        &self,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRuntimeRequest, BackendExecutionError>;
}

#[allow(dead_code)]
struct DirectVerifierHttpClientRuntimeRequestBuilder;

impl VerifierHttpClientRuntimeRequestBuilder for DirectVerifierHttpClientRuntimeRequestBuilder {
    fn build_request(
        &self,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRuntimeRequest, BackendExecutionError> {
        Ok(VerifierHttpClientRuntimeRequest {
            method: client_request.method,
            url: client_request.url.clone(),
            headers: client_request.headers.clone(),
            body: client_request.body.clone(),
            timeout_ms: config.timeout_ms,
            profile: config.profile.clone(),
            transport_mode: config.transport_mode.clone(),
        })
    }
}

#[allow(dead_code)]
trait VerifierHttpClientRuntime: Send + Sync {
    fn execute_runtime(
        &self,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRuntimeResponse, BackendExecutionError>;
}
