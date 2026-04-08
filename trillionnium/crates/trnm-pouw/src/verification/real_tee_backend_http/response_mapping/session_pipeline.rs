use super::*;


#[allow(dead_code)]
struct PassthroughVerifierHttpClientSessionResponseReader;

impl VerifierHttpClientSessionResponseReader
    for PassthroughVerifierHttpClientSessionResponseReader
{
    fn read_response(
        &self,
        session_response: VerifierHttpClientSessionResponse,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRuntimeResponse, BackendExecutionError> {
        Ok(VerifierHttpClientRuntimeResponse {
            status_code: session_response.status_code,
            headers: session_response.headers,
            body: session_response.body,
        })
    }
}

#[allow(dead_code)]
struct ExecutorBackedVerifierHttpClientSession {
    request_executor: Arc<dyn VerifierHttpClientSessionRequestExecutor>,
    response_reader: Arc<dyn VerifierHttpClientSessionResponseReader>,
}

#[allow(dead_code)]
impl ExecutorBackedVerifierHttpClientSession {
    fn new() -> Self {
        Self {
            request_executor: Arc::new(WireBackedVerifierHttpClientSessionRequestExecutor::new()),
            response_reader: Arc::new(PassthroughVerifierHttpClientSessionResponseReader),
        }
    }

    #[cfg(test)]
    fn with_components(
        request_executor: Arc<dyn VerifierHttpClientSessionRequestExecutor>,
        response_reader: Arc<dyn VerifierHttpClientSessionResponseReader>,
    ) -> Self {
        Self {
            request_executor,
            response_reader,
        }
    }
}

impl VerifierHttpClientSession for ExecutorBackedVerifierHttpClientSession {
    fn execute_session(
        &self,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRuntimeResponse, BackendExecutionError> {
        let session_request = VerifierHttpClientSessionRequest {
            method: runtime_request.method,
            url: runtime_request.url.clone(),
            headers: runtime_request.headers.clone(),
            body: runtime_request.body.clone(),
            timeout_ms: session_config.timeout_ms,
            profile: session_config.profile.clone(),
            transport_mode: session_config.transport_mode.clone(),
        };
        let session_response = self.request_executor.execute_request(
            &session_request,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )?;
        self.response_reader.read_response(
            session_response,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )
    }
}

#[allow(dead_code)]
struct StaticVerifierHttpClientSessionFactory;

impl VerifierHttpClientSessionFactory for StaticVerifierHttpClientSessionFactory {
    fn open_session(
        &self,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<Box<dyn VerifierHttpClientSession>, BackendExecutionError> {
        Ok(Box::new(ExecutorBackedVerifierHttpClientSession::new()))
    }
}

#[allow(dead_code)]
struct SessionBackedVerifierHttpClientRuntime {
    session_factory: Arc<dyn VerifierHttpClientSessionFactory>,
}

#[allow(dead_code)]
impl SessionBackedVerifierHttpClientRuntime {
    fn new() -> Self {
        Self {
            session_factory: Arc::new(StaticVerifierHttpClientSessionFactory),
        }
    }

    #[cfg(test)]
    fn with_session_factory(session_factory: Arc<dyn VerifierHttpClientSessionFactory>) -> Self {
        Self { session_factory }
    }
}

impl VerifierHttpClientRuntime for SessionBackedVerifierHttpClientRuntime {
    fn execute_runtime(
        &self,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRuntimeResponse, BackendExecutionError> {
        let session_config = ResolvedVerifierHttpClientSessionConfig {
            profile: config.profile.clone(),
            transport_mode: config.transport_mode.clone(),
            timeout_ms: runtime_request.timeout_ms,
        };
        let session = self.session_factory.open_session(
            &session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )?;
        session.execute_session(
            &session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )
    }
}

#[allow(dead_code)]
trait VerifierHttpClientRuntimeResponseAdapter: Send + Sync {
    fn adapt_response(
        &self,
        runtime_response: VerifierHttpClientRuntimeResponse,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError>;
}

#[allow(dead_code)]
struct PassthroughVerifierHttpClientRuntimeResponseAdapter;

impl VerifierHttpClientRuntimeResponseAdapter
    for PassthroughVerifierHttpClientRuntimeResponseAdapter
{
    fn adapt_response(
        &self,
        runtime_response: VerifierHttpClientRuntimeResponse,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError> {
        Ok(RawHttpVerifierResponse {
            status_code: runtime_response.status_code,
            headers: runtime_response.headers,
            body: runtime_response.body,
        })
    }
}

#[allow(dead_code)]
struct RuntimeBackedVerifierHttpClientHandle {
    request_builder: Arc<dyn VerifierHttpClientRuntimeRequestBuilder>,
    runtime: Arc<dyn VerifierHttpClientRuntime>,
    response_adapter: Arc<dyn VerifierHttpClientRuntimeResponseAdapter>,
}

#[allow(dead_code)]
impl RuntimeBackedVerifierHttpClientHandle {
    fn new() -> Self {
        Self {
            request_builder: Arc::new(DirectVerifierHttpClientRuntimeRequestBuilder),
            runtime: Arc::new(SessionBackedVerifierHttpClientRuntime::new()),
            response_adapter: Arc::new(PassthroughVerifierHttpClientRuntimeResponseAdapter),
        }
    }

    #[cfg(test)]
    fn with_components(
        request_builder: Arc<dyn VerifierHttpClientRuntimeRequestBuilder>,
        runtime: Arc<dyn VerifierHttpClientRuntime>,
        response_adapter: Arc<dyn VerifierHttpClientRuntimeResponseAdapter>,
    ) -> Self {
        Self {
            request_builder,
            runtime,
            response_adapter,
        }
    }
}

impl VerifierHttpClientHandle for RuntimeBackedVerifierHttpClientHandle {
    fn execute(
        &self,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError> {
        let runtime_request =
            self.request_builder
                .build_request(config, client_request, http_request, request)?;
        let runtime_response = self.runtime.execute_runtime(
            &runtime_request,
            config,
            client_request,
            http_request,
            request,
        )?;
        self.response_adapter.adapt_response(
            runtime_response,
            config,
            client_request,
            http_request,
            request,
        )
    }
}

#[allow(dead_code)]
struct HandleBackedVerifierHttpClientAdapter {
    config_resolver: Arc<dyn VerifierHttpClientConfigResolver>,
    client_handle: Arc<dyn VerifierHttpClientHandle>,
}

#[allow(dead_code)]
impl HandleBackedVerifierHttpClientAdapter {
    fn new() -> Self {
        Self {
            config_resolver: Arc::new(StaticVerifierHttpClientConfigResolver),
            client_handle: Arc::new(RuntimeBackedVerifierHttpClientHandle::new()),
        }
    }

    #[cfg(test)]
    fn with_components(
        config_resolver: Arc<dyn VerifierHttpClientConfigResolver>,
        client_handle: Arc<dyn VerifierHttpClientHandle>,
    ) -> Self {
        Self {
            config_resolver,
            client_handle,
        }
    }
}

impl VerifierHttpClientAdapter for HandleBackedVerifierHttpClientAdapter {
    fn execute(
        &self,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError> {
        let config = self
            .config_resolver
            .resolve_config(client_request, http_request, request)?;
        self.client_handle
            .execute(&config, client_request, http_request, request)
    }
}

#[allow(dead_code)]
struct AdapterBackedVerifierHttpRequestExecutor {
    planner: Arc<dyn VerifierHttpRequestPlanner>,
    client_adapter: Arc<dyn VerifierHttpClientAdapter>,
}

#[allow(dead_code)]
impl AdapterBackedVerifierHttpRequestExecutor {
    fn new() -> Self {
        Self {
            planner: Arc::new(DirectVerifierHttpRequestPlanner),
            client_adapter: Arc::new(HandleBackedVerifierHttpClientAdapter::new()),
        }
    }

    #[cfg(test)]
    fn with_components(
        planner: Arc<dyn VerifierHttpRequestPlanner>,
        client_adapter: Arc<dyn VerifierHttpClientAdapter>,
    ) -> Self {
        Self {
            planner,
            client_adapter,
        }
    }
}

impl VerifierHttpRequestExecutor for AdapterBackedVerifierHttpRequestExecutor {
    fn execute_request(
        &self,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError> {
        let client_request = self.planner.plan_request(http_request, request)?;
        self.client_adapter
            .execute(&client_request, http_request, request)
    }
}
