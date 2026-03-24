use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendVerificationRequest<'a> {
    pub family: VerificationBackendFamily,
    pub task: &'a TaskObject,
    pub proof_data: &'a [u8],
    /// Parsed canonical TEE attestation payload, when the verifier/backend pair
    /// opts into the structured quote/report handoff contract.
    pub tee_payload: Option<&'a ParsedTeeProofPayload>,
    /// Parsed canonical ZK payload, when the envelope is the structured JSON
    /// shape expected by platform backends.
    pub zk_payload: Option<&'a ParsedZkProofPayload>,
    /// Resolved VK metadata, when the proof family is ZK and the vk_ref was
    /// accepted by the platform registry.
    pub resolved_vk_ref: Option<&'a ResolvedVkRef>,
}

impl<'a> BackendVerificationRequest<'a> {
    pub fn backend_family(&self) -> &'static str {
        self.family.as_str()
    }

    pub fn backend_label(&self, backend_id: &str) -> String {
        format!("{}:{}", self.backend_family(), backend_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendVerificationSuccess {
    pub backend_id: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendSelectionError {
    #[error("verification backend '{backend}' is not registered for family '{family}'")]
    UnknownBackend {
        family: VerificationBackendFamily,
        backend: String,
    },
}

pub trait VerificationBackend: Send + Sync {
    fn backend_id(&self) -> &str;
    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError>;
}

/// Back-compat shim: existing tests and local mock backends still import
/// `ZkBackend`, but the registry is now family-agnostic.
pub trait ZkBackend: Send + Sync {
    fn backend_id(&self) -> &str;
    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError>;
}

impl<T> VerificationBackend for T
where
    T: ZkBackend + ?Sized,
{
    fn backend_id(&self) -> &str {
        ZkBackend::backend_id(self)
    }

    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        ZkBackend::verify(self, request)
    }
}

#[derive(Default)]
pub struct VerificationBackendRegistry {
    backends: HashMap<String, Arc<dyn VerificationBackend>>,
}

impl VerificationBackendRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            backends: HashMap::new(),
        };
        registry.register(Arc::new(NoopVerificationBackend));
        registry
    }

    pub fn register(&mut self, backend: Arc<dyn VerificationBackend>) {
        let raw_key = backend.backend_id().trim().to_ascii_lowercase();
        self.backends.insert(raw_key, Arc::clone(&backend));

        if let Some(normalized_key) = normalize_backend_token(backend.backend_id()) {
            self.backends.entry(normalized_key).or_insert(backend);
        }
    }

    pub fn resolve(
        &self,
        family: VerificationBackendFamily,
        kind: &VerificationBackendKind,
    ) -> Result<Arc<dyn VerificationBackend>, BackendSelectionError> {
        let key = kind.key().trim().to_ascii_lowercase();
        self.backends
            .get(&key)
            .cloned()
            .or_else(|| {
                normalize_backend_token(kind.key())
                    .and_then(|normalized_key| self.backends.get(&normalized_key).cloned())
            })
            .ok_or_else(|| BackendSelectionError::UnknownBackend {
                family,
                backend: key,
            })
    }
}

/// Back-compat alias for the previous ZK-named registry type.
pub type ZkBackendRegistry = VerificationBackendRegistry;

pub struct NoopVerificationBackend;

impl VerificationBackend for NoopVerificationBackend {
    fn backend_id(&self) -> &str {
        "noop"
    }

    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        Err(BackendExecutionError::NotConfigured {
            backend: request.backend_label(self.backend_id()),
        })
    }
}
