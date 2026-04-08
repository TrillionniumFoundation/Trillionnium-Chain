use super::*;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VkRefResolutionError {
    #[error("invalid zk payload: vk_ref is required")]
    Missing,
    #[error("invalid zk payload: unknown vk_ref '{vk_ref}'")]
    Unknown { vk_ref: String },
}

impl VkRefResolutionError {
    pub fn into_backend_execution_error(self) -> BackendExecutionError {
        match self {
            Self::Missing => BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: vk_ref is required".to_string(),
            },
            Self::Unknown { vk_ref } => BackendExecutionError::InvalidProof {
                backend: "zk:payload".to_string(),
                reason: format!("invalid zk payload: unknown vk_ref '{vk_ref}'"),
            },
        }
    }
}

pub trait VkRefResolver: Send + Sync {
    fn resolve(&self, vk_ref: &str) -> Result<ResolvedVkRef, VkRefResolutionError>;
}

#[derive(Default)]
pub struct VkRefRegistry {
    entries: HashMap<String, ResolvedVkRef>,
}

impl VkRefRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            entries: HashMap::new(),
        };
        registry.register_demo_dev_defaults();
        registry
    }

    pub fn register(&mut self, resolved: ResolvedVkRef) {
        self.entries.insert(resolved.vk_ref.clone(), resolved);
    }

    fn register_demo_dev_defaults(&mut self) {
        for (vk_ref, zk_system) in [
            ("vk://trnm/dev/mock-groth16/v1", Some("groth16")),
            ("vk://trnm/dev/mock-groth16/valid", Some("groth16")),
            ("vk://trnm/dev/mock-groth16/invalid", Some("groth16")),
            ("vk://trnm/dev/mock-plonk/v1", Some("plonk")),
            ("vk://trnm/dev/mock-plonk/valid", Some("plonk")),
            ("vk://trnm/dev/mock-plonk/invalid", Some("plonk")),
            ("vk://trnm/dev/mock-halo2/v1", Some("halo2")),
            ("vk://trnm/dev/mock-stark/v1", Some("stark")),
            ("vk://trnm/dev/mock-risc0/v1", Some("risc0")),
            ("vk://trnm/dev/mock-sp1/v1", Some("sp1")),
            ("vk://trnm/dev/mock-no-system/v1", None),
        ] {
            self.register(ResolvedVkRef {
                vk_ref: vk_ref.to_string(),
                scope: "dev".to_string(),
                zk_system: zk_system.map(str::to_string),
            });
        }
    }
}

impl VkRefResolver for VkRefRegistry {
    fn resolve(&self, vk_ref: &str) -> Result<ResolvedVkRef, VkRefResolutionError> {
        if vk_ref.trim().is_empty() {
            return Err(VkRefResolutionError::Missing);
        }

        self.entries
            .get(vk_ref)
            .cloned()
            .ok_or_else(|| VkRefResolutionError::Unknown {
                vk_ref: vk_ref.to_string(),
            })
    }
}

pub fn resolve_zk_vk_ref(
    resolver: &dyn VkRefResolver,
    payload: &ParsedZkProofPayload,
) -> Result<ResolvedVkRef, BackendExecutionError> {
    let resolved = resolver
        .resolve(&payload.vk_ref)
        .map_err(VkRefResolutionError::into_backend_execution_error)?;

    if let (Some(payload_system), Some(resolved_system)) = (
        payload.zk_system.as_deref().and_then(normalize_zk_system),
        resolved.zk_system.as_deref().and_then(normalize_zk_system),
    ) {
        if payload_system != resolved_system {
            return Err(BackendExecutionError::InvalidProof {
                backend: "zk:payload".to_string(),
                reason: format!(
                    "invalid zk payload: zk_system '{payload_system}' does not match vk_ref '{}'",
                    resolved.vk_ref
                ),
            });
        }
    }

    Ok(resolved)
}
