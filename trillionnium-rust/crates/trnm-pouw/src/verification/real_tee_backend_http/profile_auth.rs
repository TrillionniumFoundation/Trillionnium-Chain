use super::*;

use super::*;

struct RegistryBackedVerifierProfileResolver {
    source: Arc<dyn VerifierProfileRegistrySource>,
}

impl RegistryBackedVerifierProfileResolver {
    fn with_builtin_defaults() -> Self {
        Self {
            source: Arc::new(StaticVerifierProfileRegistrySource::with_builtin_defaults()),
        }
    }

    #[allow(dead_code)]
    fn with_runtime_overlays_from_env() -> Self {
        Self {
            source: Arc::new(EnvJsonVerifierProfileRegistrySource::from_env(
                RuntimeVerifierProfileRegistry::with_builtin_defaults(),
            )),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn with_registry(registry: RuntimeVerifierProfileRegistry) -> Self {
        Self {
            source: Arc::new(StaticVerifierProfileRegistrySource::from_registry(registry)),
        }
    }
}

impl VerifierProfileResolver for RegistryBackedVerifierProfileResolver {
    fn resolve(
        &self,
        transport: &VerifierTransportConfig,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<ResolvedVerifierProfile, BackendExecutionError> {
        let registry = self.source.load(request)?;
        let Some(entry) = registry.resolve(&transport.profile) else {
            return Err(BackendExecutionError::NotConfigured {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
            });
        };
        if entry.mode != transport.mode {
            return Err(BackendExecutionError::MalformedProof {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: format!(
                    "verifier profile '{}' does not match transport mode",
                    transport.profile
                ),
            });
        }
        if !transport.endpoint.starts_with(&entry.endpoint_prefix) {
            return Err(BackendExecutionError::MalformedProof {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: format!(
                    "verifier profile '{}' does not match endpoint prefix",
                    transport.profile
                ),
            });
        }
        if entry.auth_required
            && transport
                .auth_ref
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
        {
            return Err(BackendExecutionError::NotConfigured {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
            });
        }
        Ok(ResolvedVerifierProfile {
            mode: transport.mode.clone(),
            profile: transport.profile.clone(),
            endpoint: transport.endpoint.clone(),
            timeout_ms: transport.timeout_ms,
        })
    }
}

trait VerifierAuthInjector: Send + Sync {
    fn inject(
        &self,
        transport: &VerifierTransportConfig,
        headers: &mut BTreeMap<String, String>,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError>;
}

struct HeaderVerifierAuthInjector;

impl VerifierAuthInjector for HeaderVerifierAuthInjector {
    fn inject(
        &self,
        transport: &VerifierTransportConfig,
        headers: &mut BTreeMap<String, String>,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError> {
        match transport.mode {
            VerifierTransportMode::Mock => Ok(()),
            VerifierTransportMode::External => {
                let auth_scheme = transport
                    .auth_scheme
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| BackendExecutionError::NotConfigured {
                        backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    })?;
                let auth_ref = transport
                    .auth_ref
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| BackendExecutionError::NotConfigured {
                        backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    })?;
                headers.insert(
                    "authorization".to_string(),
                    format!("{} {}", auth_scheme, auth_ref),
                );
                Ok(())
            }
        }
    }
}
