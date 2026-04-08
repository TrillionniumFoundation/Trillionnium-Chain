use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifierTransportTemplate {
    mode: VerifierTransportMode,
    profile: String,
    endpoint_base: String,
    timeout_ms: u64,
    auth_scheme: Option<String>,
    auth_ref_prefix: Option<String>,
    retry_policy: RetryBackoffPolicy,
}

impl VerifierTransportTemplate {
    fn render(&self, attestation_target: &str) -> VerifierTransportConfig {
        VerifierTransportConfig {
            mode: self.mode.clone(),
            profile: self.profile.clone(),
            endpoint: format!(
                "{}/{}",
                self.endpoint_base.trim_end_matches('/'),
                attestation_target
            ),
            timeout_ms: self.timeout_ms,
            auth_scheme: self.auth_scheme.clone(),
            auth_ref: self
                .auth_ref_prefix
                .as_ref()
                .map(|prefix| format!("{prefix}.{attestation_target}")),
            retry_policy: self.retry_policy.clone(),
        }
    }
}

pub(super) trait VerifierTransportConfigSource: Send + Sync {
    fn intel_quote_transport_config(&self, attestation_target: &str) -> VerifierTransportConfig;
    fn amd_report_transport_config(&self, attestation_target: &str) -> VerifierTransportConfig;
}

#[derive(Debug, Clone)]
pub(super) struct StaticVerifierTransportConfigSource {
    intel_quote: VerifierTransportTemplate,
    amd_report: VerifierTransportTemplate,
}

impl StaticVerifierTransportConfigSource {
    pub(super) fn mock_defaults() -> Self {
        Self {
            intel_quote: VerifierTransportTemplate {
                mode: VerifierTransportMode::Mock,
                profile: "intel-dcap-mock-default".to_string(),
                endpoint_base: "mock://intel-quote-verifier".to_string(),
                timeout_ms: 1_500,
                auth_scheme: Some("bearer".to_string()),
                auth_ref_prefix: Some("tee.intel.mock-token".to_string()),
                retry_policy: RetryBackoffPolicy {
                    max_attempts: 1,
                    backoff_ms: 0,
                    strategy: RetryBackoffStrategy::Fixed,
                },
            },
            amd_report: VerifierTransportTemplate {
                mode: VerifierTransportMode::Mock,
                profile: "amd-sev-snp-mock-default".to_string(),
                endpoint_base: "mock://amd-report-verifier".to_string(),
                timeout_ms: 1_500,
                auth_scheme: Some("bearer".to_string()),
                auth_ref_prefix: Some("tee.amd.mock-token".to_string()),
                retry_policy: RetryBackoffPolicy {
                    max_attempts: 1,
                    backoff_ms: 0,
                    strategy: RetryBackoffStrategy::Fixed,
                },
            },
        }
    }

    #[allow(dead_code)]
    pub(super) fn external_defaults() -> Self {
        Self {
            intel_quote: VerifierTransportTemplate {
                mode: VerifierTransportMode::External,
                profile: "intel-dcap-external-default".to_string(),
                endpoint_base: "https://intel-verifier.invalid/v1/quote".to_string(),
                timeout_ms: 5_000,
                auth_scheme: Some("bearer".to_string()),
                auth_ref_prefix: Some("tee.intel.external-token".to_string()),
                retry_policy: RetryBackoffPolicy {
                    max_attempts: 3,
                    backoff_ms: 250,
                    strategy: RetryBackoffStrategy::Exponential,
                },
            },
            amd_report: VerifierTransportTemplate {
                mode: VerifierTransportMode::External,
                profile: "amd-sev-snp-external-default".to_string(),
                endpoint_base: "https://amd-verifier.invalid/v1/report".to_string(),
                timeout_ms: 5_000,
                auth_scheme: Some("bearer".to_string()),
                auth_ref_prefix: Some("tee.amd.external-token".to_string()),
                retry_policy: RetryBackoffPolicy {
                    max_attempts: 3,
                    backoff_ms: 250,
                    strategy: RetryBackoffStrategy::Exponential,
                },
            },
        }
    }
}

impl VerifierTransportConfigSource for StaticVerifierTransportConfigSource {
    fn intel_quote_transport_config(&self, attestation_target: &str) -> VerifierTransportConfig {
        self.intel_quote.render(attestation_target)
    }

    fn amd_report_transport_config(&self, attestation_target: &str) -> VerifierTransportConfig {
        self.amd_report.render(attestation_target)
    }
}

#[derive(Debug, Clone)]
pub(super) struct EnvVerifierTransportConfigSource {
    defaults: StaticVerifierTransportConfigSource,
    vars: BTreeMap<String, String>,
}

impl EnvVerifierTransportConfigSource {
    pub(super) fn from_env(defaults: StaticVerifierTransportConfigSource) -> Self {
        Self {
            defaults,
            vars: std::env::vars().collect(),
        }
    }

    #[cfg(test)]
    pub(super) fn from_vars(
        defaults: StaticVerifierTransportConfigSource,
        vars: BTreeMap<String, String>,
    ) -> Self {
        Self { defaults, vars }
    }

    fn render_profile(
        &self,
        profile_prefix: &str,
        fallback: &VerifierTransportTemplate,
        attestation_target: &str,
    ) -> VerifierTransportConfig {
        let key = |suffix: &str| format!("TRNM_TEE_{}_{}", profile_prefix, suffix);
        let mode = self
            .vars
            .get(&key("MODE"))
            .and_then(|value| parse_transport_mode(value))
            .unwrap_or_else(|| fallback.mode.clone());
        let profile = self
            .vars
            .get(&key("PROFILE"))
            .cloned()
            .unwrap_or_else(|| fallback.profile.clone());
        let endpoint_base = self
            .vars
            .get(&key("ENDPOINT_BASE"))
            .cloned()
            .unwrap_or_else(|| fallback.endpoint_base.clone());
        let timeout_ms = self
            .vars
            .get(&key("TIMEOUT_MS"))
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(fallback.timeout_ms);
        let retry_max_attempts = self
            .vars
            .get(&key("RETRY_MAX_ATTEMPTS"))
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(fallback.retry_policy.max_attempts);
        let retry_backoff_ms = self
            .vars
            .get(&key("RETRY_BACKOFF_MS"))
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(fallback.retry_policy.backoff_ms);
        let retry_strategy = self
            .vars
            .get(&key("RETRY_STRATEGY"))
            .and_then(|value| parse_retry_backoff_strategy(value))
            .unwrap_or(fallback.retry_policy.strategy);
        let auth_scheme = self
            .vars
            .get(&key("AUTH_SCHEME"))
            .cloned()
            .or_else(|| fallback.auth_scheme.clone());
        let auth_ref_prefix = self
            .vars
            .get(&key("AUTH_REF_PREFIX"))
            .cloned()
            .or_else(|| fallback.auth_ref_prefix.clone());
        VerifierTransportTemplate {
            mode,
            profile,
            endpoint_base,
            timeout_ms,
            auth_scheme,
            auth_ref_prefix,
            retry_policy: RetryBackoffPolicy {
                max_attempts: retry_max_attempts,
                backoff_ms: retry_backoff_ms,
                strategy: retry_strategy,
            },
        }
        .render(attestation_target)
    }
}

impl VerifierTransportConfigSource for EnvVerifierTransportConfigSource {
    fn intel_quote_transport_config(&self, attestation_target: &str) -> VerifierTransportConfig {
        self.render_profile(
            "INTEL_QUOTE",
            &self.defaults.intel_quote,
            attestation_target,
        )
    }

    fn amd_report_transport_config(&self, attestation_target: &str) -> VerifierTransportConfig {
        self.render_profile("AMD_REPORT", &self.defaults.amd_report, attestation_target)
    }
}

pub(super) fn parse_transport_mode(raw: &str) -> Option<VerifierTransportMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "mock" => Some(VerifierTransportMode::Mock),
        "external" => Some(VerifierTransportMode::External),
        _ => None,
    }
}

pub(super) fn parse_retry_backoff_strategy(raw: &str) -> Option<RetryBackoffStrategy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "fixed" => Some(RetryBackoffStrategy::Fixed),
        "exponential" => Some(RetryBackoffStrategy::Exponential),
        _ => None,
    }
}
