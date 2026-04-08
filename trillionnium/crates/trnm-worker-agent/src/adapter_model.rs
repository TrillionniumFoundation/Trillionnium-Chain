use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LlmAdapterResponse {
    pub(crate) output_text: String,
    #[serde(default)]
    pub(crate) provider_request_id: Option<String>,
    #[serde(default)]
    pub(crate) provider: Option<String>,
    #[serde(default)]
    pub(crate) model: Option<String>,
    #[serde(default)]
    pub(crate) adapter: Option<String>,
    #[serde(default)]
    pub(crate) agent_protocol: Option<String>,
    #[serde(default)]
    pub(crate) compliance_profile: Option<String>,
}
