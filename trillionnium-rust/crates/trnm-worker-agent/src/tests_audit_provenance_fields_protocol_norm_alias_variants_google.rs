use super::*;

#[test]
fn normalized_agent_protocol_accepts_google_aliases_and_variants() {
    assert_eq!(
        normalized_agent_protocol(Some("Google A2A")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google A2A JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google A2A over JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google A2A over HTTP v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent Protocol")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent2Agent")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent2Agent Protocol")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent over Streamable HTTP v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent2Agent over Streamable HTTP v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent2Agent Protocol v2")).as_deref(),
        Some("a2a")
    );
}
