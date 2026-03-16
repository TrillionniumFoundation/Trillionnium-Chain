use super::*;
#[test]
fn attach_llm_provenance_normalizes_agent_protocol_casing() {
    let mut rec = MessageIngressRecord {
        request_id: "r5".to_string(),
        task_id: 13,
        channel: "telegram".to_string(),
        user_id: "u5".to_string(),
        session_id: "s5".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik5".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("  MCP  ".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("mcp"));
}

#[test]
fn attach_llm_provenance_accepts_agent_protocol_aliases() {
    let mut rec = MessageIngressRecord {
        request_id: "r5a".to_string(),
        task_id: 130,
        channel: "telegram".to_string(),
        user_id: "u5".to_string(),
        session_id: "s5".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik5a".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("  Model-Context Protocol  ".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("mcp"));

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("MCP v2".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("mcp"));

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("Agent/2/Agent".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("A2A v1".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("agent-to-agent".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("Agent 2 Agent Protocol".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));
}

#[test]
fn normalized_agent_protocol_accepts_punctuation_variants_for_aliases() {
    assert_eq!(
        normalized_agent_protocol(Some("Model.Context.Protocol")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol 2.0")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol JSON-RPC v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent:To:Agent")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent-To-Agent Protocol v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A 2.0")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent-to-Agent JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent-2-Agent Protocol JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol STDIO v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP over JSON-RPC v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP over STDIO v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP over SSE v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP Streamable HTTP v1")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP HTTP v1")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol over HTTP v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol over Streamable HTTP v2"))
            .as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol SSE v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent-to-Agent Protocol STDIO v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over SSE v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over STDIO v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A Streamable HTTP v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A HTTP v1")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent-to-Agent Streamable HTTP v1")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent HTTP v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent over HTTP v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI MCP")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI Model Context Protocol v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI MCP over HTTP v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI MCP over Streamable HTTP v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic MCP Protocol")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic Model Context Protocol v1")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic MCP over Streamable HTTP v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic Model Context Protocol over HTTP v2")).as_deref(),
        Some("mcp")
    );
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

#[test]
fn normalized_agent_protocol_accepts_future_version_suffixes() {
    assert_eq!(
        normalized_agent_protocol(Some("MCP over HTTP v9")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A Streamable HTTP v12")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent Protocol v27")).as_deref(),
        Some("a2a")
    );
}

#[test]
fn normalized_agent_protocol_rejects_oversized_alias_input() {
    let oversized = format!("MCP over HTTP v2 {}", "x".repeat(200));
    assert_eq!(normalized_agent_protocol(Some(&oversized)), None);
}

#[test]
fn normalized_agent_protocol_accepts_websocket_aliases() {
    assert_eq!(
        normalized_agent_protocol(Some("MCP over WebSocket v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP over WS v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP over WebSockets v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI MCP WebSocket v3")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI MCP WebSockets v3")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic MCP over WebSocket v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic MCP over WebSockets v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over WebSocket v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over WS v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over WebSockets v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent WebSocket v4")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent WebSockets v4")).as_deref(),
        Some("a2a")
    );
}
