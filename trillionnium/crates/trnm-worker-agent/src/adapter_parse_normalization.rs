//! Adapter output/provenance normalization helpers.

pub(super) fn is_invisible_filler(c: char) -> bool {
    matches!(
        c,
        '\u{200B}' // ZERO WIDTH SPACE
            | '\u{200C}' // ZERO WIDTH NON-JOINER
            | '\u{200D}' // ZERO WIDTH JOINER
            | '\u{200E}' // LEFT-TO-RIGHT MARK
            | '\u{200F}' // RIGHT-TO-LEFT MARK
            | '\u{061C}' // ARABIC LETTER MARK (bidi/invisible)
            | '\u{2060}' // WORD JOINER
            | '\u{2061}' // FUNCTION APPLICATION (invisible operator)
            | '\u{2062}' // INVISIBLE TIMES
            | '\u{2063}' // INVISIBLE SEPARATOR
            | '\u{2064}' // INVISIBLE PLUS
            | '\u{2066}' // LEFT-TO-RIGHT ISOLATE
            | '\u{2067}' // RIGHT-TO-LEFT ISOLATE
            | '\u{2068}' // FIRST STRONG ISOLATE
            | '\u{2069}' // POP DIRECTIONAL ISOLATE
            | '\u{00AD}' // SOFT HYPHEN
            | '\u{034F}' // COMBINING GRAPHEME JOINER (non-rendering)
            | '\u{180E}' // MONGOLIAN VOWEL SEPARATOR (historically zero-width)
            | '\u{FE0E}' // VARIATION SELECTOR-15 (text presentation)
            | '\u{FE0F}' // VARIATION SELECTOR-16 (emoji presentation)
            | '\u{FEFF}' // ZERO WIDTH NO-BREAK SPACE / BOM
    )
}

pub(crate) fn verify_model_output(output: &str, max_chars: usize) -> (&'static str, &'static str) {
    let trimmed = output.trim();
    if trimmed.is_empty()
        || !trimmed
            .chars()
            .any(|c| !c.is_whitespace() && !c.is_control() && !is_invisible_filler(c))
    {
        return ("rejected", "empty_output");
    }

    let normalized_char_count = trimmed
        .chars()
        .filter(|c| !c.is_control() && !is_invisible_filler(*c))
        .count();
    if normalized_char_count > max_chars {
        return ("rejected", "output_too_long");
    }
    ("accepted", "ok")
}

pub(crate) fn normalized_optional_field(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn trim_boundary_audit_fillers(value: &str) -> &str {
    value.trim_matches(|c: char| c.is_whitespace() || c.is_control() || is_invisible_filler(c))
}

pub(crate) fn normalized_provider_request_id(value: Option<&str>) -> Option<String> {
    let normalized =
        trim_boundary_audit_fillers(normalized_optional_field(value)?.as_str()).to_string();
    if normalized.is_empty() {
        return None;
    }
    let is_allowed = normalized
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    let starts_and_ends_alnum = normalized
        .chars()
        .next()
        .zip(normalized.chars().last())
        .map(|(start, end)| start.is_ascii_alphanumeric() && end.is_ascii_alphanumeric())
        .unwrap_or(false);
    if is_allowed && starts_and_ends_alnum && normalized.len() <= 128 {
        Some(normalized)
    } else {
        None
    }
}

pub(crate) fn normalized_provenance_label(value: Option<&str>, max_len: usize) -> Option<String> {
    let normalized = normalized_optional_field(value)?;
    let has_disallowed_chars = normalized
        .chars()
        .any(|c| c.is_control() || is_invisible_filler(c) || !c.is_ascii() || c.is_ascii_control());
    if !has_disallowed_chars && normalized.len() <= max_len {
        Some(normalized)
    } else {
        None
    }
}

pub(crate) fn normalized_agent_protocol(value: Option<&str>) -> Option<String> {
    let normalized = normalized_optional_field(value)?.to_ascii_lowercase();
    let has_disallowed_chars = normalized
        .chars()
        .any(|c| c.is_control() || is_invisible_filler(c) || !c.is_ascii());
    if has_disallowed_chars || normalized.len() > 128 {
        return None;
    }

    let alias_key: String = normalized
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let alias_key = alias_key.trim_end_matches(|c: char| c.is_ascii_digit());
    match alias_key {
        "mcp"
        | "mcpv"
        | "mcpv1"
        | "mcpv2"
        | "mcpjsonrpc"
        | "mcpjsonrpcv"
        | "mcpjsonrpcv1"
        | "mcpjsonrpcv2"
        | "mcpoverjsonrpc"
        | "mcpoverjsonrpcv"
        | "mcpoverjsonrpcv1"
        | "mcpoverjsonrpcv2"
        | "mcpstdio"
        | "mcpstdiov"
        | "mcpstdiov1"
        | "mcpstdiov2"
        | "mcpoverstdio"
        | "mcpoverstdiov"
        | "mcpoverstdiov1"
        | "mcpoverstdiov2"
        | "mcpsse"
        | "mcpssev"
        | "mcpssev1"
        | "mcpssev2"
        | "mcpoversse"
        | "mcpoverssev"
        | "mcpoverssev1"
        | "mcpoverssev2"
        | "modelcontextprotocol"
        | "modelcontextprotocolv"
        | "modelcontextprotocolv1"
        | "modelcontextprotocolv2"
        | "modelcontextprotocoljsonrpc"
        | "modelcontextprotocoljsonrpcv"
        | "modelcontextprotocoljsonrpcv1"
        | "modelcontextprotocoljsonrpcv2"
        | "modelcontextprotocolstdio"
        | "modelcontextprotocolstdiov"
        | "modelcontextprotocolstdiov1"
        | "modelcontextprotocolstdiov2"
        | "modelcontextprotocolsse"
        | "modelcontextprotocolssev"
        | "modelcontextprotocolssev1"
        | "modelcontextprotocolssev2"
        | "mcpstreamablehttp"
        | "mcpstreamablehttpv"
        | "mcpstreamablehttpv1"
        | "mcpstreamablehttpv2"
        | "mcpoverstreamablehttp"
        | "mcpoverstreamablehttpv"
        | "mcpoverstreamablehttpv1"
        | "mcpoverstreamablehttpv2"
        | "modelcontextprotocolstreamablehttp"
        | "modelcontextprotocolstreamablehttpv"
        | "modelcontextprotocolstreamablehttpv1"
        | "modelcontextprotocolstreamablehttpv2"
        | "modelcontextprotocoloverstreamablehttp"
        | "modelcontextprotocoloverstreamablehttpv"
        | "modelcontextprotocoloverstreamablehttpv1"
        | "modelcontextprotocoloverstreamablehttpv2"
        | "mcphttp"
        | "mcphttpv"
        | "mcpoverhttp"
        | "mcpoverhttpv"
        | "modelcontextprotocolhttp"
        | "modelcontextprotocolhttpv"
        | "modelcontextprotocoloverhttp"
        | "modelcontextprotocoloverhttpv"
        | "openaimcp"
        | "openaimcpprotocol"
        | "openaimodelcontextprotocol"
        | "openaimodelcontextprotocolv"
        | "openaimodelcontextprotocolv1"
        | "openaimodelcontextprotocolv2"
        | "openaimcphttp"
        | "openaimcphttpv"
        | "openaimcpoverhttp"
        | "openaimcpoverhttpv"
        | "openaimcpstreamablehttp"
        | "openaimcpstreamablehttpv"
        | "openaimcpoverstreamablehttp"
        | "openaimcpoverstreamablehttpv"
        | "openaimcpsse"
        | "openaimcpssev"
        | "openaimcpoversse"
        | "openaimcpoverssev"
        | "openaimodelcontextprotocolstreamablehttp"
        | "openaimodelcontextprotocolstreamablehttpv"
        | "openaimodelcontextprotocoloverstreamablehttp"
        | "openaimodelcontextprotocoloverstreamablehttpv"
        | "openaimodelcontextprotocolsse"
        | "openaimodelcontextprotocolssev"
        | "openaimodelcontextprotocoloversse"
        | "openaimodelcontextprotocoloverssev"
        | "mcpwebsocket"
        | "mcpwebsocketv"
        | "mcpwebsockets"
        | "mcpwebsocketsv"
        | "mcpws"
        | "mcpwsv"
        | "mcpoverwebsocket"
        | "mcpoverwebsocketv"
        | "mcpoverwebsockets"
        | "mcpoverwebsocketsv"
        | "mcpoverws"
        | "mcpoverwsv"
        | "modelcontextprotocolwebsocket"
        | "modelcontextprotocolwebsocketv"
        | "modelcontextprotocolwebsockets"
        | "modelcontextprotocolwebsocketsv"
        | "modelcontextprotocoloverwebsocket"
        | "modelcontextprotocoloverwebsocketv"
        | "modelcontextprotocoloverwebsockets"
        | "modelcontextprotocoloverwebsocketsv"
        | "openaimcpwebsocket"
        | "openaimcpwebsocketv"
        | "openaimcpwebsockets"
        | "openaimcpwebsocketsv"
        | "openaimcpoverwebsocket"
        | "openaimcpoverwebsocketv"
        | "openaimcpoverwebsockets"
        | "openaimcpoverwebsocketsv"
        | "openaimodelcontextprotocolwebsocket"
        | "openaimodelcontextprotocolwebsocketv"
        | "openaimodelcontextprotocolwebsockets"
        | "openaimodelcontextprotocolwebsocketsv"
        | "openaimodelcontextprotocoloverwebsocket"
        | "openaimodelcontextprotocoloverwebsocketv"
        | "openaimodelcontextprotocoloverwebsockets"
        | "openaimodelcontextprotocoloverwebsocketsv"
        | "anthropicmcp"
        | "anthropicmcpprotocol"
        | "anthropicmodelcontextprotocol"
        | "anthropicmodelcontextprotocolv"
        | "anthropicmodelcontextprotocolv1"
        | "anthropicmodelcontextprotocolv2"
        | "anthropicmcphttp"
        | "anthropicmcphttpv"
        | "anthropicmcpoverhttp"
        | "anthropicmcpoverhttpv"
        | "anthropicmcpstreamablehttp"
        | "anthropicmcpstreamablehttpv"
        | "anthropicmcpoverstreamablehttp"
        | "anthropicmcpoverstreamablehttpv"
        | "anthropicmcpsse"
        | "anthropicmcpssev"
        | "anthropicmcpoversse"
        | "anthropicmcpoverssev"
        | "anthropicmodelcontextprotocolhttp"
        | "anthropicmodelcontextprotocolhttpv"
        | "anthropicmodelcontextprotocoloverhttp"
        | "anthropicmodelcontextprotocoloverhttpv"
        | "anthropicmodelcontextprotocolstreamablehttp"
        | "anthropicmodelcontextprotocolstreamablehttpv"
        | "anthropicmodelcontextprotocoloverstreamablehttp"
        | "anthropicmodelcontextprotocoloverstreamablehttpv"
        | "anthropicmodelcontextprotocolsse"
        | "anthropicmodelcontextprotocolssev"
        | "anthropicmodelcontextprotocoloversse"
        | "anthropicmodelcontextprotocoloverssev"
        | "anthropicmcpwebsocket"
        | "anthropicmcpwebsocketv"
        | "anthropicmcpwebsockets"
        | "anthropicmcpwebsocketsv"
        | "anthropicmcpoverwebsocket"
        | "anthropicmcpoverwebsocketv"
        | "anthropicmcpoverwebsockets"
        | "anthropicmcpoverwebsocketsv"
        | "anthropicmodelcontextprotocolwebsocket"
        | "anthropicmodelcontextprotocolwebsocketv"
        | "anthropicmodelcontextprotocolwebsockets"
        | "anthropicmodelcontextprotocolwebsocketsv"
        | "anthropicmodelcontextprotocoloverwebsocket"
        | "anthropicmodelcontextprotocoloverwebsocketv"
        | "anthropicmodelcontextprotocoloverwebsockets"
        | "anthropicmodelcontextprotocoloverwebsocketsv" => Some("mcp".to_string()),
        "a2a"
        | "a2av"
        | "a2av1"
        | "a2av2"
        | "a2ajsonrpc"
        | "a2ajsonrpcv"
        | "a2ajsonrpcv1"
        | "a2ajsonrpcv2"
        | "a2aoverjsonrpc"
        | "a2aoverjsonrpcv"
        | "a2aoverjsonrpcv1"
        | "a2aoverjsonrpcv2"
        | "a2astdio"
        | "a2astdiov"
        | "a2astdiov1"
        | "a2astdiov2"
        | "a2aoverstdio"
        | "a2aoverstdiov"
        | "a2aoverstdiov1"
        | "a2aoverstdiov2"
        | "a2asse"
        | "a2assev"
        | "a2assev1"
        | "a2assev2"
        | "a2aoversse"
        | "a2aoverssev"
        | "a2aoverssev1"
        | "a2aoverssev2"
        | "a2aprotocol"
        | "agent2agent"
        | "agenttoagent"
        | "agent2agentprotocol"
        | "agenttoagentprotocol"
        | "agent2agentprotocolv"
        | "agent2agentprotocolv1"
        | "agent2agentprotocolv2"
        | "agenttoagentprotocolv"
        | "agenttoagentprotocolv1"
        | "agenttoagentprotocolv2"
        | "agent2agentv"
        | "agent2agentv1"
        | "agent2agentv2"
        | "agenttoagentv"
        | "agenttoagentv1"
        | "agenttoagentv2"
        | "agent2agentjsonrpc"
        | "agent2agentjsonrpcv"
        | "agent2agentjsonrpcv1"
        | "agent2agentjsonrpcv2"
        | "agent2agentstdio"
        | "agent2agentstdiov"
        | "agent2agentstdiov1"
        | "agent2agentstdiov2"
        | "agenttoagentjsonrpc"
        | "agenttoagentjsonrpcv"
        | "agenttoagentjsonrpcv1"
        | "agenttoagentjsonrpcv2"
        | "agenttoagentstdio"
        | "agenttoagentstdiov"
        | "agenttoagentstdiov1"
        | "agenttoagentstdiov2"
        | "agent2agentprotocoljsonrpc"
        | "agent2agentprotocoljsonrpcv"
        | "agent2agentprotocoljsonrpcv1"
        | "agent2agentprotocoljsonrpcv2"
        | "agent2agentprotocolstdio"
        | "agent2agentprotocolstdiov"
        | "agent2agentprotocolstdiov1"
        | "agent2agentprotocolstdiov2"
        | "agenttoagentprotocoljsonrpc"
        | "agenttoagentprotocoljsonrpcv"
        | "agenttoagentprotocoljsonrpcv1"
        | "agenttoagentprotocoljsonrpcv2"
        | "agenttoagentprotocolstdio"
        | "agenttoagentprotocolstdiov"
        | "agenttoagentprotocolstdiov1"
        | "agenttoagentprotocolstdiov2"
        | "a2astreamablehttp"
        | "a2astreamablehttpv"
        | "a2astreamablehttpv1"
        | "a2astreamablehttpv2"
        | "a2aoverstreamablehttp"
        | "a2aoverstreamablehttpv"
        | "a2aoverstreamablehttpv1"
        | "a2aoverstreamablehttpv2"
        | "a2ahttp"
        | "a2ahttpv"
        | "a2aoverhttp"
        | "a2aoverhttpv"
        | "a2awebsocket"
        | "a2awebsocketv"
        | "a2awebsockets"
        | "a2awebsocketsv"
        | "a2aws"
        | "a2awsv"
        | "a2aoverwebsocket"
        | "a2aoverwebsocketv"
        | "a2aoverwebsockets"
        | "a2aoverwebsocketsv"
        | "a2aoverws"
        | "a2aoverwsv"
        | "agent2agenthttp"
        | "agent2agenthttpv"
        | "agenttoagenthttp"
        | "agenttoagenthttpv"
        | "agent2agentprotocolhttp"
        | "agent2agentprotocolhttpv"
        | "agenttoagentprotocolhttp"
        | "agenttoagentprotocolhttpv"
        | "agent2agentwebsocket"
        | "agent2agentwebsocketv"
        | "agent2agentwebsockets"
        | "agent2agentwebsocketsv"
        | "agent2agentoverwebsocket"
        | "agent2agentoverwebsocketv"
        | "agent2agentoverwebsockets"
        | "agent2agentoverwebsocketsv"
        | "agenttoagentwebsocket"
        | "agenttoagentwebsocketv"
        | "agenttoagentwebsockets"
        | "agenttoagentwebsocketsv"
        | "agenttoagentoverwebsocket"
        | "agenttoagentoverwebsocketv"
        | "agenttoagentoverwebsockets"
        | "agenttoagentoverwebsocketsv"
        | "agent2agentprotocolwebsocket"
        | "agent2agentprotocolwebsocketv"
        | "agent2agentprotocolwebsockets"
        | "agent2agentprotocolwebsocketsv"
        | "agent2agentprotocoloverwebsocket"
        | "agent2agentprotocoloverwebsocketv"
        | "agent2agentprotocoloverwebsockets"
        | "agent2agentprotocoloverwebsocketsv"
        | "agenttoagentprotocolwebsocket"
        | "agenttoagentprotocolwebsocketv"
        | "agenttoagentprotocolwebsockets"
        | "agenttoagentprotocolwebsocketsv"
        | "agenttoagentprotocoloverwebsocket"
        | "agenttoagentprotocoloverwebsocketv"
        | "agenttoagentprotocoloverwebsockets"
        | "agenttoagentprotocoloverwebsocketsv"
        | "agent2agentstreamablehttp"
        | "agent2agentstreamablehttpv"
        | "agent2agentstreamablehttpv1"
        | "agent2agentstreamablehttpv2"
        | "agenttoagentstreamablehttp"
        | "agenttoagentstreamablehttpv"
        | "agenttoagentstreamablehttpv1"
        | "agenttoagentstreamablehttpv2"
        | "googlea2a"
        | "googlea2av"
        | "googlea2ajsonrpc"
        | "googlea2ajsonrpcv"
        | "googlea2aoverjsonrpc"
        | "googlea2aoverjsonrpcv"
        | "googlea2aprotocol"
        | "googlea2ahttp"
        | "googlea2ahttpv"
        | "googlea2aoverhttp"
        | "googlea2aoverhttpv"
        | "googleagent2agent"
        | "googleagent2agentprotocol"
        | "googleagent2agentv"
        | "googleagent2agentprotocolv"
        | "googleagent2agentjsonrpc"
        | "googleagent2agentjsonrpcv"
        | "googleagent2agentstreamablehttp"
        | "googleagent2agentstreamablehttpv"
        | "googleagent2agentoverstreamablehttp"
        | "googleagent2agentoverstreamablehttpv"
        | "googleagenttoagent"
        | "googleagenttoagentprotocol"
        | "googleagenttoagentv"
        | "googleagenttoagentprotocolv"
        | "googleagenttoagentjsonrpc"
        | "googleagenttoagentjsonrpcv"
        | "googleagenttoagentstreamablehttp"
        | "googleagenttoagentstreamablehttpv"
        | "googleagenttoagentoverstreamablehttp"
        | "googleagenttoagentoverstreamablehttpv"
        | "googleagent2agenthttp"
        | "googleagent2agenthttpv"
        | "googleagent2agentoverhttp"
        | "googleagent2agentoverhttpv"
        | "googleagent2agentwebsocket"
        | "googleagent2agentwebsocketv"
        | "googleagent2agentwebsockets"
        | "googleagent2agentwebsocketsv"
        | "googleagent2agentoverwebsocket"
        | "googleagent2agentoverwebsocketv"
        | "googleagent2agentoverwebsockets"
        | "googleagent2agentoverwebsocketsv"
        | "googleagenttoagenthttp"
        | "googleagenttoagenthttpv"
        | "googleagenttoagentoverhttp"
        | "googleagenttoagentoverhttpv"
        | "googleagenttoagentwebsocket"
        | "googleagenttoagentwebsocketv"
        | "googleagenttoagentwebsockets"
        | "googleagenttoagentwebsocketsv"
        | "googleagenttoagentoverwebsocket"
        | "googleagenttoagentoverwebsocketv"
        | "googleagenttoagentoverwebsockets"
        | "googleagenttoagentoverwebsocketsv" => Some("a2a".to_string()),
        _ => None,
    }
}

pub(crate) fn normalized_compliance_profile(value: Option<&str>) -> Option<String> {
    let raw = normalized_optional_field(value)?.to_ascii_lowercase();
    let has_disallowed_chars = raw
        .chars()
        .any(|c| c.is_control() || is_invisible_filler(c) || !c.is_ascii());
    if has_disallowed_chars {
        return None;
    }

    let normalized: String = raw
        .chars()
        .map(|c| if c.is_ascii_whitespace() { '-' } else { c })
        .collect();
    let is_allowed = normalized.chars().all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.' | '/' | '\\')
    });
    let starts_with_alpha_and_ends_alnum = normalized
        .chars()
        .next()
        .zip(normalized.chars().last())
        .map(|(start, end)| start.is_ascii_lowercase() && end.is_ascii_alphanumeric())
        .unwrap_or(false);
    let has_adjacent_separators = normalized
        .chars()
        .fold((false, false), |(found, prev_sep), c| {
            let is_sep = matches!(c, '-' | '_' | '.' | '/' | '\\');
            (found || (prev_sep && is_sep), is_sep)
        })
        .0;
    let has_alpha = normalized.chars().any(|c| c.is_ascii_lowercase());
    let has_separator = normalized
        .chars()
        .any(|c| matches!(c, '-' | '_' | '.' | '/' | '\\'));
    if is_allowed
        && starts_with_alpha_and_ends_alnum
        && !has_adjacent_separators
        && normalized.len() <= 64
        && has_alpha
        && has_separator
    {
        Some(
            normalized
                .chars()
                .map(|c| {
                    if matches!(c, '_' | '.' | '/' | '\\') {
                        '-'
                    } else {
                        c
                    }
                })
                .collect(),
        )
    } else {
        None
    }
}

fn collapse_contract_match_delimiters(value: &str) -> String {
    value
        .chars()
        .filter_map(|ch| match ch {
            '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{2063}' | '\u{feff}' => None,
            '‐' | '‑' | '‒' | '–' | '—' | '―' | '−' | '－' => Some('-'),
            other => Some(other),
        })
        .collect()
}

pub(crate) fn context_matches_token(context: &str, token: &str) -> bool {
    fn normalize_for_contract_match(value: &str) -> String {
        let lowered = collapse_contract_match_delimiters(value).to_ascii_lowercase();
        let mut out = String::with_capacity(lowered.len());
        let mut prev_space = false;
        for ch in lowered.chars() {
            if ch.is_ascii_alphanumeric() {
                out.push(ch);
                prev_space = false;
            } else if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        }
        out.trim().to_string()
    }

    let normalized_context = collapse_contract_match_delimiters(context).to_ascii_lowercase();
    let normalized_token = collapse_contract_match_delimiters(token).to_ascii_lowercase();
    let context_with_spaces = normalized_context.replace(['-', '_'], " ");
    let token_with_spaces = normalized_token.replace(['-', '_'], " ");
    let normalized_context_relaxed = normalize_for_contract_match(context);
    let normalized_token_relaxed = normalize_for_contract_match(token);
    let normalized_context_compact = normalized_context_relaxed.replace(' ', "");
    let normalized_token_compact = normalized_token_relaxed.replace(' ', "");

    normalized_context.contains(&normalized_token)
        || normalized_context.contains(&normalized_token.replace('-', "_"))
        || normalized_context.contains(&normalized_token.replace('_', "-"))
        || context_with_spaces.contains(&token_with_spaces)
        || (!normalized_token_relaxed.is_empty()
            && normalized_context_relaxed.contains(&normalized_token_relaxed))
        || (!normalized_token_compact.is_empty()
            && normalized_context_compact.contains(&normalized_token_compact))
}
