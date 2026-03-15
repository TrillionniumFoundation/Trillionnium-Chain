use crate::proof_adapter_utils::has_non_empty_auditable_value;
use crate::LlmAdapterResponse;

pub(crate) fn verify_standard_adapter_output(output: &str, max_chars: usize) -> (bool, String) {
    let (status, code): (&str, &str) = crate::verify_model_output(output, max_chars);
    (status == "accepted", code.to_string())
}

pub(crate) fn verify_tee_receipt_adapter_output(output: &str, max_chars: usize) -> (bool, String) {
    let (ok, code) = verify_standard_adapter_output(output, max_chars);
    if !ok {
        return (false, code);
    }
    (true, "tee_receipt_ok".to_string())
}

pub(crate) fn verify_zk_receipt_adapter_output(output: &str, max_chars: usize) -> (bool, String) {
    let (ok, code) = verify_standard_adapter_output(output, max_chars);
    if !ok {
        return (false, code);
    }
    (true, "zk_receipt_ok".to_string())
}

pub(crate) fn validate_receipt_adapter_response(
    adapter_name: &str,
    parsed: &LlmAdapterResponse,
    is_accepted_label: fn(Option<&str>) -> bool,
) -> Result<(), String> {
    let request_id_ok = has_non_empty_auditable_value(parsed.provider_request_id.as_deref());
    if !request_id_ok {
        return Err(format!("{adapter_name}-missing-provider-request-id"));
    }

    let adapter_ok = is_accepted_label(parsed.adapter.as_deref());
    if !adapter_ok {
        return Err(format!("{adapter_name}-missing-adapter-label"));
    }

    Ok(())
}
