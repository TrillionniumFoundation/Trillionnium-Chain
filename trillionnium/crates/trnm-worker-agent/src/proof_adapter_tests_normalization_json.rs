use super::*;

#[test]
fn last_balanced_json_object_ignores_braces_inside_strings() {
    let payload = "log {\"message\":\"brace } kept\"}\nlog {\"output_text\":\"ok\",\"provider_request_id\":\"r4\"}";
    let candidate = last_balanced_json_object(payload).expect("expected a balanced json object");
    assert_eq!(
        candidate,
        "{\"output_text\":\"ok\",\"provider_request_id\":\"r4\"}"
    );
}
