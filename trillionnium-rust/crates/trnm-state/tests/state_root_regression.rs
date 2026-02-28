use trnm_state::*;
use trnm_types::*;

#[test]
fn pending_gov_updates_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    // Base states are identical
    assert_eq!(st1.state_root(), st2.state_root());

    // Add a pending update to st1 only
    st1.set_gov_param(
        1000, 
        7001, 
        "max_block_ms".to_string(), 
        "5000".to_string()
    ).unwrap();

    // Roots should now differ because of pending_gov_updates
    assert_ne!(
        st1.state_root(), 
        st2.state_root(), 
        "State root should incorporate pending governance updates"
    );
}
