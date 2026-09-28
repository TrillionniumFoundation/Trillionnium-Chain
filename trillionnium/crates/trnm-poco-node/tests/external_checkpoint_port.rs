//! Compatibility of the Node API with the shared M03 checkpoint port.
use trnm_poco_node::{ExternalNodeCheckpointStoreV0, ExternalNodeCheckpointV0};

fn preserve_value(
    value: ExternalNodeCheckpointV0,
) -> trnm_consensus_signer_journal::ExternalNodeCheckpointV0 {
    value
}
fn preserve_port(
    store: &mut dyn ExternalNodeCheckpointStoreV0,
) -> &mut dyn trnm_consensus_signer_journal::ExternalNodeCheckpointStoreV0 {
    store
}
#[test]
fn node_reexports_keep_one_checkpoint_type_and_port() {
    let _ = preserve_value;
    let _ = preserve_port;
    assert_eq!(
        trnm_poco_node::EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0,
        672
    );
    assert_eq!(trnm_poco_node::EXTERNAL_NODE_CHECKPOINT_SCHEMA_V0, 0);
}

const _: () = {
    assert!(!trnm_poco_node::EXTERNAL_NODE_CHECKPOINT_OPERATIONAL_INTEGRATION_V0);
    assert!(!trnm_poco_node::EXTERNAL_NODE_CHECKPOINT_PRODUCTION_ACTIVATION_V0);
};
