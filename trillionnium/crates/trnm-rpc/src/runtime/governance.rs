use trnm_state::StateStore;
use trnm_types::{GovProposalObject, GovProposalStatus};

pub(crate) use super::EMERGENCY_PAUSE_KEY_ID;

pub(crate) fn governance_state() -> StateStore {
    let mut st = StateStore::new();
    let _ = st.put_proposal_new(GovProposalObject {
        proposal_id: 9001,
        title: "update max_block_ms".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Voting,
        version: 1,
    });
    let _ = st.set_gov_param(0, 7001, "max_block_ms".into(), "10".into());
    let _ = st.set_gov_param(
        0,
        EMERGENCY_PAUSE_KEY_ID,
        "emergency_pause".into(),
        "false".into(),
    );
    st
}
