//! Bind an exact retained acceptance packet to the current task settlement.
//! This is a local, generation-scoped observation, never execution authority.
use super::Node;
use crate::{ensure, sequence_root, Error, Packet, Result};
use serde::Serialize;
use trnm_mvcc_fee::pon_executor::State;
use trnm_protocol::pon_wire::{Envelope, Hash};

#[derive(Serialize)]
pub(super) struct AcceptedTaskObservation {
    schema_version: u32,
    task_id: String,
    owner: String,
    provider: String,
    output_sha256: String,
    accept_tx_id: String,
    accepted_in_exact_packet: bool,
    current_status: &'static str,
}

fn unique_acceptance(transactions: &[Vec<u8>]) -> Result<Option<Envelope>> {
    let mut acceptance = None;
    for raw in transactions {
        let tx = Envelope::decode(raw)
            .map_err(|_| Error::from("TRANSACTION_CODEC").local_integrity())?;
        if tx.tag == 5 {
            // A multi-accept block cannot name one unambiguous upgrade in this
            // optional convenience observation.
            if acceptance.is_some() {
                return Ok(None);
            }
            acceptance = Some(tx);
        }
    }
    Ok(acceptance)
}

impl Node {
    pub(super) fn accepted_task_observation(
        &self,
        packet: &Packet,
        tip: Hash,
        generation: u64,
    ) -> Result<Option<AcceptedTaskObservation>> {
        ensure(
            packet.header.transactions == sequence_root("transactions", &packet.transactions),
            "ROOT",
        )
        .map_err(Error::local_integrity)?;
        let Some(tx) = unique_acceptance(&packet.transactions)? else {
            return Ok(None);
        };
        let (state_tip, state_generation, state) = self.read_active()?;
        ensure(
            (tip, generation) == (state_tip, state_generation),
            "STALE_VIEW",
        )?;
        self.accepted_task_in_state(&tx, &state)
    }

    /// The growth observer has already checked the exact retained transition
    /// and obtains this working partition from its active read snapshot.
    pub(super) fn accepted_task_from_working(
        &self,
        transactions: &[Vec<u8>],
        working: &State,
    ) -> Result<Option<AcceptedTaskObservation>> {
        let Some(tx) = unique_acceptance(transactions)? else {
            return Ok(None);
        };
        self.accepted_task_in_state(&tx, working)
    }

    fn accepted_task_in_state(
        &self,
        tx: &Envelope,
        state: &State,
    ) -> Result<Option<AcceptedTaskObservation>> {
        let task_id = hex::encode(&tx.payload[..32]);
        let Some(task) = state.get(&format!("task:{task_id}")) else {
            // An expired/pruned local record is not a current settlement proof.
            return Ok(None);
        };
        let owner = hex::encode(tx.sender);
        let output_sha256 = hex::encode(&tx.payload[32..]);
        let provider = task["provider"]
            .as_str()
            .ok_or_else(|| Error::from("TASK_OBSERVATION_STATE").local_integrity())?;
        let provider_key = crate::digest(provider).map_err(Error::local_integrity)?;
        ensure(
            tx.network == self.settings.network()
                && task["owner"] == owner
                && task["output"] == output_sha256
                && task["status"] == "settled"
                && task["remaining"] == 0
                && provider == hex::encode(provider_key),
            "TASK_OBSERVATION_STATE",
        )
        .map_err(Error::local_integrity)?;
        Ok(Some(AcceptedTaskObservation {
            schema_version: 1,
            task_id,
            owner,
            provider: provider.to_owned(),
            output_sha256,
            accept_tx_id: hex::encode(
                tx.id()
                    .map_err(|_| Error::from("TRANSACTION_CODEC").local_integrity())?,
            ),
            accepted_in_exact_packet: true,
            current_status: "settled",
        }))
    }
}
