//! Exact PNP2 provenance from one native read snapshot. This is deliberately
//! distinct from the PNP1 observer and grants no execution or finality authority.
use super::*;
use serde_json::Value;

// Growth does not populate the historical PNP1 ancestry index. Walk checked
// fixed headers with an explicit local read budget; exhaustion is an error,
// never an observation of absence. This is a service limit, not a chain rule.
const MEMBERSHIP_SQL_BUDGET: u64 = 8193;

impl Node {
    pub(super) fn growth_active_member(
        &self,
        mut current: Hash,
        block: Hash,
        block_height: u64,
        budget: u64,
    ) -> Result<(bool, u64)> {
        let mut used = 0;
        let mut expected: Option<(u64, consensus::Work)> = None;
        loop {
            ensure(used < budget, "GROWTH_MEMBERSHIP_BUDGET")?;
            let record = self.record(current)?;
            used += 1;
            if let Some((height, work)) = expected {
                ensure(
                    record.height == height && record.work == work,
                    "GROWTH_HEADER_RECORD",
                )
                .map_err(Error::local_integrity)?;
            }
            if current == block {
                ensure(record.height == block_height, "GROWTH_HEADER_RECORD")
                    .map_err(Error::local_integrity)?;
                return Ok((true, used));
            }
            if record.height <= block_height {
                return Ok((false, used));
            }
            ensure(used < budget, "GROWTH_MEMBERSHIP_BUDGET")?;
            let header = self.growth_header(current)?.ledger;
            used += 1;
            ensure(
                header.network == self.settings.network()
                    && header.parameters == self.settings.parameters()
                    && record.parent == Some(header.parent)
                    && record.height == header.height
                    && record.root == header.state,
                "GROWTH_HEADER_RECORD",
            )
            .map_err(Error::local_integrity)?;
            expected = Some((
                record.height.checked_sub(1).ok_or("HEIGHT")?,
                record
                    .work
                    .checked_sub(consensus::required_work(header.target)?)?,
            ));
            current = header.parent;
        }
    }

    /// Observe exact retained bytes, validated transition and active membership
    /// in this already-open native growth owner. No admission, activation, or
    /// operation identity is created. An absent packet is only local absence.
    pub fn growth_exact_packet_observation(&self, packet: &GrowthPacket) -> Result<Value> {
        self.growth_guard()?;
        ensure(
            packet.header.ledger.network == self.settings.network()
                && packet.header.ledger.parameters == self.settings.parameters(),
            "NETWORK",
        )?;
        let expected = packet.encode()?;
        let id = packet.id()?;
        let tx = self.db.unchecked_transaction()?;
        self.growth_guard()?;
        let changes = self.db.total_changes();
        let stored: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT substr(packet,1,?) FROM blocks WHERE id=?",
                params![limits::MAX_PACKET_BYTES + 1, id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let (tip, generation) = self.active()?;
        let tip_record = self.record(tip)?;
        let mut block_height = None;
        let mut block_chainwork_hex = None;
        let mut active_chain_member = false;
        let mut active_depth = None;
        let mut active_work_depth_hex = None;
        let mut active_membership_sql_lookups = None;
        let stored_exact = if let Some(raw) = stored {
            ensure(raw == expected, "DUPLICATE_CONTENT")?;
            // Reuse the original native W1, original-parent account witness,
            // signed M06 execution, receipt, commitment and retained delta checks.
            self.growth_check_retained_transition(id, None)?;
            let record = self.record(id)?;
            let header = &packet.header.ledger;
            let parent = self.record(header.parent)?;
            ensure(
                record.parent == Some(header.parent)
                    && record.height == header.height
                    && record.root == header.state
                    && record.work
                        == parent
                            .work
                            .checked_add(consensus::required_work(header.target)?)?,
                "GROWTH_HEADER_RECORD",
            )
            .map_err(Error::local_integrity)?;
            let (member, used) =
                self.growth_active_member(tip, id, record.height, MEMBERSHIP_SQL_BUDGET)?;
            active_chain_member = member;
            active_membership_sql_lookups = Some(used);
            if member {
                active_depth = Some(
                    tip_record
                        .height
                        .checked_sub(record.height)
                        .ok_or("HEIGHT")?,
                );
                active_work_depth_hex = Some(hex::encode(
                    tip_record.work.checked_sub(record.work)?.bytes(),
                ));
            }
            block_height = Some(record.height);
            block_chainwork_hex = Some(hex::encode(record.work.bytes()));
            true
        } else {
            false
        };
        let accepted_task = if stored_exact && active_chain_member {
            let working = self.growth_parent(tip)?.source.stored.working;
            self.accepted_task_from_working(&packet.transactions, &working)?
        } else {
            None
        };
        self.growth_guard()?;
        ensure(self.active()? == (tip, generation), "STALE_VIEW")?;
        ensure(
            self.db.total_changes() == changes,
            "GROWTH_OBSERVATION_WRITE",
        )
        .map_err(Error::local_integrity)?;
        let result = json!({
            "schema":"pon-native-exact-growth-packet-observation-v1",
            "packet_profile":"PNP2",
            "state_profile":limits::PROFILE,
            "network":hex::encode(self.settings.network()),
            "parameters":hex::encode(self.settings.parameters()),
            "genesis":hex::encode(self.settings.genesis()),
            "block":hex::encode(id),
            "stored_exact":stored_exact,
            "block_height":block_height,
            "block_chainwork_hex":block_chainwork_hex,
            "active_tip":hex::encode(tip),
            "active_tip_height":tip_record.height,
            "active_tip_chainwork_hex":hex::encode(tip_record.work.bytes()),
            "active_chain_member":active_chain_member,
            "active_depth":active_depth,
            "active_work_depth_hex":active_work_depth_hex,
            "active_membership_sql_lookups":active_membership_sql_lookups,
            "active_membership_sql_budget":MEMBERSHIP_SQL_BUDGET,
            "generation":generation,
            "accepted_task":accepted_task,
            "local_target_only":true,
            "global_absence_authority":false,
            "confirmation_authority":false,
            "finality_authority":false,
            "execution_authority":false,
            "production_activation":false
        });
        tx.rollback()?;
        Ok(result)
    }
}
