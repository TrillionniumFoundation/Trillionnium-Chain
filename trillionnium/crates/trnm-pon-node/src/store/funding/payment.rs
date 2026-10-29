//! A payment observation is published only after reexecuting the specific
//! ordinary native transition and matching the admitted header. Row differences
//! alone and net account differences alone are never accepted as payment proof.
use super::*;
use crate::{consensus, ensure, sequence_root, Packet};
use rusqlite::{params, OptionalExtension};
use serde_json::Value;
use std::sync::Mutex;
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::pon_executor::pq_accounts_v2;
use trnm_mvcc_fee::pon_executor::{self, CanonicalTransitionObserver, State};
use trnm_protocol::pon_wire::{hash, Envelope, Hash, Header};

const MAX_ANCESTORS: usize = 4096;
const MAX_CANDIDATE_BYTES: usize = 16 * 1024 * 1024;
struct PaymentObserver<'a> {
    query: &'a NativePaymentQueryV1,
    height: u64,
    quota_unit_price: u64,
    result: Mutex<Option<(u64, u64)>>,
}
fn n(row: &Value, key: &str) -> pon_executor::Result<u64> {
    row.get(key)
        .and_then(Value::as_u64)
        .ok_or("NATIVE_PAYMENT_ROW")
}
fn text<'a>(row: &'a Value, key: &str) -> pon_executor::Result<&'a str> {
    row.get(key)
        .and_then(Value::as_str)
        .ok_or("NATIVE_PAYMENT_ROW")
}
fn h(bytes: &[u8]) -> pon_executor::Result<Hash> {
    bytes.try_into().map_err(|_| "NATIVE_PAYMENT_PAYLOAD")
}
fn u64_at(bytes: &[u8], start: usize) -> pon_executor::Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(start..start + 8)
            .ok_or("NATIVE_PAYMENT_PAYLOAD")?
            .try_into()
            .map_err(|_| "NATIVE_PAYMENT_PAYLOAD")?,
    ))
}
fn check(ok: bool) -> pon_executor::Result<()> {
    if ok {
        Ok(())
    } else {
        Err("NATIVE_PAYMENT_BINDING")
    }
}
impl PaymentObserver<'_> {
    fn record(&self, gross: u64, credit: u64) -> pon_executor::Result<()> {
        check(
            gross > 0
                && gross <= self.query.maximum_gross_units
                && credit <= gross
                && (matches!(self.query.source, NativeFundingSourceV1::Quota(_))
                    || credit == gross),
        )?;
        let mut result = self
            .result
            .lock()
            .map_err(|_| "NATIVE_PAYMENT_OBSERVATION")?;
        check(result.is_none())?;
        *result = Some((gross, credit));
        Ok(())
    }
}
impl CanonicalTransitionObserver for PaymentObserver<'_> {
    fn mandatory(
        &self,
        before: &State,
        after: &State,
        _receipts: &[Vec<u8>],
    ) -> pon_executor::Result<()> {
        let NativeFundingSourceV1::Reward(reward) = self.query.source else {
            return Ok(());
        };
        let key = self.query.source.key();
        let Some(row) = before.get(&key) else {
            return Ok(());
        };
        if n(row, "maturity")? > self.height {
            return Ok(());
        }
        check(
            self.query.operation == reward
                && self.query.subject == reward
                && text(row, "owner")? == hex::encode(self.query.beneficiary)
                && !after.contains_key(&key),
        )?;
        // This callback ran immediately after the actual M06 mandatory code
        // credited this exact reward row. Other credits may share its owner;
        // the individual amount is the executed instruction, not their net sum.
        self.record(n(row, "amount")?, n(row, "amount")?)
    }
    fn transaction(
        &self,
        _index: usize,
        envelope: &Envelope,
        before: &State,
        writes: &State,
        fee: u64,
        receipt: &[u8],
    ) -> pon_executor::Result<()> {
        self.observe_command(
            PaymentCommand {
                id: envelope.id().map_err(|_| "ENCODING")?,
                sender: envelope.sender,
                tag: envelope.tag,
                payload: &envelope.payload,
                encoding: PaymentEncoding::Classical,
            },
            before,
            writes,
            fee,
            receipt,
        )
    }
    fn native_pq_transaction(
        &self,
        _index: usize,
        command: &pq_accounts_v2::PreparedCommand,
        before: &State,
        writes: &State,
        fee: u64,
        receipt: &[u8],
    ) -> pon_executor::Result<()> {
        self.observe_command(
            PaymentCommand {
                id: command.wire_id(),
                sender: command.sender(),
                tag: command.kind(),
                payload: command.payload(),
                encoding: PaymentEncoding::NativePq,
            },
            before,
            writes,
            fee,
            receipt,
        )
    }
}

// Only the two verified canonical observer callbacks above construct this view.
// The enum selects payload grammar; it is never signature or payment authority.
enum PaymentEncoding {
    Classical,
    NativePq,
}
struct PaymentCommand<'a> {
    id: Hash,
    sender: Hash,
    tag: u8,
    payload: &'a [u8],
    encoding: PaymentEncoding,
}
impl PaymentObserver<'_> {
    fn observe_command(
        &self,
        command: PaymentCommand<'_>,
        before: &State,
        writes: &State,
        fee: u64,
        receipt: &[u8],
    ) -> pon_executor::Result<()> {
        if matches!(self.query.source, NativeFundingSourceV1::Reward(_))
            || command.id != self.query.operation
        {
            return Ok(());
        }
        let raw = &command.payload;
        let source_key = self.query.source.key();
        let original = before.get(&source_key).ok_or("NATIVE_PAYMENT_SOURCE")?;
        let successor = writes.get(&source_key).ok_or("NATIVE_PAYMENT_SOURCE")?;
        let (gross, credit) = match self.query.source {
            NativeFundingSourceV1::Task(task) => {
                check(
                    command.tag == 5
                        && raw.len() == 64
                        && h(&raw[..32])? == task
                        && h(&raw[32..])? == self.query.subject
                        && text(original, "owner")? == hex::encode(command.sender)
                        && text(original, "provider")? == hex::encode(self.query.beneficiary)
                        && text(original, "status")? == "receipt"
                        && text(original, "output")? == hex::encode(self.query.subject)
                        && self.height < n(original, "deadline")?
                        && n(successor, "remaining")? == 0
                        && text(successor, "status")? == "settled",
                )?;
                (n(original, "remaining")?, n(original, "remaining")?)
            }
            NativeFundingSourceV1::Release(release) => {
                check(
                    command.tag == 9
                        && raw.len() >= 73
                        && h(&raw[..32])? == release
                        && h(&raw[32..64])? == self.query.subject
                        && command.sender == self.query.beneficiary
                        && text(original, "status")? == "open"
                        && self.height >= n(original, "maturity")?
                        && self.height < n(original, "deadline")?,
                )?;
                let subject = hex::encode(self.query.subject);
                check(original["claims"].get(&subject).is_none())?;
                let total = n(original, "total")?;
                check(total > 0)?;
                let amount = u64::try_from(
                    (n(original, "budget")? as u128) * (u64_at(raw, 64)? as u128) / (total as u128),
                )
                .map_err(|_| "RANGE")?;
                check(
                    successor["claims"].get(&subject).and_then(Value::as_u64) == Some(amount)
                        && n(original, "remaining")?.checked_sub(amount)
                            == Some(n(successor, "remaining")?),
                )?;
                // M06 already verified the actual CID/sender/score allocation path
                // and canonical proof depth before this canonical patch callback.
                (amount, amount)
            }
            NativeFundingSourceV1::Quota(quota) => {
                check(
                    command.tag == 11
                        && raw.len()
                            == match command.encoding {
                                PaymentEncoding::Classical => 136,
                                PaymentEncoding::NativePq => 72,
                            }
                        && h(&raw[..32])? == quota
                        && h(&raw[40..72])? == self.query.subject
                        && command.sender == self.query.beneficiary
                        && text(original, "provider")? == hex::encode(command.sender)
                        && text(original, "status")? == "reserved"
                        && self.height < n(original, "deadline")?,
                )?;
                let units = u64_at(raw, 32)?;
                let cost = units.checked_mul(self.quota_unit_price).ok_or("RANGE")?;
                check(
                    units > 0
                        && n(original, "units")?.checked_sub(units) == Some(n(successor, "units")?)
                        && n(original, "remaining")?.checked_sub(cost)
                            == Some(n(successor, "remaining")?),
                )?;
                // Its real consumer authorization and provider envelope signature
                // passed M06. Tag11 pays its native fee from this exact debit.
                (cost, cost.checked_sub(fee).ok_or("RANGE")?)
            }
            NativeFundingSourceV1::Reward(_) => return Err("NATIVE_PAYMENT_KIND"),
        };
        let account_key = format!("account:{}", hex::encode(self.query.beneficiary));
        let old = before.get(&account_key);
        let next = writes.get(&account_key).ok_or("NATIVE_PAYMENT_CREDIT")?;
        let prior_balance = old.map(|v| n(v, "balance")).transpose()?.unwrap_or(0);
        let sender_fee = if command.sender == self.query.beneficiary && command.tag != 11 {
            fee
        } else {
            0
        };
        check(
            prior_balance
                .checked_sub(sender_fee)
                .and_then(|v| v.checked_add(credit))
                == Some(n(next, "balance")?),
        )?;
        let receipt: Value =
            serde_json::from_slice(receipt).map_err(|_| "NATIVE_PAYMENT_RECEIPT")?;
        check(
            receipt["tx"] == hex::encode(self.query.operation)
                && receipt["fee"] == fee
                && receipt["status"] == "applied",
        )?;
        self.record(gross, credit)
    }
}

impl Node {
    pub fn native_payment_observation(
        &self,
        query: &NativePaymentQueryV1,
    ) -> Result<NativePaymentObservationV1> {
        ensure(query.maximum_gross_units > 0, "NATIVE_PAYMENT_LIMIT")?;
        self.namespace()?;
        let read = self.db.unchecked_transaction()?;
        self.storage_context()?;
        let anchor = if self.state_backend == StateBackend::PermanentAccountGrowthV2 {
            let view = self.growth_snapshot_in_read()?;
            NativeBudgetAnchorV1 {
                network: view.commitment.network,
                parameters: view.commitment.parameters,
                genesis: view.commitment.genesis,
                block: view.block,
                state_root: view.commitment.id,
                height: view.height,
                generation: view.generation,
            }
        } else {
            let (block, generation, _) = self.read_active()?;
            let r = self.record(block)?;
            NativeBudgetAnchorV1 {
                network: self.settings.network(),
                parameters: self.settings.parameters(),
                genesis: self.settings.genesis(),
                block,
                state_root: r.root,
                height: r.height,
                generation,
            }
        };
        let mut cursor = anchor.block;
        let mut examined = 0usize;
        let mut candidate_bytes = 0usize;
        let mut result = None;
        while cursor != self.settings.genesis() && examined < MAX_ANCESTORS {
            examined += 1;
            let record = self.record(cursor)?;
            let header = self.native_payment_header(cursor)?;
            ensure(
                record.parent == Some(header.parent)
                    && record.height == header.height
                    && record.root == header.state
                    && header.network == self.settings.network()
                    && header.parameters == self.settings.parameters(),
                "NATIVE_PAYMENT_ANCESTRY",
            )?;
            let parent = self.record(header.parent)?;
            ensure(
                parent.height.checked_add(1) == Some(header.height)
                    && record.work
                        == parent
                            .work
                            .checked_add(consensus::required_work(header.target)?)?,
                "NATIVE_PAYMENT_ANCESTRY",
            )?;
            // Actual per-block/key deltas are only a cheap candidate locator.
            // They confer no payment authority; the selected transition is fully
            // replayed and compared to its existing header below.
            let relevant: Option<bool> = self
                .db
                .query_row(
                    "SELECT 1 FROM deltas WHERE block=? AND key=?",
                    params![cursor.as_slice(), query.source.key()],
                    |r| r.get(0),
                )
                .optional()?;
            if relevant == Some(true) {
                let bytes: usize = self.db.query_row(
                    "SELECT length(packet) FROM blocks WHERE id=?",
                    [cursor.as_slice()],
                    |r| r.get(0),
                )?;
                ensure(bytes <= 1_048_576, "NATIVE_PAYMENT_SCAN_LIMIT")?;
                candidate_bytes = candidate_bytes
                    .checked_add(bytes)
                    .ok_or("NATIVE_PAYMENT_SCAN_LIMIT")?;
                ensure(
                    candidate_bytes <= MAX_CANDIDATE_BYTES,
                    "NATIVE_PAYMENT_SCAN_LIMIT",
                )?;
                let (transactions, encoded_bytes) =
                    if self.state_backend == StateBackend::PermanentAccountGrowthV2 {
                        let packet = self.growth_packet(cursor)?;
                        let bytes = packet.encode()?.len();
                        (packet.transactions, bytes)
                    } else {
                        let packet = self.packet(cursor)?;
                        let bytes = packet.checked_wire_length_for_settings(&self.settings)?;
                        (packet.transactions, bytes)
                    };
                ensure(encoded_bytes == bytes, "NATIVE_PAYMENT_PACKET_LENGTH")?;
                let selected_pq = if pq_accounts_v2::enabled(&self.settings.app) {
                    Some(pq_accounts_v2::account_profile(&self.settings.app)?)
                } else {
                    None
                };
                let found = matches!(query.source, NativeFundingSourceV1::Reward(_))
                    || transactions.iter().any(|raw| {
                        if let Some(profile) = selected_pq {
                            trnm_protocol::pq_native_accounts_v2::UnverifiedEnvelope::decode_for_profile(raw,profile)
                                .map(|tx|tx.wire_id()).ok() == Some(query.operation)
                        } else { Envelope::decode(raw).and_then(|tx| tx.id()).ok() == Some(query.operation) }
                    });
                if found {
                    let observer = PaymentObserver {
                        query,
                        height: record.height,
                        quota_unit_price: self.settings.limit("quota_unit_price")?,
                        result: Mutex::new(None),
                    };
                    if self.state_backend == StateBackend::PermanentAccountGrowthV2 {
                        self.growth_check_payment_transition(cursor, &observer)?;
                    } else {
                        self.check_native_payment_transition(cursor, &observer)?;
                    }
                    if let Some((gross, credit)) = observer
                        .result
                        .into_inner()
                        .map_err(|_| "NATIVE_PAYMENT_OBSERVATION")?
                    {
                        result = Some(NativePaymentObservationV1 {
                            anchor,
                            source: query.source,
                            subject: query.subject,
                            beneficiary: query.beneficiary,
                            operation: query.operation,
                            gross_escrow_debit: gross,
                            beneficiary_credit: credit,
                        });
                        break;
                    }
                }
            }
            cursor = header.parent;
        }
        self.namespace()?;
        self.storage_context()?;
        if self.state_backend == StateBackend::PermanentAccountGrowthV2 {
            self.growth_payment_epoch()?;
        }
        read.rollback()?;
        result.ok_or_else(|| {
            if cursor != self.settings.genesis() && examined == MAX_ANCESTORS {
                "NATIVE_PAYMENT_SCAN_LIMIT".into()
            } else {
                "NATIVE_PAYMENT_NOT_CONFIRMED".into()
            }
        })
    }
    fn native_payment_header(&self, id: Hash) -> Result<Header> {
        let growth = self.state_backend == StateBackend::PermanentAccountGrowthV2;
        let width = if growth {
            4 + trnm_protocol::pon_growth::GROWTH_HEADER_BYTES
        } else {
            self.settings.packet_header_length()
        };
        let (prefix, trace): (Vec<u8>, Vec<u8>) = self.db.query_row(
            "SELECT substr(packet,1,?),substr(packet,-32,32) FROM blocks WHERE id=?",
            params![width, id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let trace: Hash = trace.try_into().map_err(|_| "WORK_LENGTH")?;
        ensure(prefix.len() == width, "HEADER_CODEC")?;
        if growth {
            ensure(prefix[..4] == *b"PNP2", "HEADER_CODEC")?;
            let h = trnm_protocol::pon_growth::GrowthHeader::decode(&prefix[4..])
                .map_err(|_| "HEADER_CODEC")?;
            ensure(h.block_id(trace) == id, "BLOCK_ID")?;
            Ok(h.ledger)
        } else {
            let h = self.settings.decode_packet_header(&prefix)?;
            ensure(h.block_id(trace) == id, "BLOCK_ID")?;
            Ok(h)
        }
    }
    fn check_native_payment_transition(
        &self,
        id: Hash,
        observer: &dyn CanonicalTransitionObserver,
    ) -> Result<()> {
        let packet: Packet = self.packet(id)?;
        let h = &packet.header;
        ensure(
            h.target == self.expected_target(h.parent)?
                && h.transactions == sequence_root("transactions", &packet.transactions),
            "NATIVE_PAYMENT_HEADER",
        )?;
        let recent: Vec<_> = self
            .recent(h.parent)?
            .iter()
            .take(11)
            .map(|p| p.0)
            .collect();
        consensus::check_time(
            h.timestamp,
            &recent,
            u64::MAX,
            self.settings.limit("future_skew_seconds")?,
        )?;
        let before = self.state_at(h.parent)?;
        let eligible = self.eligible_work_task_from_state(&before, h.work_task, h.height)?;
        if let Some(manifest) = eligible.manifest() {
            let size = pon_work::CELLS * 4;
            ensure(
                packet.proof.len() == pon_work::PROOF_BYTES
                    && packet.proof.get(..4) == Some(b"PNW1")
                    && hash(b"artifact", &[&packet.proof[4..4 + size]]) == manifest.model
                    && hash(
                        b"qualified-task-input-v1",
                        &[&packet.proof[4 + size..4 + 2 * size]],
                    ) == manifest.input,
                "TASK_PROOF_MATERIAL",
            )?;
        }
        let work = pon_work::verify(h.challenge(), h.work_task, h.target, &packet.proof)
            .map_err(|error| Error::from(format!("WORK:{error:?}")))?;
        let mut output = pon_executor::execute_observed(
            &before,
            pon_executor::BlockExecution {
                timestamp: Some(h.timestamp),
                transactions: &packet.transactions,
                height: h.height,
                miner: h.miner,
                parent_id: h.parent,
                workers: 1,
            },
            &self.settings.app,
            observer,
        )?;
        if eligible.manifest().is_some() {
            let product: Vec<u8> = work
                .product()
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect();
            self.record_task_output(h.height, &mut output.state, &eligible, &product)?;
        }
        ensure(
            self.settings.state_root(&output.state)? == h.state
                && sequence_root("receipts", &output.receipts) == h.receipts
                && self.state_at(id)? == output.state,
            "NATIVE_PAYMENT_TRANSITION",
        )
    }
}
