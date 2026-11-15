//! V6 stored namespace for exact, durable V5 request and receipt evidence.
//!
//! This extends the same SQLite register, never a second operation ledger. A
//! V5 CAS is durable before signing; the complete signed exchange is durable
//! before returning it. Interrupted retention can leave an advanced head
//! without an archived ACK. That is uncertainty, not a retained ACK or rollback.
use super::*;
use crate::root_recovery_v3::digest;
use std::collections::BTreeSet;
use trnm_crypto_primitives::pq_root_v3::RootSignatureV3;
use trnm_release_bundle::root_recovery_v3::DigestV3;

pub(super) const MAX_RECORDS: u64 = 128;
const MAX_RECORD_BYTES: usize = 196_608;
const RECORD: &[u8] = b"TRNM/RootWitness/RetainedExchange/v6\0";
const INITIAL: &[u8] = b"TRNM/RootWitness/ReceiptArchiveInitial/v6\0";
const COMMITMENT: &[u8] = b"TRNM/RootWitness/ReceiptArchiveRecord/v6\0";
pub(super) const DDL: &str = "CREATE TABLE root_witness_receipts_v6(sequence INTEGER PRIMARY KEY CHECK(sequence>0 AND sequence<=128),record BLOB NOT NULL CHECK(length(record)>0 AND length(record)<=196608),digest BLOB NOT NULL CHECK(length(digest)=64))";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ArchiveV6 {
    pub(super) count: u64,
    digest: DigestV3,
}
impl ArchiveV6 {
    pub(super) fn initial(policy: &WitnessPolicyV5) -> Self {
        Self {
            count: 0,
            digest: digest(INITIAL, &[&policy.binding]),
        }
    }
}
/// An exact external recovery pin. Matching bytes do not prove independent
/// custody. Never obtain this pin by trusting the restored database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessReceiptCheckpointV6 {
    pub head: JournalHeadV3,
    pub records: u64,
    pub record_digest: DigestV3,
}
/// Historical evidence, not a new Current response, authorization or CAS retry.
pub struct RetainedWitnessReceiptV6 {
    sequence: u64,
    record_digest: DigestV3,
    request: WitnessEnvelopeV5,
    response: SignedWitnessReceiptV5,
}
impl RetainedWitnessReceiptV6 {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn record_digest(&self) -> DigestV3 {
        self.record_digest
    }
    pub fn request(&self) -> &WitnessRequestV5 {
        &self.request.request
    }
    pub fn writer_approvals(&self) -> &[RootSignatureV3] {
        &self.request.writer_approvals
    }
    pub fn receipt(&self) -> &WitnessReceiptV5 {
        &self.response.receipt
    }
    pub fn witness_approvals(&self) -> &[RootSignatureV3] {
        &self.response.approvals
    }
}
/// Mandatory retention through the existing RootWitnessTransportV5 path.
/// V6 never silently migrates V5. Recovery requires an independently retained
/// exact checkpoint; signatures cannot detect common rollback of all pins.
pub struct ReceiptedRootWitnessV6 {
    inner: DurableRootWitnessV5,
}
impl ReceiptedRootWitnessV6 {
    pub fn register_new(
        path: &Path,
        policy: WitnessPolicyV5,
        enrollment: &JournalEnrollmentV3,
        signer: impl RootWriterSignerV3 + 'static,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Self> {
        Ok(Self {
            inner: DurableRootWitnessV5::register(
                path,
                policy,
                enrollment,
                signer,
                budget,
                Namespace::ReceiptsV6,
            )?,
        })
    }
    pub fn open_existing(
        path: &Path,
        policy: WitnessPolicyV5,
        expected: WitnessReceiptCheckpointV6,
        signer: impl RootWriterSignerV3 + 'static,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Self> {
        require(
            expected.records <= MAX_RECORDS && expected.record_digest != [0; 64],
            "ROOT_WITNESS_V6_RECEIPT_CHECKPOINT_SHAPE",
        )?;
        Ok(Self {
            inner: DurableRootWitnessV5::reopen(
                path,
                policy,
                expected.head,
                Some(ArchiveV6 {
                    count: expected.records,
                    digest: expected.record_digest,
                }),
                signer,
                budget,
            )?,
        })
    }
    /// A checked local snapshot for an independent owner to retain. Returning
    /// it does not itself establish that its copies survive a common restore.
    pub fn checkpoint(
        &mut self,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<WitnessReceiptCheckpointV6> {
        let result = (|| {
            require(!self.inner.fenced, "ROOT_WITNESS_V5_DURABLE_FENCED")?;
            self.inner.check_known(budget)?;
            let archive = self
                .inner
                .archive
                .ok_or_else(|| rejected("ROOT_WITNESS_V6_NAMESPACE"))?;
            Ok(WitnessReceiptCheckpointV6 {
                head: self.inner.known.head,
                records: archive.count,
                record_digest: archive.digest,
            })
        })();
        if result.is_err() {
            self.inner.fenced = true;
        }
        result
    }
    /// Read only original evidence. No signer, CAS, new challenge, effect,
    /// append or cold historical-retry privilege is invoked.
    pub fn retained_receipt(
        &mut self,
        sequence: u64,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<RetainedWitnessReceiptV6> {
        let result = (|| {
            require(!self.inner.fenced, "ROOT_WITNESS_V5_DURABLE_FENCED")?;
            self.inner.check_known(budget)?;
            let archive = self
                .inner
                .archive
                .ok_or_else(|| rejected("ROOT_WITNESS_V6_NAMESPACE"))?;
            require(
                sequence > 0 && sequence <= archive.count,
                "ROOT_WITNESS_V6_RECEIPT_SEQUENCE",
            )?;
            let record = read_record(&self.inner.db, sequence)?;
            let (retained, _) = decode(&record, sequence)?;
            verify(&retained, &self.inner.policy, budget)?;
            self.inner.check_known(budget)?;
            Ok(retained)
        })();
        if result.is_err() {
            self.inner.fenced = true;
        }
        result
    }
}
impl RootWitnessTransportV5 for ReceiptedRootWitnessV6 {
    fn exchange(
        &mut self,
        request: WitnessEnvelopeV5,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<SignedWitnessReceiptV5> {
        self.inner.exchange(request, budget)
    }
}
pub(super) fn check_schema(db: &Connection) -> RootOwnerResultV3<()> {
    let valid: bool = db.query_row(
        "SELECT COALESCE(type='table' AND name='root_witness_receipts_v6' AND tbl_name='root_witness_receipts_v6' AND typeof(sql)='text' AND length(CAST(sql AS BLOB))=?1 AND sql=?2,0) FROM sqlite_master WHERE name='root_witness_receipts_v6'",
        params![DDL.len(), DDL], |row| row.get(0),
    ).map_err(map_error)?;
    require(valid, "ROOT_WITNESS_V6_RECEIPT_SCHEMA")
}

pub(super) fn replay(
    db: &Connection,
    policy: &WitnessPolicyV5,
    current_head: JournalHeadV3,
    budget: &mut OwnerBudgetV3,
    verify_signatures: bool,
) -> RootOwnerResultV3<ArchiveV6> {
    budget.check()?;
    check_schema(db)?;
    let count: u64 = db
        .query_row("SELECT COUNT(*) FROM root_witness_receipts_v6", [], |r| {
            r.get(0)
        })
        .map_err(map_error)?;
    require(count <= MAX_RECORDS, "ROOT_WITNESS_V6_RECEIPT_CAPACITY")?;
    let mut archive = ArchiveV6::initial(policy);
    let mut previous_head: Option<JournalHeadV3> = None;
    let mut requests = BTreeSet::new();
    for sequence in 1..=count {
        budget.check()?;
        let record = read_record(db, sequence)?;
        let (retained, previous) = decode(&record, sequence)?;
        require(previous == archive.digest, "ROOT_WITNESS_V6_RECEIPT_CHAIN")?;
        require(
            retained.request.request.binding == policy.binding,
            "ROOT_WITNESS_V6_RECEIPT_POLICY",
        )?;
        require(
            requests.insert(retained.response.receipt.request_digest),
            "ROOT_WITNESS_V6_REPEATED_RETAINED_REQUEST",
        )?;
        let head = retained.response.receipt.head;
        if let Some(previous) = previous_head {
            require(
                head.version > previous.version || head == previous,
                "ROOT_WITNESS_V6_RECEIPT_HEAD_REGRESSION",
            )?;
        }
        previous_head = Some(head);
        if verify_signatures {
            verify(&retained, policy, budget)?;
        }
        archive = ArchiveV6 {
            count: sequence,
            digest: retained.record_digest,
        };
    }
    if let Some(last) = previous_head {
        require(
            last.version < current_head.version || last == current_head,
            "ROOT_WITNESS_V6_RECEIPT_HEAD_AHEAD",
        )?;
    }
    budget.check()?;
    Ok(archive)
}
/// A captured request cannot consume capacity. The checked prefix binds these
/// exact records; refuse before CAS and signing.
pub(super) fn contains_request(
    db: &Connection,
    archive: ArchiveV6,
    request_digest: DigestV3,
    budget: &OwnerBudgetV3,
) -> RootOwnerResultV3<bool> {
    for sequence in 1..=archive.count {
        budget.check()?;
        let (retained, _) = decode(&read_record(db, sequence)?, sequence)?;
        if retained.response.receipt.request_digest == request_digest {
            return Ok(true);
        }
    }
    budget.check()?;
    Ok(false)
}
fn read_record(db: &Connection, sequence: u64) -> RootOwnerResultV3<Vec<u8>> {
    let (size, valid): (u64, bool) = db.query_row(
        "SELECT length(record),typeof(sequence)='integer' AND typeof(record)='blob' AND typeof(digest)='blob' AND length(digest)=64 FROM root_witness_receipts_v6 WHERE sequence=?1",
        [sequence], |row| Ok((row.get(0)?,row.get(1)?)),
    ).map_err(map_error)?;
    require(
        valid && size > 0 && size <= MAX_RECORD_BYTES as u64,
        "ROOT_WITNESS_V6_RECEIPT_SHAPE",
    )?;
    let (record, stored_digest): (Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT record,digest FROM root_witness_receipts_v6 WHERE sequence=?1",
            [sequence],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(map_error)?;
    require(
        record.len() as u64 == size && stored_digest == digest(COMMITMENT, &[&record]),
        "ROOT_WITNESS_V6_RECEIPT_DIGEST",
    )?;
    Ok(record)
}
pub(super) fn retain(
    owner: &mut DurableRootWitnessV5,
    request: &WitnessEnvelopeV5,
    response: &SignedWitnessReceiptV5,
    budget: &mut OwnerBudgetV3,
) -> RootOwnerResultV3<()> {
    let before = owner
        .archive
        .ok_or_else(|| rejected("ROOT_WITNESS_V6_NAMESPACE"))?;
    require(
        before.count < MAX_RECORDS,
        "ROOT_WITNESS_V6_RECEIPT_CAPACITY",
    )?;
    let sequence = before.count + 1;
    let bytes = encode(sequence, before.digest, request, response)?;
    let after = ArchiveV6 {
        count: sequence,
        digest: digest(COMMITMENT, &[&bytes]),
    };
    {
        let guard = progress(&mut owner.db, budget)?;
        let tx = guard
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_error)?;
        require(
            read_row(&tx, &owner.policy_bytes, owner.namespace)? == owner.known,
            "ROOT_WITNESS_V5_DURABLE_STATE_CHANGED",
        )?;
        require(
            replay(&tx, &owner.policy, owner.known.head, budget, false)? == before,
            "ROOT_WITNESS_V6_RECEIPT_HISTORY_CHANGED",
        )?;
        tx.execute(
            "INSERT INTO root_witness_receipts_v6 VALUES(?1,?2,?3)",
            params![sequence, &bytes, after.digest.as_slice()],
        )
        .map_err(map_error)?;
        require(
            replay(&tx, &owner.policy, owner.known.head, budget, false)? == after,
            "ROOT_WITNESS_V6_RECEIPT_HISTORY_CHANGED",
        )?;
        owner.files.check()?;
        budget.check()?;
        tx.commit().map_err(map_error)?;
    }
    owner.files.sync()?;
    owner.archive = Some(after);
    budget.check()
}
fn encode(
    sequence: u64,
    previous: DigestV3,
    request: &WitnessEnvelopeV5,
    response: &SignedWitnessReceiptV5,
) -> RootOwnerResultV3<Vec<u8>> {
    let mut bytes = RECORD.to_vec();
    bytes.extend(sequence.to_be_bytes());
    bytes.extend(previous);
    for (message, approvals) in [
        (request.request.message()?, &request.writer_approvals),
        (response.receipt.message()?, &response.approvals),
    ] {
        require(
            message.len() <= 512 && approvals.len() == 4,
            "ROOT_WITNESS_V6_RECEIPT_SHAPE",
        )?;
        bytes.extend((message.len() as u32).to_be_bytes());
        bytes.extend(message);
        bytes.push(4);
        for approval in approvals {
            require(
                approval.signature.len() <= 32768,
                "ROOT_WITNESS_V6_RECEIPT_SHAPE",
            )?;
            bytes.extend(approval.signer);
            bytes.extend((approval.signature.len() as u32).to_be_bytes());
            bytes.extend(&approval.signature);
        }
    }
    require(
        bytes.len() <= MAX_RECORD_BYTES,
        "ROOT_WITNESS_V6_RECEIPT_SHAPE",
    )?;
    Ok(bytes)
}
struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> RootOwnerResultV3<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or_else(|| rejected("ROOT_WITNESS_V6_RECEIPT_ENCODING"))?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| rejected("ROOT_WITNESS_V6_RECEIPT_ENCODING"))?;
        self.cursor = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> RootOwnerResultV3<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| rejected("ROOT_WITNESS_V6_RECEIPT_ENCODING"))
    }
    fn head(&mut self) -> RootOwnerResultV3<JournalHeadV3> {
        let value = JournalHeadV3 {
            version: u64::from_be_bytes(self.array()?),
            root: self.array()?,
        };
        value.validate()?;
        Ok(value)
    }
    fn approvals(&mut self) -> RootOwnerResultV3<Vec<RootSignatureV3>> {
        require(self.take(1)? == [4], "ROOT_WITNESS_V6_RECEIPT_ENCODING")?;
        let mut values = Vec::with_capacity(4);
        for _ in 0..4 {
            let signer = self.array()?;
            let length = u32::from_be_bytes(self.array()?) as usize;
            require(length <= 32768, "ROOT_WITNESS_V6_RECEIPT_ENCODING")?;
            values.push(RootSignatureV3 {
                signer,
                signature: self.take(length)?.to_vec(),
            });
        }
        Ok(values)
    }
    fn message(&mut self) -> RootOwnerResultV3<&'a [u8]> {
        let length = u32::from_be_bytes(self.array()?) as usize;
        require(length <= 512, "ROOT_WITNESS_V6_RECEIPT_ENCODING")?;
        self.take(length)
    }
    fn done(&self) -> RootOwnerResultV3<()> {
        require(
            self.cursor == self.bytes.len(),
            "ROOT_WITNESS_V6_RECEIPT_ENCODING",
        )
    }
}

fn decode(
    bytes: &[u8],
    expected_sequence: u64,
) -> RootOwnerResultV3<(RetainedWitnessReceiptV6, DigestV3)> {
    require(
        bytes.len() <= MAX_RECORD_BYTES,
        "ROOT_WITNESS_V6_RECEIPT_ENCODING",
    )?;
    let mut reader = Reader { bytes, cursor: 0 };
    require(
        reader.take(RECORD.len())? == RECORD,
        "ROOT_WITNESS_V6_RECEIPT_ENCODING",
    )?;
    let sequence = u64::from_be_bytes(reader.array()?);
    require(
        sequence == expected_sequence,
        "ROOT_WITNESS_V6_RECEIPT_SEQUENCE",
    )?;
    let previous = reader.array()?;
    let request_bytes = reader.message()?;
    let mut request = Reader {
        bytes: request_bytes,
        cursor: 0,
    };
    require(
        request.take(super::super::REQUEST.len())? == super::super::REQUEST,
        "ROOT_WITNESS_V6_RECEIPT_ENCODING",
    )?;
    let binding = request.array()?;
    let challenge = request.array()?;
    let (expected, target) = match request.take(1)?[0] {
        0 => (None, None),
        1 => (Some(request.head()?), Some(request.head()?)),
        _ => return Err(rejected("ROOT_WITNESS_V6_RECEIPT_ENCODING")),
    };
    request.done()?;
    let request = WitnessRequestV5 {
        binding,
        challenge,
        expected,
        target,
    };
    require(
        request.message()? == request_bytes,
        "ROOT_WITNESS_V6_RECEIPT_ENCODING",
    )?;
    let writer_approvals = reader.approvals()?;
    let response_bytes = reader.message()?;
    let mut response = Reader {
        bytes: response_bytes,
        cursor: 0,
    };
    require(
        response.take(super::super::RECEIPT.len())? == super::super::RECEIPT,
        "ROOT_WITNESS_V6_RECEIPT_ENCODING",
    )?;
    let binding = response.array()?;
    let challenge = response.array()?;
    let request_digest = response.array()?;
    let head = response.head()?;
    let outcome = match response.take(1)?[0] {
        0 => WitnessOutcomeV5::Current,
        1 => WitnessOutcomeV5::Advanced,
        2 => WitnessOutcomeV5::Mismatch,
        _ => return Err(rejected("ROOT_WITNESS_V6_RECEIPT_ENCODING")),
    };
    response.done()?;
    let receipt = WitnessReceiptV5 {
        binding,
        challenge,
        request_digest,
        head,
        outcome,
    };
    require(
        receipt.message()? == response_bytes
            && receipt.binding == request.binding
            && receipt.challenge == request.challenge
            && receipt.request_digest == request.digest()?,
        "ROOT_WITNESS_V6_RECEIPT_COMPLETE_BINDING",
    )?;
    let shape = match (request.expected, request.target, receipt.outcome) {
        (None, None, WitnessOutcomeV5::Current) => true,
        (Some(_), Some(target), WitnessOutcomeV5::Advanced) => receipt.head == target,
        (Some(_), Some(_), WitnessOutcomeV5::Mismatch) => true,
        _ => false,
    };
    require(shape, "ROOT_WITNESS_V6_RECEIPT_OUTCOME")?;
    let approvals = reader.approvals()?;
    reader.done()?;
    let retained = RetainedWitnessReceiptV6 {
        sequence,
        record_digest: digest(COMMITMENT, &[bytes]),
        request: WitnessEnvelopeV5 {
            request,
            writer_approvals,
        },
        response: SignedWitnessReceiptV5 { receipt, approvals },
    };
    require(
        encode(sequence, previous, &retained.request, &retained.response)? == bytes,
        "ROOT_WITNESS_V6_RECEIPT_ENCODING",
    )?;
    Ok((retained, previous))
}
fn verify(
    retained: &RetainedWitnessReceiptV6,
    policy: &WitnessPolicyV5,
    budget: &mut OwnerBudgetV3,
) -> RootOwnerResultV3<()> {
    retained.request.verify_writer(policy, budget)?;
    policy
        .witness
        .verify_quorum(
            &retained.response.receipt.message()?,
            &retained.response.approvals,
            budget.verification(),
        )
        .map_err(map_error)?;
    budget.check()
}
