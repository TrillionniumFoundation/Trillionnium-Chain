//! M05 canonical persisted transaction record bytes. No storage or authority I/O.

use super::*;

const RECORD_MAGIC_V0: &[u8; 8] = b"TRNMTXR0";
const RECORD_VERSION_V0: u16 = 0;
// Prefix, fixed intent fields, two byte-string lengths, transaction identity,
// phase/sequence and the eight option tags, with no optional values present.
const BASE_RECORD_BYTES_V0: usize = 183;

/// Largest valid v0 record: maximum payload and authorization, with every
/// optional value present in a finalized tombstone. Checked before allocation.
pub const MAX_TX_RECORD_ENCODED_BYTES_V0: usize =
    MAX_TX_BYTES_V0 + MAX_AUTHORIZATION_BYTES_V0 + 773;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxRecordCodecErrorV0 {
    TooLarge,
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u16),
    InvalidTag(&'static str),
    TrailingBytes,
    AllocationFailed,
    InvalidRecord(ProductionTxErrorV0),
}

impl fmt::Display for TxRecordCodecErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => formatter.write_str("transaction record exceeds its byte bound"),
            Self::Truncated => formatter.write_str("transaction record is truncated"),
            Self::InvalidMagic => formatter.write_str("transaction record magic mismatch"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported transaction record version {version}"
                )
            }
            Self::InvalidTag(field) => {
                write!(formatter, "noncanonical transaction record {field} tag")
            }
            Self::TrailingBytes => formatter.write_str("transaction record has trailing bytes"),
            Self::AllocationFailed => formatter.write_str("transaction record allocation failed"),
            Self::InvalidRecord(error) => write!(formatter, "invalid transaction record: {error}"),
        }
    }
}

impl Error for TxRecordCodecErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRecord(error) => Some(error),
            _ => None,
        }
    }
}

impl TxRecordV0 {
    /// Encode the entire record in the closed v0 storage format. Local shape
    /// validation does not supply signature, finality or durable-history proof.
    pub fn encode_canonical_v0(&self) -> Result<Vec<u8>, TxRecordCodecErrorV0> {
        self.validate_persisted_v0(self.intent.chain_id)
            .map_err(TxRecordCodecErrorV0::InvalidRecord)?;
        let encoded_len = BASE_RECORD_BYTES_V0
            + self.intent.payload.len()
            + self.intent.authorization.len()
            + self.wal_sequence.map_or(0, |_| 8)
            + self.proposal.map_or(0, |_| 36)
            + self.ordered.map_or(0, |_| 44)
            + self.execution.map_or(0, |_| 221)
            + self.finality.map_or(0, |_| 104)
            + self.broadcast_intent.map_or(0, |_| 72)
            + self.broadcast_receipt.map_or(0, |_| 104)
            + self.tombstone.map_or(0, |reason| match reason {
                TombstoneReasonV0::Replaced { .. } => 33,
                _ => 1,
            });
        if encoded_len > MAX_TX_RECORD_ENCODED_BYTES_V0 {
            return Err(TxRecordCodecErrorV0::TooLarge);
        }
        let mut out = RecordWriterV0(Vec::new());
        out.0
            .try_reserve_exact(encoded_len)
            .map_err(|_| TxRecordCodecErrorV0::AllocationFailed)?;
        out.raw(RECORD_MAGIC_V0);
        out.raw(&RECORD_VERSION_V0.to_be_bytes());
        out.digest(self.intent.chain_id);
        out.digest(self.intent.sender);
        out.u64(self.intent.nonce);
        out.u128(self.intent.fee_bid);
        out.u64(self.intent.valid_until_height);
        out.u64(self.intent.resource_limits.max_compute);
        out.u32(self.intent.resource_limits.max_state_reads);
        out.u32(self.intent.resource_limits.max_state_writes);
        out.u32(self.intent.resource_limits.max_event_bytes);
        out.bytes(&self.intent.payload);
        out.bytes(&self.intent.authorization);
        out.digest(self.tx_id);
        out.byte(self.phase as u8);
        out.u64(self.lifecycle_sequence);
        out.option(self.wal_sequence, RecordWriterV0::u64);
        out.option(self.proposal, |out, value| {
            out.digest(value.proposal_id);
            out.u32(value.proposal_index);
        });
        out.option(self.ordered, RecordWriterV0::ordered);
        out.option(self.execution, |out, value| {
            out.digest(value.tx_id);
            out.ordered(value.ordered);
            out.digest(value.pre_state_root);
            out.digest(value.post_state_root);
            out.digest(value.receipt_digest);
            out.digest(value.event_root);
            out.u128(value.fee_charged);
            out.byte(u8::from(value.success));
        });
        out.option(self.finality, |out, value| {
            out.digest(value.block_id);
            out.u64(value.height);
            out.digest(value.state_root);
            out.digest(value.finality_proof_digest);
        });
        out.option(self.broadcast_intent, |out, value| {
            out.digest(value.tx_id);
            out.u64(value.intent_sequence);
            out.digest(value.envelope_digest);
        });
        out.option(self.broadcast_receipt, |out, value| {
            out.digest(value.tx_id);
            out.u64(value.intent_sequence);
            out.digest(value.envelope_digest);
            out.digest(value.transport_receipt_digest);
        });
        out.option(self.tombstone, |out, value| match value {
            TombstoneReasonV0::Replaced { by } => {
                out.byte(0);
                out.digest(by);
            }
            TombstoneReasonV0::Finalized => out.byte(1),
            TombstoneReasonV0::Expired => out.byte(2),
            TombstoneReasonV0::Rejected => out.byte(3),
        });
        debug_assert_eq!(out.0.len(), encoded_len);
        Ok(out.0)
    }

    /// Decode exactly one complete canonical record. A journal must separately
    /// bind the returned record to its installed chain and predecessor history.
    pub fn decode_canonical_v0(bytes: &[u8]) -> Result<Self, TxRecordCodecErrorV0> {
        if bytes.len() > MAX_TX_RECORD_ENCODED_BYTES_V0 {
            return Err(TxRecordCodecErrorV0::TooLarge);
        }
        let mut input = RecordReaderV0 { bytes, position: 0 };
        if input.take(RECORD_MAGIC_V0.len())? != RECORD_MAGIC_V0 {
            return Err(TxRecordCodecErrorV0::InvalidMagic);
        }
        let version = u16::from_be_bytes(input.array()?);
        if version != RECORD_VERSION_V0 {
            return Err(TxRecordCodecErrorV0::UnsupportedVersion(version));
        }
        let intent = TxIntentV0 {
            chain_id: input.digest()?,
            sender: input.digest()?,
            nonce: input.u64()?,
            fee_bid: input.u128()?,
            valid_until_height: input.u64()?,
            resource_limits: ResourceLimitsV0 {
                max_compute: input.u64()?,
                max_state_reads: input.u32()?,
                max_state_writes: input.u32()?,
                max_event_bytes: input.u32()?,
            },
            payload: input.bytes(MAX_TX_BYTES_V0)?,
            authorization: input.bytes(MAX_AUTHORIZATION_BYTES_V0)?,
        };
        let tx_id = input.digest()?;
        let phase = match input.byte()? {
            0 => TxPhaseV0::Admitted,
            1 => TxPhaseV0::WalPersisted,
            2 => TxPhaseV0::Proposed,
            3 => TxPhaseV0::Ordered,
            4 => TxPhaseV0::Executed,
            5 => TxPhaseV0::Finalized,
            6 => TxPhaseV0::Tombstoned,
            _ => return Err(TxRecordCodecErrorV0::InvalidTag("phase")),
        };
        let lifecycle_sequence = input.u64()?;
        let record = Self {
            intent,
            tx_id,
            phase,
            lifecycle_sequence,
            wal_sequence: input.option(RecordReaderV0::u64)?,
            proposal: input.option(|input| {
                Ok(ProposalHandoffV0 {
                    proposal_id: input.digest()?,
                    proposal_index: input.u32()?,
                })
            })?,
            ordered: input.option(RecordReaderV0::ordered)?,
            execution: input.option(|input| {
                Ok(ExecutionReceiptV0 {
                    tx_id: input.digest()?,
                    ordered: input.ordered()?,
                    pre_state_root: input.digest()?,
                    post_state_root: input.digest()?,
                    receipt_digest: input.digest()?,
                    event_root: input.digest()?,
                    fee_charged: input.u128()?,
                    success: match input.byte()? {
                        0 => false,
                        1 => true,
                        _ => return Err(TxRecordCodecErrorV0::InvalidTag("boolean")),
                    },
                })
            })?,
            finality: input.option(|input| {
                Ok(FinalityWitnessV0 {
                    block_id: input.digest()?,
                    height: input.u64()?,
                    state_root: input.digest()?,
                    finality_proof_digest: input.digest()?,
                })
            })?,
            broadcast_intent: input.option(|input| {
                Ok(BroadcastIntentV0 {
                    tx_id: input.digest()?,
                    intent_sequence: input.u64()?,
                    envelope_digest: input.digest()?,
                })
            })?,
            broadcast_receipt: input.option(|input| {
                Ok(BroadcastReceiptV0 {
                    tx_id: input.digest()?,
                    intent_sequence: input.u64()?,
                    envelope_digest: input.digest()?,
                    transport_receipt_digest: input.digest()?,
                })
            })?,
            tombstone: input.option(|input| {
                Ok(match input.byte()? {
                    0 => TombstoneReasonV0::Replaced {
                        by: input.digest()?,
                    },
                    1 => TombstoneReasonV0::Finalized,
                    2 => TombstoneReasonV0::Expired,
                    3 => TombstoneReasonV0::Rejected,
                    _ => return Err(TxRecordCodecErrorV0::InvalidTag("tombstone")),
                })
            })?,
        };
        if input.position != bytes.len() {
            return Err(TxRecordCodecErrorV0::TrailingBytes);
        }
        record
            .validate_persisted_v0(record.intent.chain_id)
            .map_err(TxRecordCodecErrorV0::InvalidRecord)?;
        Ok(record)
    }
}

struct RecordWriterV0(Vec<u8>);

impl RecordWriterV0 {
    fn raw(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }

    fn byte(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.raw(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.raw(&value.to_be_bytes());
    }

    fn u128(&mut self, value: u128) {
        self.raw(&value.to_be_bytes());
    }

    fn digest(&mut self, value: Digest32V0) {
        self.raw(&value.0);
    }

    fn bytes(&mut self, value: &[u8]) {
        // Intent validation bounds both byte strings well below u32::MAX.
        self.u32(value.len() as u32);
        self.raw(value);
    }

    fn option<T>(&mut self, value: Option<T>, write: impl FnOnce(&mut Self, T)) {
        match value {
            None => self.byte(0),
            Some(value) => {
                self.byte(1);
                write(self, value);
            }
        }
    }

    fn ordered(&mut self, value: OrderedPositionV0) {
        self.digest(value.block_id);
        self.u64(value.height);
        self.u32(value.transaction_index);
    }
}

struct RecordReaderV0<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> RecordReaderV0<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], TxRecordCodecErrorV0> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(TxRecordCodecErrorV0::TooLarge)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(TxRecordCodecErrorV0::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TxRecordCodecErrorV0> {
        let mut value = [0; N];
        value.copy_from_slice(self.take(N)?);
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, TxRecordCodecErrorV0> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, TxRecordCodecErrorV0> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, TxRecordCodecErrorV0> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn u128(&mut self) -> Result<u128, TxRecordCodecErrorV0> {
        Ok(u128::from_be_bytes(self.array()?))
    }

    fn digest(&mut self) -> Result<Digest32V0, TxRecordCodecErrorV0> {
        Ok(Digest32V0(self.array()?))
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, TxRecordCodecErrorV0> {
        let len = usize::try_from(self.u32()?).map_err(|_| TxRecordCodecErrorV0::TooLarge)?;
        if len > maximum {
            return Err(TxRecordCodecErrorV0::TooLarge);
        }
        let source = self.take(len)?;
        let mut value = Vec::new();
        value
            .try_reserve_exact(len)
            .map_err(|_| TxRecordCodecErrorV0::AllocationFailed)?;
        value.extend_from_slice(source);
        Ok(value)
    }

    fn option<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> Result<T, TxRecordCodecErrorV0>,
    ) -> Result<Option<T>, TxRecordCodecErrorV0> {
        match self.byte()? {
            0 => Ok(None),
            1 => read(self).map(Some),
            _ => Err(TxRecordCodecErrorV0::InvalidTag("option")),
        }
    }

    fn ordered(&mut self) -> Result<OrderedPositionV0, TxRecordCodecErrorV0> {
        Ok(OrderedPositionV0 {
            block_id: self.digest()?,
            height: self.u64()?,
            transaction_index: self.u32()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    fn d(value: u8) -> Digest32V0 {
        Digest32V0([value; 32])
    }

    struct Accept;

    impl AuthorizationVerifierV0 for Accept {
        type Error = Infallible;

        fn verify(&self, _: AccountIdV0, _: Digest32V0, _: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    // Obtain records through the real state machine, including broadcast-only
    // changes which do not advance the lifecycle phase or sequence.
    fn lifecycle_records() -> Vec<TxRecordV0> {
        let intent = TxIntentV0 {
            chain_id: d(1),
            sender: d(2),
            nonce: 7,
            fee_bid: 10,
            valid_until_height: 100,
            resource_limits: ResourceLimitsV0 {
                max_compute: 10_000,
                max_state_reads: 10,
                max_state_writes: 10,
                max_event_bytes: 1024,
            },
            payload: vec![3, 4, 5],
            authorization: vec![6; 4],
        };
        let mut lifecycle = TxLifecycleV0::new(d(1), Accept);
        let tx_id = lifecycle.admit(intent, 1).unwrap();
        let mut records = vec![lifecycle.record(tx_id).unwrap().clone()];
        lifecycle.persist_wal(tx_id, 1).unwrap();
        records.push(lifecycle.record(tx_id).unwrap().clone());
        let broadcast = lifecycle.create_broadcast_intent(tx_id, d(14)).unwrap();
        records.push(lifecycle.record(tx_id).unwrap().clone());
        lifecycle
            .confirm_broadcast(BroadcastReceiptV0 {
                tx_id,
                intent_sequence: broadcast.intent_sequence,
                envelope_digest: broadcast.envelope_digest,
                transport_receipt_digest: d(15),
            })
            .unwrap();
        records.push(lifecycle.record(tx_id).unwrap().clone());
        lifecycle
            .handoff_proposal(
                tx_id,
                ProposalHandoffV0 {
                    proposal_id: d(7),
                    proposal_index: 2,
                },
            )
            .unwrap();
        records.push(lifecycle.record(tx_id).unwrap().clone());
        let ordered = OrderedPositionV0 {
            block_id: d(8),
            height: 9,
            transaction_index: 3,
        };
        lifecycle.mark_ordered(tx_id, ordered).unwrap();
        records.push(lifecycle.record(tx_id).unwrap().clone());
        lifecycle
            .mark_executed(ExecutionReceiptV0 {
                tx_id,
                ordered,
                pre_state_root: d(10),
                post_state_root: d(11),
                receipt_digest: d(12),
                event_root: d(13),
                fee_charged: 5,
                success: true,
            })
            .unwrap();
        records.push(lifecycle.record(tx_id).unwrap().clone());
        lifecycle
            .finalize(
                tx_id,
                FinalityWitnessV0 {
                    block_id: ordered.block_id,
                    height: ordered.height,
                    state_root: d(11),
                    finality_proof_digest: d(16),
                },
            )
            .unwrap();
        records.push(lifecycle.record(tx_id).unwrap().clone());
        lifecycle.tombstone_finalized(tx_id).unwrap();
        records.push(lifecycle.record(tx_id).unwrap().clone());
        records
    }

    fn assert_round_trip(record: &TxRecordV0) {
        let digest = record.canonical_record_digest_v0();
        let encoded = record.encode_canonical_v0().unwrap();
        let decoded = TxRecordV0::decode_canonical_v0(&encoded).unwrap();
        assert_eq!(&decoded, record);
        assert_eq!(decoded.canonical_record_digest_v0(), digest);
        assert_eq!(decoded.encode_canonical_v0().unwrap(), encoded);
        decoded.validate_persisted_v0(d(1)).unwrap();
        assert_eq!(
            decoded.validate_persisted_v0(d(2)),
            Err(ProductionTxErrorV0::InvalidRecoveredRecord)
        );
    }

    #[test]
    fn real_lifecycle_round_trips_every_phase_option_and_terminal_reason() {
        let records = lifecycle_records();
        for record in &records {
            assert_round_trip(record);
        }
        for base in [&records[0], &records[3]] {
            for reason in [
                TombstoneReasonV0::Replaced { by: d(44) },
                TombstoneReasonV0::Expired,
                TombstoneReasonV0::Rejected,
            ] {
                let mut record = base.clone();
                record.phase = TxPhaseV0::Tombstoned;
                record.lifecycle_sequence += 1;
                record.tombstone = Some(reason);
                assert_round_trip(&record);
            }
        }
        let mut unsuccessful = records[6].clone();
        unsuccessful.execution.as_mut().unwrap().success = false;
        assert_round_trip(&unsuccessful);
    }

    #[test]
    fn admitted_record_matches_independently_derived_wire_golden() {
        // Independently assembled from the documented field order and the
        // existing transaction digest algorithm; no codec writer generated it.
        let golden = concat!(
            "54524e4d545852300000",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "0202020202020202020202020202020202020202020202020202020202020202",
            "0000000000000007",
            "0000000000000000000000000000000a",
            "0000000000000064",
            "0000000000002710",
            "0000000a",
            "0000000a",
            "00000400",
            "00000003030405",
            "0000000406060606",
            "0b59b101c7b409ba3e1b679091d150c90749c0de3980dcda3686df62733fcff9",
            "00",
            "0000000000000000",
            "0000000000000000"
        );
        let bytes = (0..golden.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&golden[offset..offset + 2], 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(bytes.len(), 190);
        let record = lifecycle_records().remove(0);
        assert_eq!(record.encode_canonical_v0().unwrap(), bytes);
        assert_eq!(TxRecordV0::decode_canonical_v0(&bytes).unwrap(), record);
    }

    #[test]
    fn exact_maximum_record_and_unsigned_boundaries_are_representable() {
        let mut record = lifecycle_records().pop().unwrap();
        record.intent.payload = vec![0xa5; MAX_TX_BYTES_V0];
        record.intent.authorization = vec![0x5a; MAX_AUTHORIZATION_BYTES_V0];
        record.intent.nonce = u64::MAX;
        record.intent.fee_bid = u128::MAX;
        record.intent.valid_until_height = u64::MAX;
        record.intent.resource_limits = ResourceLimitsV0 {
            max_compute: u64::MAX,
            max_state_reads: u32::MAX,
            max_state_writes: u32::MAX,
            max_event_bytes: MAX_EVENTS_ROOT_INPUT_BYTES_V0 as u32,
        };
        record.tx_id = record.intent.tx_id();
        record.wal_sequence = Some(u64::MAX);
        record.proposal.as_mut().unwrap().proposal_index = u32::MAX - 1;
        let ordered = record.ordered.as_mut().unwrap();
        ordered.height = u64::MAX;
        ordered.transaction_index = u32::MAX - 1;
        let execution = record.execution.as_mut().unwrap();
        execution.tx_id = record.tx_id;
        execution.ordered = *ordered;
        execution.fee_charged = u128::MAX;
        execution.success = false;
        record.finality.as_mut().unwrap().height = ordered.height;
        let intent = record.broadcast_intent.as_mut().unwrap();
        intent.tx_id = record.tx_id;
        intent.intent_sequence = u64::MAX - 1;
        let receipt = record.broadcast_receipt.as_mut().unwrap();
        receipt.tx_id = record.tx_id;
        receipt.intent_sequence = intent.intent_sequence;
        let bytes = record.encode_canonical_v0().unwrap();
        assert_eq!(bytes.len(), MAX_TX_RECORD_ENCODED_BYTES_V0);
        assert_round_trip(&record);
        let mut oversized = bytes;
        oversized.push(0);
        assert_eq!(
            TxRecordV0::decode_canonical_v0(&oversized),
            Err(TxRecordCodecErrorV0::TooLarge)
        );
        record.intent.payload.push(1);
        assert!(matches!(
            record.encode_canonical_v0(),
            Err(TxRecordCodecErrorV0::InvalidRecord(_))
        ));
    }

    #[test]
    fn every_truncation_and_noncanonical_tag_or_suffix_is_rejected() {
        let record = lifecycle_records().pop().unwrap();
        let bytes = record.encode_canonical_v0().unwrap();
        for end in 0..bytes.len() {
            assert_eq!(
                TxRecordV0::decode_canonical_v0(&bytes[..end]),
                Err(TxRecordCodecErrorV0::Truncated),
                "cut {end}"
            );
        }
        let phase_offset = 166 + record.intent.payload.len() + record.intent.authorization.len();
        let option_offset = phase_offset + 9;
        let execution_boolean_offset = option_offset + 9 + 37 + 45 + 221;
        for (offset, value, expected) in [
            (0, b'X', TxRecordCodecErrorV0::InvalidMagic),
            (9, 1, TxRecordCodecErrorV0::UnsupportedVersion(1)),
            (phase_offset, 7, TxRecordCodecErrorV0::InvalidTag("phase")),
            (option_offset, 2, TxRecordCodecErrorV0::InvalidTag("option")),
            (
                execution_boolean_offset,
                2,
                TxRecordCodecErrorV0::InvalidTag("boolean"),
            ),
            (
                bytes.len() - 1,
                4,
                TxRecordCodecErrorV0::InvalidTag("tombstone"),
            ),
        ] {
            let mut mutation = bytes.clone();
            mutation[offset] = value;
            assert_eq!(
                TxRecordV0::decode_canonical_v0(&mutation),
                Err(expected),
                "offset {offset}"
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            TxRecordV0::decode_canonical_v0(&trailing),
            Err(TxRecordCodecErrorV0::TrailingBytes)
        );
    }

    #[test]
    fn declared_lengths_are_rejected_before_payload_allocation_or_read() {
        let record = lifecycle_records().remove(0);
        let bytes = record.encode_canonical_v0().unwrap();
        for offset in [126, 130 + record.intent.payload.len()] {
            let mut mutation = bytes[..offset].to_vec();
            mutation.extend_from_slice(&u32::MAX.to_be_bytes());
            // The declared data is absent; TooLarge instead of Truncated
            // demonstrates that the protocol bound is checked first.
            assert_eq!(
                TxRecordV0::decode_canonical_v0(&mutation),
                Err(TxRecordCodecErrorV0::TooLarge)
            );
        }
        let mut record = record;
        record.intent.authorization = vec![1; MAX_AUTHORIZATION_BYTES_V0 + 1];
        assert!(matches!(
            record.encode_canonical_v0(),
            Err(TxRecordCodecErrorV0::InvalidRecord(_))
        ));
    }

    #[test]
    fn decoder_rejects_complete_but_misbound_or_impossible_record_bytes() {
        let record = lifecycle_records().remove(0);
        let bytes = record.encode_canonical_v0().unwrap();
        let phase_offset = 166 + record.intent.payload.len() + record.intent.authorization.len();
        for (offset, value) in [
            (10, 99),               // Chain changed without a new tx ID.
            (phase_offset - 1, 99), // Supplied transaction ID substituted.
            (phase_offset, 5),      // Finalized with no predecessors.
            (phase_offset + 8, 1),  // Admitted with advanced lifecycle sequence.
        ] {
            let mut mutation = bytes.clone();
            mutation[offset] = value;
            assert_eq!(
                TxRecordV0::decode_canonical_v0(&mutation),
                Err(TxRecordCodecErrorV0::InvalidRecord(
                    ProductionTxErrorV0::InvalidRecoveredRecord
                ))
            );
        }
    }

    #[test]
    fn persisted_validation_rejects_field_substitution_and_illegal_terminal_shapes() {
        let finalized = lifecycle_records().pop().unwrap();
        let mutations: &[fn(&mut TxRecordV0)] = &[
            |r| r.wal_sequence = Some(0),
            |r| r.proposal.as_mut().unwrap().proposal_id = d(0),
            |r| r.proposal.as_mut().unwrap().proposal_index = u32::MAX,
            |r| r.ordered.as_mut().unwrap().block_id = d(0),
            |r| r.ordered.as_mut().unwrap().height = 0,
            |r| r.ordered.as_mut().unwrap().transaction_index = u32::MAX,
            |r| r.execution.as_mut().unwrap().tx_id = d(99),
            |r| r.execution.as_mut().unwrap().fee_charged = r.intent.fee_bid + 1,
            |r| r.finality.as_mut().unwrap().state_root = d(99),
            |r| r.finality.as_mut().unwrap().finality_proof_digest = d(0),
            |r| r.broadcast_intent.as_mut().unwrap().tx_id = d(99),
            |r| r.broadcast_intent.as_mut().unwrap().envelope_digest = d(0),
            |r| r.broadcast_intent.as_mut().unwrap().intent_sequence = u64::MAX,
            |r| {
                r.broadcast_receipt
                    .as_mut()
                    .unwrap()
                    .transport_receipt_digest = d(0)
            },
            |r| r.broadcast_intent = None,
            |r| r.lifecycle_sequence = 5,
            |r| r.finality = None,
            |r| r.tombstone = Some(TombstoneReasonV0::Rejected),
        ];
        for mutate in mutations {
            let mut record = finalized.clone();
            mutate(&mut record);
            assert_eq!(
                record.validate_persisted_v0(d(1)),
                Err(ProductionTxErrorV0::InvalidRecoveredRecord)
            );
            assert!(matches!(
                record.encode_canonical_v0(),
                Err(TxRecordCodecErrorV0::InvalidRecord(_))
            ));
        }
        let mut early = lifecycle_records().remove(0);
        early.phase = TxPhaseV0::Tombstoned;
        early.lifecycle_sequence = 1;
        for reason in [
            TombstoneReasonV0::Finalized,
            TombstoneReasonV0::Replaced { by: early.tx_id },
            TombstoneReasonV0::Replaced { by: d(0) },
        ] {
            early.tombstone = Some(reason);
            assert!(early.validate_persisted_v0(d(1)).is_err());
        }
        let mut admitted = lifecycle_records().remove(0);
        admitted.broadcast_intent = finalized.broadcast_intent;
        assert!(admitted.validate_persisted_v0(d(1)).is_err());
    }
}
