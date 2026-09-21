//! Inert, bounded history transport from a fully audited schema10 source.
use super::*;
use trnm_consensus_types::{
    decode_consensus_parameters_v0_exact, decode_validator_set_v0_exact,
    validate_root_bound_epoch_body_v1, validate_root_bound_regular_body_v0, Block,
};

const MAX_RECORDS: usize = 256;
const MAX_TRANSITIONS: usize = 32;
const HEADER_BYTES: usize = 4096;
const SET_BYTES: usize = 1024 * 1024;
const ROOT_BYTES: usize = 8 * 1024 * 1024;
const PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const EVIDENCE_LIMITS: [usize; 8] = [
    ROOT_BYTES,
    HEADER_BYTES,
    ROOT_BYTES,
    SET_BYTES,
    HEADER_BYTES,
    SET_BYTES,
    HEADER_BYTES,
    HEADER_BYTES,
];

/// Canonical bytes only. A seal has no application body or replay version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeHistoricalRecordV1 {
    Application {
        header_cev0: Vec<u8>,
        application_payload_cev0: Vec<u8>,
    },
    Seal {
        header_cev0: Vec<u8>,
    },
}

impl NativeHistoricalRecordV1 {
    pub fn header_cev0(&self) -> &[u8] {
        match self {
            Self::Application { header_cev0, .. } | Self::Seal { header_cev0 } => header_cev0,
        }
    }
}

/// Untrusted history; decoding grants neither consensus nor execution authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeHistoricalReplayV1 {
    pub anchor_header_cev0: Vec<u8>,
    pub terminal_finality_cev0: Vec<u8>,
    pub records: Vec<NativeHistoricalRecordV1>,
    pub activations: Vec<EpochActivationEvidenceBytesV0>,
}

fn evidence_parts(e: &EpochActivationEvidenceBytesV0) -> [&[u8]; 8] {
    [
        &e.old_checkpoint_finality,
        &e.next_epoch_commitment,
        &e.authorization_kernel,
        &e.old_validator_set,
        &e.old_consensus_parameters,
        &e.new_validator_set,
        &e.new_consensus_parameters,
        &e.authenticated_checkpoint_parent_header,
    ]
}

fn frame_size(bytes: &[u8], minimum: usize, maximum: usize) -> Result<usize> {
    ensure!(
        (minimum..=maximum).contains(&bytes.len()),
        "history frame bound"
    );
    bytes.len().checked_add(4).context("history frame overflow")
}

fn add_size(total: &mut usize, size: usize) -> Result<()> {
    *total = total
        .checked_add(size)
        .context("history aggregate overflow")?;
    ensure!(*total <= MAX_PATH_BYTES, "history aggregate byte bound");
    Ok(())
}

impl NativeHistoricalReplayV1 {
    fn encoded_size(&self) -> Result<usize> {
        ensure!(
            !self.records.is_empty() && self.records.len() <= MAX_RECORDS,
            "history record count"
        );
        ensure!(
            self.activations.len() <= MAX_TRANSITIONS,
            "history transition count"
        );
        let mut total = 16; // magic/revision/profile and two list counts
        add_size(
            &mut total,
            frame_size(&self.anchor_header_cev0, 1, HEADER_BYTES)?,
        )?;
        add_size(
            &mut total,
            frame_size(&self.terminal_finality_cev0, 1, ROOT_BYTES)?,
        )?;
        for record in &self.records {
            add_size(&mut total, 1)?;
            add_size(
                &mut total,
                frame_size(record.header_cev0(), 1, HEADER_BYTES)?,
            )?;
            if let NativeHistoricalRecordV1::Application {
                application_payload_cev0,
                ..
            } = record
            {
                add_size(
                    &mut total,
                    frame_size(application_payload_cev0, 4, PAYLOAD_BYTES)?,
                )?;
            }
        }
        for evidence in &self.activations {
            for (bytes, maximum) in evidence_parts(evidence).into_iter().zip(EVIDENCE_LIMITS) {
                add_size(&mut total, frame_size(bytes, 1, maximum)?)?;
            }
        }
        Ok(total)
    }

    /// Exact local NHR1 framing, with complete checked sizing before allocation.
    pub fn encode_v1(&self) -> Result<Vec<u8>> {
        let size = self.encoded_size()?;
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(b"NHR1\0\x01\0\0");
        put_frame(&mut out, &self.anchor_header_cev0);
        put_frame(&mut out, &self.terminal_finality_cev0);
        out.extend_from_slice(&(self.records.len() as u32).to_be_bytes());
        for record in &self.records {
            out.push(u8::from(matches!(
                record,
                NativeHistoricalRecordV1::Seal { .. }
            )));
            put_frame(&mut out, record.header_cev0());
            if let NativeHistoricalRecordV1::Application {
                application_payload_cev0,
                ..
            } = record
            {
                put_frame(&mut out, application_payload_cev0);
            }
        }
        out.extend_from_slice(&(self.activations.len() as u32).to_be_bytes());
        for evidence in &self.activations {
            for bytes in evidence_parts(evidence) {
                put_frame(&mut out, bytes);
            }
        }
        debug_assert_eq!(out.len(), size);
        Ok(out)
    }

    /// Bounds and remaining bytes are checked before each copy/allocation.
    /// Canonical consensus semantics and signatures require M01 verification.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_PATH_BYTES,
            "history aggregate byte bound"
        );
        let mut r = Reader { bytes, offset: 0 };
        ensure!(
            r.take(8)? == b"NHR1\0\x01\0\0",
            "history magic/revision/profile"
        );
        let anchor_header_cev0 = r.frame(1, HEADER_BYTES)?;
        let terminal_finality_cev0 = r.frame(1, ROOT_BYTES)?;
        let count = r.count(MAX_RECORDS, 6)?;
        ensure!(count > 0, "history empty records");
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let tag = r.take(1)?[0];
            ensure!(tag <= 1, "history record tag");
            let header_cev0 = r.frame(1, HEADER_BYTES)?;
            records.push(if tag == 0 {
                NativeHistoricalRecordV1::Application {
                    header_cev0,
                    application_payload_cev0: r.frame(4, PAYLOAD_BYTES)?,
                }
            } else {
                NativeHistoricalRecordV1::Seal { header_cev0 }
            });
        }
        let count = r.count(MAX_TRANSITIONS, 40)?;
        let mut activations = Vec::with_capacity(count);
        for _ in 0..count {
            activations.push(EpochActivationEvidenceBytesV0 {
                old_checkpoint_finality: r.frame(1, ROOT_BYTES)?,
                next_epoch_commitment: r.frame(1, HEADER_BYTES)?,
                authorization_kernel: r.frame(1, ROOT_BYTES)?,
                old_validator_set: r.frame(1, SET_BYTES)?,
                old_consensus_parameters: r.frame(1, HEADER_BYTES)?,
                new_validator_set: r.frame(1, SET_BYTES)?,
                new_consensus_parameters: r.frame(1, HEADER_BYTES)?,
                authenticated_checkpoint_parent_header: r.frame(1, HEADER_BYTES)?,
            });
        }
        ensure!(r.offset == bytes.len(), "history trailing bytes");
        Ok(Self {
            anchor_header_cev0,
            terminal_finality_cev0,
            records,
            activations,
        })
    }
}

fn put_frame(out: &mut Vec<u8>, bytes: &[u8]) {
    // Every caller has already checked this frame against its <=8 MiB ceiling.
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .context("history offset overflow")?;
        let result = self
            .bytes
            .get(self.offset..end)
            .context("history truncated frame")?;
        self.offset = end;
        Ok(result)
    }
    fn u32(&mut self) -> Result<usize> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("exact four bytes")) as usize)
    }
    fn frame(&mut self, minimum: usize, maximum: usize) -> Result<Vec<u8>> {
        let count = self.u32()?;
        ensure!((minimum..=maximum).contains(&count), "history frame bound");
        Ok(self.take(count)?.to_vec())
    }
    fn count(&mut self, maximum: usize, minimum_bytes: usize) -> Result<usize> {
        let count = self.u32()?;
        ensure!(
            count <= maximum && count <= (self.bytes.len() - self.offset) / minimum_bytes,
            "history list bound/remaining bytes"
        );
        Ok(count)
    }
}

fn protocol<T, E: core::fmt::Debug>(result: core::result::Result<T, E>) -> Result<T> {
    result.map_err(|error| anyhow::anyhow!("history source protocol: {error:?}"))
}

impl DurableNativeApplicationV0 {
    /// Read one immutable audited source snapshot. The result must be verified
    /// by the receiver under independent trust and never supplies replay state.
    pub fn export_historical_replay_v1(
        &self,
        anchor_block: BlockIdV0,
        target_block: BlockIdV0,
    ) -> Result<NativeHistoricalReplayV1> {
        self.with_export_path_v1(anchor_block, target_block, |connection, path, prefix| {
            let terminal_finality_cev0 = path
                .steps
                .last()
                .context("history missing target")?
                .proof
                .clone();
            let mut result = NativeHistoricalReplayV1 {
                anchor_header_cev0: path.anchor_header_cev0,
                terminal_finality_cev0,
                records: Vec::new(),
                activations: Vec::new(),
            };
            let mut previous = decode_header(&result.anchor_header_cev0)?;
            for step in path.steps {
                let header = decode_header(&step.header_cev0)?;
                if let Some(evidence) = step.epoch_evidence {
                    ensure!(
                        result.activations.len() < MAX_TRANSITIONS,
                        "history transition count"
                    );
                    // Copy seals from the very same strictly audited source
                    // prefix. Contextual evidence cannot be decoded through the
                    // v0 context-free path, nor may stored roots replace trust.
                    let activation = &prefix
                        .entries
                        .iter()
                        .find(|entry| {
                            entry
                                .audit
                                .activation
                                .old_checkpoint_finality()
                                .finalized_block()
                                .header()
                                == &previous
                        })
                        .context("history source activation missing")?
                        .audit
                        .activation;
                    let proof = activation.old_checkpoint_finality();
                    ensure!(
                        protocol(proof.try_cev0_bytes())? == evidence.old_checkpoint_finality
                            && protocol(activation.authorization_cev0_bytes())?
                                == evidence.authorization_kernel,
                        "history source activation evidence substitution"
                    );
                    ensure!(
                        proof.finalized_block().header() == &previous,
                        "history checkpoint source join"
                    );
                    for seal in [proof.child().header(), proof.grandchild().header()] {
                        ensure!(
                            seal.parent_id() == previous.id()
                                && previous.height().get().checked_add(1)
                                    == Some(seal.height().get()),
                            "history seal source join"
                        );
                        result.records.push(NativeHistoricalRecordV1::Seal {
                            header_cev0: protocol(seal.try_cev0_bytes())?,
                        });
                        previous = seal.clone();
                    }
                    result.activations.push(evidence);
                }
                ensure!(
                    header.parent_id() == previous.id()
                        && previous.height().get().checked_add(1) == Some(header.height().get()),
                    "history application source join"
                );
                // The source path already passed complete P/proof audit. Read
                // just the body/configuration columns; cloning its full sparse
                // snapshot and replay sets again would add no validation fact.
                let mut statement = connection.prepare(
                    "SELECT artifact_kind,artifact,target_set,target_parameters
                     FROM native_durable_execution_p_v1
                     WHERE block_id=?1 AND status=1 AND header=?2 AND artifact_kind IN(0,1)",
                )?;
                let mut rows =
                    statement.query(params![header.id().as_bytes(), &step.header_cev0])?;
                let row = rows.next()?.context("history source P binding")?;
                let artifact_kind: i64 = row.get(0)?;
                let source_blob = |index: usize, maximum: usize| -> Result<&[u8]> {
                    let bytes = row.get_ref(index)?.as_blob()?;
                    ensure!(
                        !bytes.is_empty() && bytes.len() <= maximum,
                        "history source field byte/type bound"
                    );
                    Ok(bytes)
                };
                let artifact = source_blob(
                    1,
                    trnm_native_application::MAX_NATIVE_EXECUTED_BLOCK_ARTIFACT_BYTES_V0,
                )?;
                let exact = if artifact_kind == 1 {
                    let executed =
                        trnm_native_application::decode_native_executed_epoch_block_artifact_v1(
                            artifact,
                        )?;
                    crate::poco_checkpoint::native_execution_from_receipts_v0(
                        executed.request().preview().transactions(),
                        executed.receipts(),
                    )?
                } else {
                    ensure!(artifact_kind == 0, "history source artifact kind");
                    let executed = decode_native_executed_block_artifact_v0(artifact)?;
                    crate::poco_checkpoint::native_execution_from_receipts_v0(
                        executed.request().transactions(),
                        executed.receipts(),
                    )?
                };
                ensure!(
                    protocol(exact.execution_receipts().receipts_root())? == header.receipts_root(),
                    "history source receipt root"
                );
                let payload = protocol(exact.application_payload().try_cev0_bytes())?;
                let set = protocol(decode_validator_set_v0_exact(source_blob(2, SET_BYTES)?))?;
                let parameters = protocol(decode_consensus_parameters_v0_exact(source_blob(
                    3,
                    HEADER_BYTES,
                )?))?;
                let block = protocol(Block::new(header.clone(), payload.clone(), Vec::new()))?;
                match header.block_kind() {
                    BlockKind::Regular => {
                        protocol(validate_root_bound_regular_body_v0(
                            &block,
                            &set,
                            &parameters,
                        ))?;
                    }
                    BlockKind::EpochCheckpoint | BlockKind::EpochHandoff => {
                        protocol(validate_root_bound_epoch_body_v1(&block, &set, &parameters))?;
                    }
                    _ => anyhow::bail!("history unsupported application kind"),
                }
                result.records.push(NativeHistoricalRecordV1::Application {
                    header_cev0: step.header_cev0,
                    application_payload_cev0: payload,
                });
                // Bound cumulative output before collecting the next source P.
                result.encoded_size()?;
                previous = header;
            }
            result.encoded_size()?;
            Ok(result)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> NativeHistoricalReplayV1 {
        NativeHistoricalReplayV1 {
            anchor_header_cev0: vec![1],
            terminal_finality_cev0: vec![2],
            records: vec![NativeHistoricalRecordV1::Application {
                header_cev0: vec![3],
                application_payload_cev0: vec![0; 4],
            }],
            activations: Vec::new(),
        }
    }
    #[test]
    fn history_local_codec_is_exact_and_checks_lengths_before_copy() {
        let original = sample();
        let bytes = original.encode_v1().unwrap();
        assert_eq!(
            NativeHistoricalReplayV1::decode_v1(&bytes).unwrap(),
            original
        );
        for end in 0..bytes.len() {
            assert!(NativeHistoricalReplayV1::decode_v1(&bytes[..end]).is_err());
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(NativeHistoricalReplayV1::decode_v1(&bad).is_err());
        for offset in [0, 4, 6, 8, 13, 18, 22, 23, 28] {
            let mut bad = bytes.clone();
            bad[offset] = 255;
            assert!(
                NativeHistoricalReplayV1::decode_v1(&bad).is_err(),
                "offset {offset}"
            );
        }
        let mut bad = original.clone();
        bad.records.clear();
        assert!(bad.encode_v1().is_err());
        let mut bad = original.clone();
        bad.anchor_header_cev0 = vec![0; HEADER_BYTES + 1];
        assert!(bad.encode_v1().is_err());
        let mut bad = original;
        bad.terminal_finality_cev0.clear();
        assert!(bad.encode_v1().is_err());
    }
    #[test]
    fn history_local_codec_keeps_record_and_transition_limits_independent() {
        let mut value = sample();
        value.records = vec![
            NativeHistoricalRecordV1::Seal {
                header_cev0: vec![1]
            };
            MAX_RECORDS
        ];
        let evidence = EpochActivationEvidenceBytesV0 {
            old_checkpoint_finality: vec![1],
            next_epoch_commitment: vec![2],
            authorization_kernel: vec![3],
            old_validator_set: vec![4],
            old_consensus_parameters: vec![5],
            new_validator_set: vec![6],
            new_consensus_parameters: vec![7],
            authenticated_checkpoint_parent_header: vec![8],
        };
        value.activations = vec![evidence.clone(); MAX_TRANSITIONS];
        assert_eq!(
            NativeHistoricalReplayV1::decode_v1(&value.encode_v1().unwrap()).unwrap(),
            value
        );
        value.activations.push(evidence);
        assert!(value.encode_v1().is_err());
        value.activations.pop();
        value.records.push(NativeHistoricalRecordV1::Seal {
            header_cev0: vec![1],
        });
        assert!(value.encode_v1().is_err());
    }
}
