// Appended only to the complete, unchanged original payload_recovery.rs.
// The observer transports typed fields and calls the original private codec.
// It neither computes an ACK hash nor implements a decoder decision.
pub fn qualification_recovery_ack_codec_v1(input: &[u8]) -> (u32, Vec<u8>) {
    fn word(input: &[u8], position: usize) -> u64 {
        u64::from_le_bytes(input[position..position + 8].try_into().unwrap())
    }
    fn digest(input: &[u8], position: usize) -> [u8; 32] {
        input[position..position + 32].try_into().unwrap()
    }
    if input.len() < 8 {
        return (100, Vec::new());
    }
    match word(input, 0) {
        1 => {
            if input.len() != 256 {
                return (100, Vec::new());
            }
            let direction = match word(input, 112) {
                1 => PeerLeaseDirectionV1::Outbound,
                2 => PeerLeaseDirectionV1::Inbound,
                _ => return (100, Vec::new()),
            };
            let Ok(frame_kind) = u8::try_from(word(input, 168)) else {
                return (100, Vec::new());
            };
            let Ok(payload_len) = u32::try_from(word(input, 176)) else {
                return (100, Vec::new());
            };
            // The codec consumes the typed value directly. Public constructors
            // are tested separately against the existing native value owner.
            let target = PayloadReplayRecoveryTargetV1 {
                record_index: word(input, 40),
                record_hash: digest(input, 48),
                remote_id: digest(input, 80),
                direction,
                session_id: digest(input, 120),
                generation: word(input, 152),
                sequence: word(input, 160),
                frame_kind,
                payload_len,
                frame_fingerprint: digest(input, 184),
            };
            let acknowledgement = PayloadReplayCoreAcknowledgementV1 {
                target,
                core_safety_revision: word(input, 216),
                core_ack_digest: digest(input, 224),
            };
            (0, encode_ack(digest(input, 8), acknowledgement).to_vec())
        }
        2 => match decode_ack(&input[8..]) {
            Ok(value) => {
                let mut out = Vec::new();
                out.extend_from_slice(&value.namespace_digest);
                out.extend_from_slice(&value.record_index.to_le_bytes());
                out.extend_from_slice(&value.record_hash);
                out.extend_from_slice(&value.frame_fingerprint);
                out.extend_from_slice(&value.core_safety_revision.to_le_bytes());
                out.extend_from_slice(&value.core_ack_digest);
                out.extend_from_slice(&value.acknowledgement_hash);
                (0, out)
            }
            Err(PayloadReplayRecoveryErrorV1::AckLedgerCorrupt) => (3, Vec::new()),
            Err(error) => panic!("unexpected original ACK decoder error: {error}"),
        },
        _ => (100, Vec::new()),
    }
}
