// Standalone test adapter prefixed with the unchanged original registry and types.
use std::io::{self, Read, Write};

fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N].try_into().unwrap()
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(fixed(bytes, offset))
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(fixed(bytes, offset))
}
fn decode(r: &[u8]) -> VerificationProfileV1 {
    VerificationProfileV1 {
        profile_id: fixed(r, 0),
        profile_hash: fixed(r, 32),
        version: u32_at(r, 64),
        valid_from_height: u64_at(r, 68),
        expires_at_height: (r[94] == 1).then(|| u64_at(r, 76)),
        revoked_at_height: (r[95] == 1).then(|| u64_at(r, 84)),
        kind: match r[92] {
            0 => VerificationProfileKindV1::DeterministicReexecution,
            1 => VerificationProfileKindV1::ReproducibleMachineLearning,
            2 => VerificationProfileKindV1::ZeroKnowledge,
            3 => VerificationProfileKindV1::TrustedExecutionEnvironment,
            5 => VerificationProfileKindV1::Optimistic,
            6 => VerificationProfileKindV1::Subjective,
            _ => panic!("fixture has untyped kind"),
        },
        enabled: r[93] == 1,
        objective_settlement_allowed: r[96] == 1,
    }
}
fn emit(profile: VerificationProfileV1, out: &mut impl Write) -> io::Result<()> {
    out.write_all(&profile.profile_id)?;
    out.write_all(&profile.profile_hash)?;
    out.write_all(&profile.version.to_le_bytes())?;
    out.write_all(&profile.valid_from_height.to_le_bytes())?;
    out.write_all(&profile.expires_at_height.unwrap_or(0).to_le_bytes())?;
    out.write_all(&profile.revoked_at_height.unwrap_or(0).to_le_bytes())?;
    out.write_all(&[
        profile.kind.tag(),
        u8::from(profile.enabled),
        u8::from(profile.expires_at_height.is_some()),
        u8::from(profile.revoked_at_height.is_some()),
        u8::from(profile.objective_settlement_allowed),
    ])
}
fn error(err: VerificationProfileErrorV1) -> u8 {
    match err {
        VerificationProfileErrorV1::ZeroIdentifier => 1,
        VerificationProfileErrorV1::ZeroVersion => 2,
        VerificationProfileErrorV1::InvalidHeightRange => 3,
        VerificationProfileErrorV1::DuplicateKind => 4,
        VerificationProfileErrorV1::DuplicateProfileIdentity => 5,
        VerificationProfileErrorV1::IncompleteRegistry => 6,
        VerificationProfileErrorV1::ProfileNotFound => 7,
        VerificationProfileErrorV1::ProfileHashMismatch => 8,
        VerificationProfileErrorV1::ProfileDisabled => 9,
        VerificationProfileErrorV1::ProfileNotYetValid => 10,
        VerificationProfileErrorV1::ProfileExpired => 11,
        VerificationProfileErrorV1::ProfileRevoked => 12,
        VerificationProfileErrorV1::SubjectiveAuthorityEscalation => 13,
        _ => panic!("unrelated original error: {err}"),
    }
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let mut raw = &input[..];
    let mut out = io::stdout().lock();
    while !raw.is_empty() {
        let count = u64_at(raw, 8) as usize;
        let (frame, next) = raw.split_at(92 + 97 * count);
        raw = next;
        let profiles = frame[92..].chunks_exact(97).map(decode).collect();
        match VerificationProfileRegistryV1::closed(profiles) {
            Err(err) => out.write_all(&[error(err)])?,
            Ok(registry) => {
                let shape = [0, registry.len() as u8, u8::from(registry.is_empty()), 0, 0];
                match u32_at(frame, 4) {
                    0 => out.write_all(&shape)?,
                    1 => match registry.resolve_exact(
                        fixed(frame, 16),
                        u32_at(frame, 48),
                        fixed(frame, 52),
                        u64_at(frame, 84),
                    ) {
                        Err(err) => out.write_all(&[error(err)])?,
                        Ok(profile) => {
                            out.write_all(&shape)?;
                            emit(profile, &mut out)?;
                        }
                    },
                    _ => panic!("untyped query"),
                };
            }
        }
    }
    Ok(())
}
