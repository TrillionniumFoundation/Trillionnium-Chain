//! Research security-work floor for a complete grouped Cell statement.
//!
//! The useful grouped product may be cached. This separately named security
//! work is a fixed classical hash chain, not a neural-MAC hardness claim. A
//! caller must independently establish the challenge, statement, target and
//! authority. A successful replay is not native consensus admission.
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];
pub const PROFILE: &str = "pon-grouped-int257-sealed-research-v0";
pub const OPERATOR_PROFILE: &str = "pon-routed-int257-grouped-research-v0";
pub const NUMERIC: &str = "signed-i32-coeff-i64-accum-bias8-lowest-argmax";
pub const STEPS: u16 = 64;
pub const BATCH_SIZE: u16 = 16;
pub const MAGIC: &[u8; 6] = b"PGSF\0\0";
pub const PROOF_BYTES: usize = 6 + 4 * 32;
const DOMAIN: &[u8] = b"TRNM-GROUPED-FRESH-SEAL0\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealError {
    Length,
    Version,
    Profile,
    Challenge,
    Statement,
    Target,
    Endpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    Seed,
    Step(u16),
}

/// One seed/step evaluation observed immediately after its actual hash call.
///
/// Fields are private and this type has no decoder or caller constructor. It
/// is diagnostic evidence, not an admission capability. Copies/retransmissions
/// do not establish another execution. `preimage` only frames captured bytes:
/// it does not evaluate the oracle again or recompute the profile hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluatedQuery {
    point: Progress,
    profile: Hash,
    challenge: Hash,
    statement: Hash,
    predecessor: Hash,
    answer: Hash,
}
impl EvaluatedQuery {
    pub fn progress(&self) -> Progress {
        self.point
    }
    pub fn ordinal(&self) -> u16 {
        match self.point {
            Progress::Seed => 0,
            Progress::Step(index) => index,
        }
    }
    pub fn profile(&self) -> Hash {
        self.profile
    }
    pub fn challenge(&self) -> Hash {
        self.challenge
    }
    pub fn statement(&self) -> Hash {
        self.statement
    }
    pub fn predecessor(&self) -> Option<Hash> {
        match self.point {
            Progress::Seed => None,
            Progress::Step(_) => Some(self.predecessor),
        }
    }
    pub fn answer(&self) -> Hash {
        self.answer
    }
    pub fn preimage(&self) -> Vec<u8> {
        let index = self.ordinal().to_be_bytes();
        let (tag, parts): (&[u8], Vec<&[u8]>) = match self.point {
            Progress::Seed => (
                b"seed",
                vec![&self.profile, &self.challenge, &self.statement],
            ),
            Progress::Step(_) => (
                b"step",
                vec![&self.profile, &self.challenge, &index, &self.predecessor],
            ),
        };
        let mut raw = Vec::with_capacity(145);
        raw.extend_from_slice(DOMAIN);
        raw.extend_from_slice(&(tag.len() as u16).to_be_bytes());
        raw.extend_from_slice(tag);
        for part in parts {
            raw.extend_from_slice(&(part.len() as u32).to_be_bytes());
            raw.extend_from_slice(part);
        }
        raw
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifyError<E> {
    Relation(SealError),
    Cancelled(E),
}

/// Verified arithmetic of this seal only. It grants no task or work authority.
#[derive(Debug)]
pub struct VerifiedFreshSeal {
    challenge: Hash,
    statement: Hash,
    ticket: Hash,
}

impl VerifiedFreshSeal {
    pub fn challenge(&self) -> Hash {
        self.challenge
    }
    pub fn statement(&self) -> Hash {
        self.statement
    }
    pub fn ticket(&self) -> Hash {
        self.ticket
    }
    pub fn step_count(&self) -> u16 {
        STEPS
    }
    /// No conversion to W1 VerifiedWork or production fork-choice credit exists.
    pub fn chainwork_awarded(&self) -> u64 {
        0
    }
}

fn framed_hasher(tag: &[u8], parts: &[&[u8]]) -> Sha256 {
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    // All callers use the bounded fixed tags and fields defined in this file.
    digest.update((tag.len() as u16).to_be_bytes());
    digest.update(tag);
    for part in parts {
        digest.update((part.len() as u32).to_be_bytes());
        digest.update(part);
    }
    digest
}

fn hash(tag: &[u8], parts: &[&[u8]]) -> Hash {
    framed_hasher(tag, parts).finalize().into()
}

pub fn profile_hash() -> Hash {
    hash(
        b"profile",
        &[
            PROFILE.as_bytes(),
            OPERATOR_PROFILE.as_bytes(),
            NUMERIC.as_bytes(),
            &STEPS.to_be_bytes(),
            &BATCH_SIZE.to_be_bytes(),
        ],
    )
}

fn endpoint_with_query_observer<E>(
    challenge: Hash,
    statement: Hash,
    observer: &mut impl FnMut(&EvaluatedQuery) -> Result<(), E>,
) -> Result<Hash, E> {
    let profile = profile_hash();
    let mut state = hash(b"seed", &[&profile, &challenge, &statement]);
    observer(&EvaluatedQuery {
        point: Progress::Seed,
        profile,
        challenge,
        statement,
        predecessor: [0; 32],
        answer: state,
    })?;
    // Legal SHA-256 prefix preparation is included in this producer. A query
    // count is not a claim that every invocation repeats all prefix compression
    // work or has an architecture-independent CPU/energy price.
    let prefix = framed_hasher(b"step", &[&profile, &challenge]);
    for index in 1..=STEPS {
        let predecessor = state;
        let mut digest = prefix.clone();
        digest.update(2_u32.to_be_bytes());
        digest.update(index.to_be_bytes());
        digest.update(32_u32.to_be_bytes());
        digest.update(predecessor);
        state = digest.finalize().into();
        observer(&EvaluatedQuery {
            point: Progress::Step(index),
            profile,
            challenge,
            statement,
            predecessor,
            answer: state,
        })?;
    }
    Ok(state)
}

fn encode(challenge: Hash, statement: Hash, endpoint: Hash) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PROOF_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&profile_hash());
    bytes.extend_from_slice(&challenge);
    bytes.extend_from_slice(&statement);
    bytes.extend_from_slice(&endpoint);
    bytes
}

/// One complete endpoint witness. Generation does not grant authority or credit.
pub fn prove(challenge: Hash, statement: Hash) -> Vec<u8> {
    match prove_with_progress(challenge, statement, |_| {
        Ok::<_, std::convert::Infallible>(())
    }) {
        Ok(bytes) => bytes,
        Err(impossible) => match impossible {},
    }
}

/// Cancellation leaves no successful witness. Observed completed steps remain
/// caller-owned costs and must not disappear from the attempt ledger.
pub fn prove_with_progress<E>(
    challenge: Hash,
    statement: Hash,
    mut progress: impl FnMut(Progress) -> Result<(), E>,
) -> Result<Vec<u8>, E> {
    prove_with_query_observer(challenge, statement, |query| progress(query.progress()))
}

/// Opt-in observations of the already evaluated seed and steps. The callback
/// runs once after each actual evaluation, including the evaluation at which
/// it cancels. No subsequent query or successful partial witness is produced.
/// Observer work and profile/framing hashes are not counted as step queries.
pub fn prove_with_query_observer<E>(
    challenge: Hash,
    statement: Hash,
    mut observer: impl FnMut(&EvaluatedQuery) -> Result<(), E>,
) -> Result<Vec<u8>, E> {
    endpoint_with_query_observer(challenge, statement, &mut observer)
        .map(|endpoint| encode(challenge, statement, endpoint))
}

fn claimed_endpoint(
    challenge: Hash,
    statement: Hash,
    target: Hash,
    bytes: &[u8],
) -> Result<Hash, SealError> {
    if bytes.len() != PROOF_BYTES {
        return Err(SealError::Length);
    }
    if &bytes[..6] != MAGIC {
        return Err(SealError::Version);
    }
    if bytes[6..38] != profile_hash() {
        return Err(SealError::Profile);
    }
    if bytes[38..70] != challenge {
        return Err(SealError::Challenge);
    }
    if bytes[70..102] != statement {
        return Err(SealError::Statement);
    }
    let mut endpoint = [0; 32];
    endpoint.copy_from_slice(&bytes[102..]);
    if target == [0; 32] || endpoint > target {
        return Err(SealError::Target);
    }
    Ok(endpoint)
}

/// Cheap filter only. A low claimed endpoint can be fabricated; this cannot
/// construct VerifiedFreshSeal and cannot substitute for a complete replay.
pub fn precheck(
    challenge: Hash,
    statement: Hash,
    target: Hash,
    bytes: &[u8],
) -> Result<(), SealError> {
    claimed_endpoint(challenge, statement, target, bytes).map(|_| ())
}

pub fn verify(
    challenge: Hash,
    statement: Hash,
    target: Hash,
    bytes: &[u8],
) -> Result<VerifiedFreshSeal, SealError> {
    match verify_with_progress(challenge, statement, target, bytes, |_| {
        Ok::<_, std::convert::Infallible>(())
    }) {
        Ok(value) => Ok(value),
        Err(VerifyError::Relation(error)) => Err(error),
        Err(VerifyError::Cancelled(impossible)) => match impossible {},
    }
}

pub fn verify_with_progress<E>(
    challenge: Hash,
    statement: Hash,
    target: Hash,
    bytes: &[u8],
    mut progress: impl FnMut(Progress) -> Result<(), E>,
) -> Result<VerifiedFreshSeal, VerifyError<E>> {
    verify_with_query_observer(challenge, statement, target, bytes, |query| {
        progress(query.progress())
    })
}

/// Observes only this invocation's actual seed/step evaluations. A framing
/// rejection emits no query; a false endpoint still emits the full replay.
/// It does not reconstruct a historical or cached verification transcript.
pub fn verify_with_query_observer<E>(
    challenge: Hash,
    statement: Hash,
    target: Hash,
    bytes: &[u8],
    mut observer: impl FnMut(&EvaluatedQuery) -> Result<(), E>,
) -> Result<VerifiedFreshSeal, VerifyError<E>> {
    let expected =
        claimed_endpoint(challenge, statement, target, bytes).map_err(VerifyError::Relation)?;
    let actual = endpoint_with_query_observer(challenge, statement, &mut observer)
        .map_err(VerifyError::Cancelled)?;
    if actual != expected {
        return Err(VerifyError::Relation(SealError::Endpoint));
    }
    Ok(VerifiedFreshSeal {
        challenge,
        statement,
        ticket: actual,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_work_and_canonical_witness_replay() {
        let mut events = Vec::new();
        let proof = prove_with_progress([3; 32], [7; 32], |point| {
            events.push(point);
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(proof.len(), PROOF_BYTES);
        assert_eq!(events.len(), usize::from(STEPS) + 1);
        assert_eq!(events[0], Progress::Seed);
        assert_eq!(events[usize::from(STEPS)], Progress::Step(STEPS));
        let checked = verify([3; 32], [7; 32], [255; 32], &proof).unwrap();
        assert_eq!(checked.challenge(), [3; 32]);
        assert_eq!(checked.statement(), [7; 32]);
        assert_eq!(checked.ticket().as_slice(), &proof[102..]);
        assert_eq!(checked.step_count(), STEPS);
        assert_eq!(checked.chainwork_awarded(), 0);
        assert_eq!(proof, prove([3; 32], [7; 32]));
        let profile = profile_hash();
        let mut scalar = hash(b"seed", &[&profile, &[3; 32], &[7; 32]]);
        for index in 1..=STEPS {
            scalar = hash(
                b"step",
                &[&profile, &[3; 32], &index.to_be_bytes(), &scalar],
            );
        }
        assert_eq!(checked.ticket(), scalar);
    }

    #[test]
    fn every_fixed_field_and_extra_byte_are_rejected() {
        let proof = prove([3; 32], [7; 32]);
        for (offset, error) in [
            (0, SealError::Version),
            (6, SealError::Profile),
            (38, SealError::Challenge),
            (70, SealError::Statement),
            (102, SealError::Endpoint),
        ] {
            let mut changed = proof.clone();
            changed[offset] ^= 1;
            assert_eq!(
                verify([3; 32], [7; 32], [255; 32], &changed).unwrap_err(),
                error
            );
        }
        for length in [0, 6, PROOF_BYTES - 1, PROOF_BYTES + 1] {
            let mut changed = proof.clone();
            changed.resize(length, 0);
            assert_eq!(
                verify([3; 32], [7; 32], [255; 32], &changed).unwrap_err(),
                SealError::Length
            );
        }
        assert_eq!(
            verify([3; 32], [7; 32], [0; 32], &proof).unwrap_err(),
            SealError::Target
        );
    }

    #[test]
    fn fabricated_low_endpoint_passes_filter_but_fails_full_replay() {
        let mut proof = prove([11; 32], [13; 32]);
        proof[102..].fill(0);
        assert!(precheck([11; 32], [13; 32], [1; 32], &proof).is_ok());
        let mut steps = 0;
        let result = verify_with_progress([11; 32], [13; 32], [1; 32], &proof, |p| {
            if matches!(p, Progress::Step(_)) {
                steps += 1;
            }
            Ok::<_, ()>(())
        });
        assert_eq!(
            result.unwrap_err(),
            VerifyError::Relation(SealError::Endpoint)
        );
        assert_eq!(steps, STEPS);
    }

    #[test]
    fn cached_cell_statement_still_requires_a_new_complete_chain() {
        let first = prove([21; 32], [22; 32]);
        let second = prove([23; 32], [22; 32]);
        assert_ne!(&first[102..], &second[102..]);
        let mut relabelled = first;
        relabelled[38..70].copy_from_slice(&[23; 32]);
        assert_eq!(
            verify([23; 32], [22; 32], [255; 32], &relabelled).unwrap_err(),
            SealError::Endpoint
        );
        assert!(verify([23; 32], [22; 32], [255; 32], &second).is_ok());
    }

    #[test]
    fn cancellation_never_yields_a_partial_verified_receipt() {
        let mut completed = Vec::new();
        let result = prove_with_progress([31; 32], [32; 32], |point| {
            completed.push(point);
            if point == Progress::Step(17) {
                Err("stop")
            } else {
                Ok(())
            }
        });
        assert_eq!(result.unwrap_err(), "stop");
        assert_eq!(completed.last(), Some(&Progress::Step(17)));
        let proof = prove([31; 32], [32; 32]);
        let result = verify_with_progress([31; 32], [32; 32], [255; 32], &proof, |p| {
            if p == Progress::Step(17) {
                Err("stop")
            } else {
                Ok(())
            }
        });
        assert_eq!(result.unwrap_err(), VerifyError::Cancelled("stop"));
    }

    #[test]
    fn observer_captures_actual_framed_seed_and_step_inputs() {
        let mut generated = Vec::new();
        let proof = prove_with_query_observer([41; 32], [42; 32], |query| {
            generated.push(*query);
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(generated.len(), usize::from(STEPS) + 1);
        let mut prior = None;
        for (ordinal, query) in generated.iter().enumerate() {
            assert_eq!(usize::from(query.ordinal()), ordinal);
            assert_eq!(query.profile(), profile_hash());
            assert_eq!(query.challenge(), [41; 32]);
            assert_eq!(query.statement(), [42; 32]);
            assert_eq!(query.predecessor(), prior);
            let raw = query.preimage();
            assert_eq!(raw.len(), if ordinal == 0 { 139 } else { 145 });
            // Independent test replay is NOT another original observation.
            let expected: Hash = Sha256::digest(&raw).into();
            assert_eq!(query.answer(), expected);
            prior = Some(query.answer());
        }
        let mut verified = Vec::new();
        let seal = verify_with_query_observer([41; 32], [42; 32], [255; 32], &proof, |query| {
            verified.push(*query);
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(verified, generated);
        assert_eq!(Some(seal.ticket()), prior);
        assert_eq!(seal.chainwork_awarded(), 0);
        assert_eq!(proof, prove([41; 32], [42; 32]));
    }

    #[test]
    fn observer_cancellation_includes_the_just_evaluated_query() {
        let proof = prove([51; 32], [52; 32]);
        for stop in [0, 17, STEPS] {
            let mut observed = Vec::new();
            let result =
                verify_with_query_observer([51; 32], [52; 32], [255; 32], &proof, |query| {
                    observed.push(*query);
                    if query.ordinal() == stop {
                        Err("observer-stop")
                    } else {
                        Ok(())
                    }
                });
            assert_eq!(result.unwrap_err(), VerifyError::Cancelled("observer-stop"));
            assert_eq!(observed.len(), usize::from(stop) + 1);
            assert_eq!(observed.last().unwrap().ordinal(), stop);
        }
    }

    #[test]
    fn observer_distinguishes_precheck_rejection_from_false_endpoint_replay() {
        let mut proof = prove([61; 32], [62; 32]);
        let mut count = 0;
        let result = verify_with_query_observer([61; 32], [62; 32], [0; 32], &proof, |_| {
            count += 1;
            Ok::<_, ()>(())
        });
        assert_eq!(
            result.unwrap_err(),
            VerifyError::Relation(SealError::Target)
        );
        assert_eq!(count, 0);
        proof[102..].fill(0);
        let result = verify_with_query_observer([61; 32], [62; 32], [255; 32], &proof, |_| {
            count += 1;
            Ok::<_, ()>(())
        });
        assert_eq!(
            result.unwrap_err(),
            VerifyError::Relation(SealError::Endpoint)
        );
        assert_eq!(count, usize::from(STEPS) + 1);
    }
}
