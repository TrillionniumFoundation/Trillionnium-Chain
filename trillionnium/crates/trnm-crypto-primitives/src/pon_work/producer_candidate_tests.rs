use super::{maintenance_limb::MaintenanceLimbPreparedTask, *};

fn maintenance() -> (Vec<u32>, Vec<u32>) {
    (
        (0..CELLS).map(|i| ((13 * i + 17) % 257) as u32).collect(),
        (0..CELLS).map(|i| ((29 * i + 31) % 263) as u32).collect(),
    )
}

enum Producer<'a> {
    Generic(&'a PreparedTask),
    Limb(&'a MaintenanceLimbPreparedTask),
}

impl Producer<'_> {
    fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        match self {
            Self::Generic(task) => task.prove(challenge),
            Self::Limb(task) => task.prove(challenge),
        }
    }

    fn prove_with_progress<E>(
        &self,
        challenge: Hash,
        progress: impl FnMut(PreparedGenerationProgress) -> Result<(), E>,
    ) -> Result<Vec<u8>, PreparedGenerationError<E>> {
        match self {
            Self::Generic(task) => task.prove_with_progress(challenge, progress),
            Self::Limb(task) => task.prove_with_progress(challenge, progress),
        }
    }

    fn candidate(&self, challenge: Hash) -> Result<ProducerCandidate<'_>, WorkError> {
        match self {
            Self::Generic(task) => task.candidate(challenge),
            Self::Limb(task) => task.candidate(challenge),
        }
    }

    fn candidate_with_progress<E>(
        &self,
        challenge: Hash,
        progress: impl FnMut(PreparedGenerationProgress) -> Result<(), E>,
    ) -> Result<ProducerCandidate<'_>, PreparedGenerationError<E>> {
        match self {
            Self::Generic(task) => task.candidate_with_progress(challenge, progress),
            Self::Limb(task) => task.candidate_with_progress(challenge, progress),
        }
    }
}

// Independent schedule for this fixed challenge: all four expansions accept
// their first 512 words. Do not derive expected observations from either kernel.
fn observations() -> Vec<PreparedGenerationProgress> {
    let mut points = vec![PreparedGenerationProgress::BeforeReplay];
    for label in 0..4 {
        for counter in 0..64 {
            points.push(PreparedGenerationProgress::Noise { label, counter });
        }
    }
    for operand in 0..2 {
        for row in 0..N {
            points.push(PreparedGenerationProgress::NoiseRow { operand, row });
        }
    }
    for row in 0..N / R {
        for column in 0..N / R {
            for inner in 0..N / R {
                points.push(PreparedGenerationProgress::TranscriptTile { row, column, inner });
            }
        }
    }
    points.push(PreparedGenerationProgress::BeforeProof);
    assert_eq!(points.len(), 898);
    points
}

fn cancellation_boundaries(points: &[PreparedGenerationProgress]) -> Vec<usize> {
    let cuts: Vec<_> = points
        .iter()
        .enumerate()
        .filter_map(|(index, point)| {
            let boundary = match point {
                PreparedGenerationProgress::BeforeReplay
                | PreparedGenerationProgress::BeforeProof => true,
                PreparedGenerationProgress::Noise { counter, .. } => [0, 31, 63].contains(counter),
                PreparedGenerationProgress::NoiseRow { row, .. } => [0, 31, 63].contains(row),
                PreparedGenerationProgress::TranscriptTile { row, column, inner } => {
                    [0, 7].contains(row) && [0, 7].contains(column) && [0, 7].contains(inner)
                }
            };
            boundary.then_some(index)
        })
        .collect();
    assert_eq!(cuts.len(), 28);
    cuts
}

#[test]
fn legacy_producers_keep_exact_observations_and_cancellation_boundaries() {
    let (a, b) = maintenance();
    let generic = PreparedTask::new(&a, &b).unwrap();
    let limb = MaintenanceLimbPreparedTask::new(&a, &b).unwrap().unwrap();
    let challenge = [93; 32];
    let reference = prove(challenge, &a, &b).unwrap();
    let next_reference = prove([94; 32], &a, &b).unwrap();
    let expected = observations();
    for producer in [Producer::Generic(&generic), Producer::Limb(&limb)] {
        let mut actual = Vec::new();
        let proof = producer
            .prove_with_progress(challenge, |point| {
                actual.push(point);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(proof, reference);
        for cut in cancellation_boundaries(&expected) {
            let mut actual = Vec::new();
            let cancelled = producer.prove_with_progress(challenge, |point| {
                actual.push(point);
                if actual.len() - 1 == cut {
                    Err(cut)
                } else {
                    Ok(())
                }
            });
            assert_eq!(cancelled, Err(PreparedGenerationError::Cancelled(cut)));
            assert_eq!(actual, expected[..=cut]);
        }
        assert_eq!(producer.prove([94; 32]).unwrap(), next_reference);
        assert_eq!(producer.prove(challenge).unwrap(), reference);
    }
}

#[test]
fn candidate_generation_and_late_assembly_preserve_all_observations() {
    let (a, b) = maintenance();
    let generic = PreparedTask::new(&a, &b).unwrap();
    let limb = MaintenanceLimbPreparedTask::new(&a, &b).unwrap().unwrap();
    let challenge = [93; 32];
    let expected = observations();
    let reference = prove(challenge, &a, &b).unwrap();
    for producer in [Producer::Generic(&generic), Producer::Limb(&limb)] {
        let mut actual = Vec::new();
        let candidate = producer
            .candidate_with_progress(challenge, |point| {
                actual.push(point);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(actual, expected[..expected.len() - 1]);
        assert_eq!(candidate.prefix.len(), PROOF_BYTES - 32);
        // Reading a candidate's observations does not serialize a proof or
        // consume the late checkpoint. Both remain bound to the original input.
        assert_eq!(candidate.challenge, challenge);
        assert_eq!(
            candidate.ticket(),
            hash(b"ticket", &[&challenge, &candidate.trace()])
        );
        assert_eq!(actual.len(), 897);
        let proof = candidate
            .into_proof_with_progress(|point| {
                actual.push(point);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(proof, reference);
        assert_eq!(producer.candidate(challenge).unwrap().into_proof(), proof);
    }
}

#[test]
fn candidate_cancellation_returns_no_candidate_or_late_proof() {
    let (a, b) = maintenance();
    let generic = PreparedTask::new(&a, &b).unwrap();
    let limb = MaintenanceLimbPreparedTask::new(&a, &b).unwrap().unwrap();
    let challenge = [93; 32];
    let expected = observations();
    let reference = prove(challenge, &a, &b).unwrap();
    for producer in [Producer::Generic(&generic), Producer::Limb(&limb)] {
        for cut in cancellation_boundaries(&expected) {
            if expected[cut] == PreparedGenerationProgress::BeforeProof {
                continue;
            }
            let mut actual = Vec::new();
            let cancelled = producer.candidate_with_progress(challenge, |point| {
                actual.push(point);
                if actual.len() - 1 == cut {
                    Err(cut)
                } else {
                    Ok(())
                }
            });
            assert!(
                matches!(cancelled, Err(PreparedGenerationError::Cancelled(value)) if value == cut)
            );
            assert_eq!(actual, expected[..=cut]);
        }
        let candidate = producer.candidate(challenge).unwrap();
        // A completed trace may be retained while the caller's deadline expires.
        // Cancellation must still happen at the later serialization call.
        let mut late = Vec::new();
        let cancelled = candidate.into_proof_with_progress(|point| {
            late.push(point);
            Err("expired before serialization")
        });
        assert_eq!(cancelled, Err("expired before serialization"));
        assert_eq!(late, [PreparedGenerationProgress::BeforeProof]);
        assert_eq!(
            producer.candidate(challenge).unwrap().into_proof(),
            reference
        );
    }
}

#[test]
fn candidate_bytes_and_tickets_remain_subject_to_native_context_and_relation_checks() {
    for (a, b) in [
        maintenance(),
        (vec![0; CELLS], vec![0; CELLS]),
        (vec![Q as u32 - 1; CELLS], vec![Q as u32 - 1; CELLS]),
    ] {
        let generic = PreparedTask::new(&a, &b).unwrap();
        let limb = MaintenanceLimbPreparedTask::new(&a, &b).unwrap();
        let mut producers = vec![Producer::Generic(&generic)];
        if let Some(limb) = &limb {
            producers.push(Producer::Limb(limb));
        }
        let task = task_id(&a, &b).unwrap();
        for producer in producers {
            for challenge in [[0; 32], [255; 32], [93; 32]] {
                let reference = prove(challenge, &a, &b).unwrap();
                let candidate = producer.candidate(challenge).unwrap();
                assert_eq!(candidate.prefix, &reference[..PROOF_BYTES - 32]);
                if let Producer::Generic(prepared) = &producer {
                    assert_eq!(candidate.prefix.as_ptr(), prepared.prefix.as_ptr());
                }
                let trace: Hash = reference[PROOF_BYTES - 32..].try_into().unwrap();
                assert_eq!(candidate.trace(), trace);
                let ticket = candidate.ticket();
                assert_eq!(ticket, hash(b"ticket", &[&challenge, &trace]));
                let proof = candidate.into_proof();
                assert_eq!(proof, reference);
                assert_eq!(
                    verify(challenge, task, [255; 32], &proof).unwrap().ticket(),
                    ticket
                );
                verify_reference(challenge, task, [255; 32], &proof).unwrap();

                let mut wrong_task = task;
                wrong_task[0] ^= 1;
                assert_eq!(
                    verify(challenge, wrong_task, [255; 32], &proof).unwrap_err(),
                    WorkError::Task
                );
                let mut wrong_challenge = challenge;
                wrong_challenge[0] ^= 1;
                assert_eq!(
                    verify(wrong_challenge, task, [255; 32], &proof).unwrap_err(),
                    WorkError::Transcript
                );
                let mut lower_target = ticket;
                let last_nonzero = lower_target.iter().rposition(|byte| *byte != 0).unwrap();
                lower_target[last_nonzero] -= 1;
                lower_target[last_nonzero + 1..].fill(255);
                assert_eq!(
                    verify(challenge, task, lower_target, &proof).unwrap_err(),
                    WorkError::Target
                );
                let mut bad_trace = proof.clone();
                bad_trace[PROOF_BYTES - 1] ^= 1;
                assert_eq!(
                    verify(challenge, task, [255; 32], &bad_trace).unwrap_err(),
                    WorkError::Transcript
                );
                let mut bad_product = proof.clone();
                let word = &mut bad_product[4 + 2 * CELLS * 4..8 + 2 * CELLS * 4];
                let value = u32::from_le_bytes((&*word).try_into().unwrap());
                word.copy_from_slice(&(((u128::from(value) + 1) % Q) as u32).to_le_bytes());
                assert_eq!(
                    verify(challenge, task, [255; 32], &bad_product).unwrap_err(),
                    WorkError::Product
                );
            }
        }
    }
}
