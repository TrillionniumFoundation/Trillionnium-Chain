//! Connect canonical native header binding to full W1 transcript verification.
//! This is a primitive regression, not Node admission or a work-cost certificate.
use trnm_crypto_primitives::pon_work::{self, Hash, VerifiedWork, WorkError, CELLS};
use trnm_protocol::{pon_growth::GrowthHeader, pon_wire::Header};

type Verifier = fn(Hash, Hash, Hash, &[u8]) -> Result<VerifiedWork, WorkError>;
type HeaderMutation = fn(&mut Header);

#[test]
fn complete_w1_proofs_cannot_move_between_header_fields_or_growth_domains() {
    let header = Header::decode(include_bytes!(
        "../../../../formal/pon-nakamoto-v1/vectors/header.bin"
    ))
    .expect("retained canonical header");
    let proof = include_bytes!("../../../../formal/pon-nakamoto-v1/vectors/work.bin");
    assert_eq!(proof.len(), pon_work::PROOF_BYTES);
    let words: Vec<u32> = proof[4..4 + 3 * CELLS * 4]
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect();
    let task = pon_work::task_id(&words[..CELLS], &words[CELLS..2 * CELLS]).unwrap();
    assert_eq!(header.work_task, task);

    let growth = GrowthHeader {
        ledger: header.clone(),
        witness: [71; 32],
    };
    let prepared = pon_work::PreparedTask::new(&words[..CELLS], &words[CELLS..2 * CELLS]).unwrap();
    let growth_proof = prepared.prove(growth.challenge()).unwrap();
    let mutations: [(&str, HeaderMutation); 12] = [
        ("network", |h| h.network[0] ^= 1),
        ("parameters", |h| h.parameters[0] ^= 1),
        ("parent", |h| h.parent[0] ^= 1),
        ("height", |h| h.height ^= 1),
        ("timestamp", |h| h.timestamp ^= 1),
        ("target", |h| h.target[31] ^= 1),
        ("miner", |h| h.miner[0] ^= 1),
        ("transactions", |h| h.transactions[0] ^= 1),
        ("state", |h| h.state[0] ^= 1),
        ("receipts", |h| h.receipts[0] ^= 1),
        ("work_task", |h| h.work_task[0] ^= 1),
        ("nonce", |h| h.nonce ^= 1),
    ];
    // Default currently selects FullLimb; explicit names retain all comparison
    // APIs without representing those two entries as independent algorithms.
    let verifiers: [(&str, Verifier); 6] = [
        ("default", pon_work::verify),
        ("scalar-reference", pon_work::verify_reference),
        ("transposed", pon_work::verify_transposed),
        ("limb-transcript", pon_work::verify_limb),
        ("full-limb", pon_work::verify_full_limb),
        ("column-limb", pon_work::verify_column_limb),
    ];
    for (kernel, verify) in verifiers {
        for (profile, challenge, bytes) in [
            ("PNH1", header.challenge(), proof.as_slice()),
            ("PGH2", growth.challenge(), growth_proof.as_slice()),
        ] {
            let valid = verify(challenge, task, [255; 32], bytes)
                .unwrap_or_else(|error| panic!("{kernel}/{profile}: {error:?}"));
            assert_eq!(valid.challenge(), challenge);
            assert_eq!(valid.task(), task);
            assert_eq!(valid.product(), &words[2 * CELLS..]);
        }

        let reject_reused = |label: &str, original: Hash, changed: Hash, bytes: &[u8]| {
            assert_ne!(original, changed, "{kernel}/{label}: header not bound");
            // Keep the committed A/B task and use a permissive verifier target
            // so a cheap Task/Target failure cannot mask missing transcript
            // binding. In particular, the changed header's target and work_task
            // still enter its challenge. This deliberately isolated tuple is
            // not a request to bypass Node's actual target/task admission rules.
            pon_work::precheck_proof_statement(changed, task, [255; 32], bytes)
                .unwrap_or_else(|error| panic!("{kernel}/{label}: cheap filter {error:?}"));
            assert_eq!(
                verify(changed, task, [255; 32], bytes).unwrap_err(),
                WorkError::Transcript,
                "{kernel}/{label}: old complete proof crossed a changed statement"
            );
        };

        for (field, mutate) in mutations {
            let mut changed = header.clone();
            mutate(&mut changed);
            assert_eq!(Header::decode(&changed.encode()).unwrap(), changed);
            reject_reused(field, header.challenge(), changed.challenge(), proof);

            let changed_growth = GrowthHeader {
                ledger: changed,
                witness: growth.witness,
            };
            assert_eq!(
                GrowthHeader::decode(&changed_growth.encode()).unwrap(),
                changed_growth
            );
            reject_reused(
                field,
                growth.challenge(),
                changed_growth.challenge(),
                &growth_proof,
            );
        }
        let mut changed_witness = growth.clone();
        changed_witness.witness[0] ^= 1;
        assert_eq!(
            GrowthHeader::decode(&changed_witness.encode()).unwrap(),
            changed_witness
        );
        reject_reused(
            "growth-witness",
            growth.challenge(),
            changed_witness.challenge(),
            &growth_proof,
        );
        reject_reused(
            "PNH1-proof-in-PGH2",
            header.challenge(),
            growth.challenge(),
            proof,
        );
        reject_reused(
            "PGH2-proof-in-PNH1",
            growth.challenge(),
            header.challenge(),
            &growth_proof,
        );
    }
}
