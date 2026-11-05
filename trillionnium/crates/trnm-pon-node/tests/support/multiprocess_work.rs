//! Existing W1 producers and independently acquired hostile inputs. No new
//! work relation, ledger authority, target or admission bypass lives here.
use serde_json::{json, Value};
use trnm_crypto_primitives::pon_work::{
    self,
    maintenance_limb::MaintenanceLimbPreparedTask,
    maintenance_periodic::MaintenancePeriodicPreparedTask,
    maintenance_prefix::{MaintenanceIntegerPairedPreparedTask, MaintenancePrefixPreparedTask},
    paired_product::PairedPreparedTask,
    structured::{TileKernel, TiledPreparedTask},
    PreparedTask, WorkError,
};
use trnm_mvcc_fee::continuity_v1;
use trnm_protocol::pon_wire::{hash, Header};

pub const METHODS: [&str; 8] = [
    "prepared-generic",
    "tiled-classical",
    "tiled-strassen-one-level",
    "paired-product",
    "maintenance-periodic",
    "maintenance-integer-paired",
    "maintenance-prefix",
    "maintenance-limb",
];

pub enum Producer {
    Generic(PreparedTask),
    Tiled(TiledPreparedTask),
    Paired(PairedPreparedTask),
    Periodic(MaintenancePeriodicPreparedTask),
    Integer(MaintenanceIntegerPairedPreparedTask),
    Prefix(Box<MaintenancePrefixPreparedTask>),
    Limb(MaintenanceLimbPreparedTask),
}
impl Producer {
    pub fn new(index: usize) -> Result<Self, WorkError> {
        let (a, b) = continuity_v1::maintenance_matrices();
        match index {
            0 => Ok(Self::Generic(PreparedTask::new(&a, &b)?)),
            1 | 2 => Ok(Self::Tiled(TiledPreparedTask::new(
                &a,
                &b,
                if index == 1 {
                    TileKernel::Classical
                } else {
                    TileKernel::StrassenOneLevel
                },
            )?)),
            3 => Ok(Self::Paired(PairedPreparedTask::new(&a, &b)?)),
            4 => MaintenancePeriodicPreparedTask::new(&a, &b)?
                .map(Self::Periodic)
                .ok_or(WorkError::Task),
            5 => MaintenanceIntegerPairedPreparedTask::new(&a, &b)?
                .map(Self::Integer)
                .ok_or(WorkError::Task),
            6 => MaintenancePrefixPreparedTask::new(&a, &b)?
                .map(|task| Self::Prefix(Box::new(task)))
                .ok_or(WorkError::Task),
            7 => MaintenanceLimbPreparedTask::new(&a, &b)?
                .map(Self::Limb)
                .ok_or(WorkError::Task),
            _ => Err(WorkError::Task),
        }
    }
    pub fn prove(&self, challenge: [u8; 32]) -> Result<Vec<u8>, WorkError> {
        match self {
            Self::Generic(task) => task.prove(challenge),
            Self::Tiled(task) => task.prove(challenge),
            Self::Paired(task) => task.prove(challenge),
            Self::Periodic(task) => task.prove(challenge),
            Self::Integer(task) => task.prove(challenge),
            Self::Prefix(task) => task.prove(challenge),
            Self::Limb(task) => task.prove(challenge),
        }
    }
}

pub fn legal_search(
    producer: &Producer,
    mut header: Header,
) -> Result<(Header, Vec<u8>, Vec<Value>), String> {
    let initial = header.nonce;
    let mut attempts = Vec::new();
    for attempt in 0..4096 {
        header.nonce = initial.checked_add(attempt).ok_or_else(|| {
            format!(
                "nonce overflow; retained_attempts={}",
                serde_json::to_string(&attempts).unwrap()
            )
        })?;
        let challenge = header.challenge();
        let proof = producer.prove(challenge).map_err(|error| {
            format!(
                "producer failed {error:?}; retained_attempts={}",
                serde_json::to_string(&attempts).unwrap()
            )
        })?;
        let ticket = hash(b"ticket", &[&challenge, &proof[proof.len() - 32..]]);
        let hit = ticket <= header.target;
        attempts.push(json!({"nonce":header.nonce,"ticket":hex::encode(ticket),
            "trace":hex::encode(&proof[proof.len()-32..]),"target_hit":hit}));
        if hit {
            return Ok((header, proof, attempts));
        }
    }
    Err(format!(
        "legal search exhausted; retained_attempts={}",
        serde_json::to_string(&attempts).unwrap()
    ))
}

pub fn from_zero(header: Header) -> Result<(Vec<u8>, Vec<Value>), String> {
    let (a, b) = continuity_v1::maintenance_matrices();
    if pon_work::task_id(&a, &b).map_err(|error| format!("{error:?}"))? != header.work_task {
        return Err("source task mismatch".to_owned());
    }
    let mut proof = Vec::with_capacity(pon_work::PROOF_BYTES);
    proof.extend_from_slice(b"PNW1");
    for matrix in [&a, &b] {
        for value in matrix {
            proof.extend_from_slice(&value.to_le_bytes());
        }
    }
    proof.resize(pon_work::PROOF_BYTES, 0);
    let challenge = header.challenge();
    let mut attempts = Vec::new();
    for nonce in 0_u64..4096 {
        let trace = hash(
            b"multiprocess-from-zero-v1",
            &[&challenge, &nonce.to_le_bytes()],
        );
        let ticket = hash(b"ticket", &[&challenge, &trace]);
        let hit = ticket <= header.target;
        attempts.push(json!({"nonce":nonce,"trace":hex::encode(trace),"ticket":hex::encode(ticket),"target_hit":hit}));
        if hit {
            proof[pon_work::PROOF_BYTES - 32..].copy_from_slice(&trace);
            return Ok((proof, attempts));
        }
    }
    Err(format!(
        "from-zero search exhausted; retained_attempts={}",
        serde_json::to_string(&attempts).unwrap()
    ))
}

pub fn corrupt_product(proof: &mut [u8]) {
    let position = 4 + 2 * pon_work::CELLS * 4;
    let original = u32::from_le_bytes(proof[position..position + 4].try_into().unwrap());
    let changed = ((u128::from(original) + 1) % pon_work::Q) as u32;
    proof[position..position + 4].copy_from_slice(&changed.to_le_bytes());
}
