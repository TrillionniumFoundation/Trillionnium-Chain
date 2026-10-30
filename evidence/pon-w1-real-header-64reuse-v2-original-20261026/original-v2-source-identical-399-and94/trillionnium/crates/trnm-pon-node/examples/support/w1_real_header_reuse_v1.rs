//! Private opt-in registry. No admission authority, automatic fallback or timing selection.
use trnm_crypto_primitives::pon_work::{
    self,
    blocked_one_zero::BlockedOneZeroRankOnePreparedTask,
    blocked_zero::BlockedZeroPreparedTask,
    blocked_zero_paired::BlockedZeroPairedPreparedTask,
    maintenance_limb::MaintenanceLimbPreparedTask,
    maintenance_periodic::MaintenancePeriodicPreparedTask,
    maintenance_prefix::{MaintenanceIntegerPairedPreparedTask, MaintenancePrefixPreparedTask},
    paired_product::PairedPreparedTask,
    structured::{StructuredPreparedTask, TileKernel, TiledPreparedTask},
    Hash, PreparedTask, WorkError,
};

#[derive(Clone, Copy)]
pub enum Arm {
    Scalar,
    Generic,
    Structured,
    Classical,
    Strassen,
    Paired,
    Zero,
    ZeroPaired,
    OneZero,
    Periodic,
    Integer,
    Prefix,
    Limb,
}
pub const ALL: [Arm; 13] = [
    Arm::Scalar,
    Arm::Generic,
    Arm::Structured,
    Arm::Classical,
    Arm::Strassen,
    Arm::Paired,
    Arm::Zero,
    Arm::ZeroPaired,
    Arm::OneZero,
    Arm::Periodic,
    Arm::Integer,
    Arm::Prefix,
    Arm::Limb,
];
impl Arm {
    pub fn name(self) -> &'static str {
        match self {
            Self::Scalar => "scalar-original",
            Self::Generic => "prepared-generic",
            Self::Structured => "prepared-structured",
            Self::Classical => "tiled-classical",
            Self::Strassen => "tiled-strassen-one-level",
            Self::Paired => "paired-product",
            Self::Zero => "blocked-zero",
            Self::ZeroPaired => "blocked-zero-integer-paired",
            Self::OneZero => "blocked-one-zero-rank-one",
            Self::Periodic => "maintenance-periodic",
            Self::Integer => "maintenance-integer-paired",
            Self::Prefix => "maintenance-prefix",
            Self::Limb => "maintenance-limb",
        }
    }
}
pub enum Producer {
    Scalar(Vec<u32>, Vec<u32>),
    Generic(Box<PreparedTask>),
    Structured(Box<StructuredPreparedTask>),
    Tiled(Box<TiledPreparedTask>),
    Paired(Box<PairedPreparedTask>),
    Zero(Box<BlockedZeroPreparedTask>),
    ZeroPaired(Box<BlockedZeroPairedPreparedTask>),
    OneZero(Box<BlockedOneZeroRankOnePreparedTask>),
    Periodic(Box<MaintenancePeriodicPreparedTask>),
    Integer(Box<MaintenanceIntegerPairedPreparedTask>),
    Prefix(Box<MaintenancePrefixPreparedTask>),
    Limb(Box<MaintenanceLimbPreparedTask>),
}
#[derive(Default)]
pub struct Registry {
    pub setup_attempts: u64,
    pub supported_setups: u64,
}
impl Registry {
    /// Unsupported remains None. This registry never chooses another kernel.
    pub fn prepare(
        &mut self,
        arm: Arm,
        a: &[u32],
        b: &[u32],
    ) -> Result<Option<Producer>, WorkError> {
        self.setup_attempts = self.setup_attempts.checked_add(1).ok_or(WorkError::Task)?;
        let result = match arm {
            Arm::Scalar => {
                pon_work::task_id(a, b)?;
                Some(Producer::Scalar(a.to_vec(), b.to_vec()))
            }
            Arm::Generic => Some(Producer::Generic(Box::new(PreparedTask::new(a, b)?))),
            Arm::Structured => {
                StructuredPreparedTask::new(a, b)?.map(|p| Producer::Structured(Box::new(p)))
            }
            Arm::Classical | Arm::Strassen => {
                Some(Producer::Tiled(Box::new(TiledPreparedTask::new(
                    a,
                    b,
                    match arm {
                        Arm::Classical => TileKernel::Classical,
                        _ => TileKernel::StrassenOneLevel,
                    },
                )?)))
            }
            Arm::Paired => Some(Producer::Paired(Box::new(PairedPreparedTask::new(a, b)?))),
            Arm::Zero => BlockedZeroPreparedTask::new(a, b)?.map(|p| Producer::Zero(Box::new(p))),
            Arm::ZeroPaired => {
                BlockedZeroPairedPreparedTask::new(a, b)?.map(|p| Producer::ZeroPaired(Box::new(p)))
            }
            Arm::OneZero => BlockedOneZeroRankOnePreparedTask::new(a, b)?
                .map(|p| Producer::OneZero(Box::new(p))),
            Arm::Periodic => {
                MaintenancePeriodicPreparedTask::new(a, b)?.map(|p| Producer::Periodic(Box::new(p)))
            }
            Arm::Integer => MaintenanceIntegerPairedPreparedTask::new(a, b)?
                .map(|p| Producer::Integer(Box::new(p))),
            Arm::Prefix => {
                MaintenancePrefixPreparedTask::new(a, b)?.map(|p| Producer::Prefix(Box::new(p)))
            }
            Arm::Limb => {
                MaintenanceLimbPreparedTask::new(a, b)?.map(|p| Producer::Limb(Box::new(p)))
            }
        };
        if result.is_some() {
            self.supported_setups = self
                .supported_setups
                .checked_add(1)
                .ok_or(WorkError::Task)?;
        }
        Ok(result)
    }
}
impl Producer {
    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        match self {
            Self::Scalar(a, b) => pon_work::prove(challenge, a, b),
            Self::Generic(p) => p.prove(challenge),
            Self::Structured(p) => p.prove(challenge),
            Self::Tiled(p) => p.prove(challenge),
            Self::Paired(p) => p.prove(challenge),
            Self::Zero(p) => p.prove(challenge),
            Self::ZeroPaired(p) => p.prove(challenge),
            Self::OneZero(p) => p.prove(challenge),
            Self::Periodic(p) => p.prove(challenge),
            Self::Integer(p) => p.prove(challenge),
            Self::Prefix(p) => p.prove(challenge),
            Self::Limb(p) => p.prove(challenge),
        }
    }
}
