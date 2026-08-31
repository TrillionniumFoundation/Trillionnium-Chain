use std::collections::BTreeSet;

use crate::{
    error::{error, NativeBoundaryErrorCodeV0, NativeBoundaryResultV0},
    primitives::{HeightV0, ValidatorSetIdV0},
};

pub const MAX_VALIDATORS_V0: usize = 100;
pub const MAX_VALIDATOR_ID_BYTES_V0: usize = 128;
pub const MAX_TOTAL_VOTING_POWER_V0: u128 = (i64::MAX as u128) / 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeValidatorV0 {
    validator_id: String,
    public_key: [u8; 32],
    voting_power: u64,
}

impl NativeValidatorV0 {
    pub fn new(
        validator_id: impl Into<String>,
        public_key: [u8; 32],
        voting_power: u64,
    ) -> NativeBoundaryResultV0<Self> {
        let validator_id = validator_id.into();
        if validator_id.is_empty() {
            return Err(error(
                NativeBoundaryErrorCodeV0::Empty,
                "validator.validator_id",
            ));
        }
        if validator_id.len() > MAX_VALIDATOR_ID_BYTES_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooLong,
                "validator.validator_id",
            ));
        }
        if validator_id.trim() != validator_id
            || validator_id
                .as_bytes()
                .iter()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(error(
                NativeBoundaryErrorCodeV0::NotCanonical,
                "validator.validator_id",
            ));
        }
        if public_key.iter().all(|byte| *byte == 0) {
            return Err(error(
                NativeBoundaryErrorCodeV0::ZeroValue,
                "validator.public_key",
            ));
        }
        if voting_power == 0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::ZeroValue,
                "validator.voting_power",
            ));
        }
        Ok(Self {
            validator_id,
            public_key,
            voting_power,
        })
    }

    pub fn validator_id(&self) -> &str {
        &self.validator_id
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub const fn voting_power(&self) -> u64 {
        self.voting_power
    }
}

/// Canonically ordered validator set owned by the native application boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeValidatorSetV0 {
    set_id: ValidatorSetIdV0,
    validators: Vec<NativeValidatorV0>,
    total_power: u128,
    quorum_power: u128,
}

impl NativeValidatorSetV0 {
    pub fn new(
        set_id: ValidatorSetIdV0,
        validators: Vec<NativeValidatorV0>,
    ) -> NativeBoundaryResultV0<Self> {
        if validators.is_empty() {
            return Err(error(
                NativeBoundaryErrorCodeV0::Empty,
                "validator_set.validators",
            ));
        }
        if validators.len() > MAX_VALIDATORS_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooMany,
                "validator_set.validators",
            ));
        }
        if validators
            .windows(2)
            .any(|pair| pair[0].validator_id() >= pair[1].validator_id())
        {
            return Err(error(
                NativeBoundaryErrorCodeV0::NotCanonical,
                "validator_set.validators",
            ));
        }
        let mut keys = BTreeSet::new();
        let mut total_power = 0u128;
        for validator in &validators {
            if !keys.insert(*validator.public_key()) {
                return Err(error(
                    NativeBoundaryErrorCodeV0::Duplicate,
                    "validator_set.public_keys",
                ));
            }
            total_power = total_power
                .checked_add(u128::from(validator.voting_power()))
                .ok_or_else(|| {
                    error(
                        NativeBoundaryErrorCodeV0::Overflow,
                        "validator_set.total_power",
                    )
                })?;
        }
        if total_power > MAX_TOTAL_VOTING_POWER_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooLong,
                "validator_set.total_power",
            ));
        }
        let quorum_power = total_power
            .checked_mul(2)
            .and_then(|value| value.checked_div(3))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                error(
                    NativeBoundaryErrorCodeV0::Overflow,
                    "validator_set.quorum_power",
                )
            })?;
        Ok(Self {
            set_id,
            validators,
            total_power,
            quorum_power,
        })
    }

    pub const fn set_id(&self) -> ValidatorSetIdV0 {
        self.set_id
    }

    pub fn validators(&self) -> &[NativeValidatorV0] {
        &self.validators
    }

    pub const fn total_power(&self) -> u128 {
        self.total_power
    }

    pub const fn quorum_power(&self) -> u128 {
        self.quorum_power
    }
}

/// Application-approved validator transition for a future activation height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeValidatorSetTransitionV0 {
    current_set_id: ValidatorSetIdV0,
    target: NativeValidatorSetV0,
    activation_height: HeightV0,
}

impl NativeValidatorSetTransitionV0 {
    pub fn new(
        current_set_id: ValidatorSetIdV0,
        target: NativeValidatorSetV0,
        activation_height: HeightV0,
    ) -> NativeBoundaryResultV0<Self> {
        if current_set_id == target.set_id() {
            return Err(error(
                NativeBoundaryErrorCodeV0::InvalidTransition,
                "validator_transition.target_set_id",
            ));
        }
        if activation_height == HeightV0::GENESIS {
            return Err(error(
                NativeBoundaryErrorCodeV0::ZeroValue,
                "validator_transition.activation_height",
            ));
        }
        Ok(Self {
            current_set_id,
            target,
            activation_height,
        })
    }

    pub const fn current_set_id(&self) -> ValidatorSetIdV0 {
        self.current_set_id
    }

    pub const fn target(&self) -> &NativeValidatorSetV0 {
        &self.target
    }

    pub const fn activation_height(&self) -> HeightV0 {
        self.activation_height
    }
}
