use crate::error::{error, NativeBoundaryErrorCodeV0, NativeBoundaryResultV0};

pub const MAX_CHAIN_ID_BYTES_V0: usize = 128;

/// Canonical 32-byte value used by the native boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash32V0([u8; 32]);

impl Hash32V0 {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }

    pub(crate) fn require_nonzero(self, field: &'static str) -> NativeBoundaryResultV0<Self> {
        if self.is_zero() {
            Err(error(NativeBoundaryErrorCodeV0::ZeroValue, field))
        } else {
            Ok(self)
        }
    }
}

macro_rules! hash_newtype {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Hash32V0);

        impl $name {
            pub fn new(bytes: [u8; 32]) -> NativeBoundaryResultV0<Self> {
                Ok(Self(
                    Hash32V0::new(bytes).require_nonzero(stringify!($name))?,
                ))
            }

            pub const fn hash(self) -> Hash32V0 {
                self.0
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }
    };
}

hash_newtype!(ApplicationCommitIdV0);
hash_newtype!(BlockIdV0);
hash_newtype!(GenesisHashV0);
hash_newtype!(ReceiptsRootV0);
hash_newtype!(StateRootV0);
hash_newtype!(ValidatorSetIdV0);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainIdV0(String);

impl ChainIdV0 {
    pub fn new(value: impl Into<String>) -> NativeBoundaryResultV0<Self> {
        let value = value.into();
        if value.is_empty() {
            return Err(error(NativeBoundaryErrorCodeV0::Empty, "chain_id"));
        }
        if value.len() > MAX_CHAIN_ID_BYTES_V0 {
            return Err(error(NativeBoundaryErrorCodeV0::TooLong, "chain_id"));
        }
        if value.trim() != value || value.as_bytes().iter().any(|byte| byte.is_ascii_control()) {
            return Err(error(NativeBoundaryErrorCodeV0::NotCanonical, "chain_id"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HeightV0(u64);

impl HeightV0 {
    pub const GENESIS: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn checked_next(self) -> NativeBoundaryResultV0<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| error(NativeBoundaryErrorCodeV0::Overflow, "height"))
    }
}

/// Exact committed application head used by execution, commit, and recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationHeadV0 {
    height: HeightV0,
    block_id: BlockIdV0,
    state_root: StateRootV0,
    commit_id: ApplicationCommitIdV0,
}

impl ApplicationHeadV0 {
    pub const fn new(
        height: HeightV0,
        block_id: BlockIdV0,
        state_root: StateRootV0,
        commit_id: ApplicationCommitIdV0,
    ) -> Self {
        Self {
            height,
            block_id,
            state_root,
            commit_id,
        }
    }

    pub const fn height(&self) -> HeightV0 {
        self.height
    }

    pub const fn block_id(&self) -> BlockIdV0 {
        self.block_id
    }

    pub const fn state_root(&self) -> StateRootV0 {
        self.state_root
    }

    pub const fn commit_id(&self) -> ApplicationCommitIdV0 {
        self.commit_id
    }
}
