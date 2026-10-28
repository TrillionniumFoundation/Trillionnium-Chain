//! Fixed research adapter parameters, checked against M01 by its native tests.
pub const N: usize = 64;
pub const R: usize = 8;
pub const Q: u128 = 4_294_967_291;
pub const CELLS: usize = N * N;
pub const PROOF_BYTES: usize = 4 + 3 * CELLS * 4 + 32;
pub type Hash = [u8; 32];
