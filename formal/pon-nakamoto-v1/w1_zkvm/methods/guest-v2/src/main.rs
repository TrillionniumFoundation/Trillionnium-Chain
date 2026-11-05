#![no_main]
#![no_std]
extern crate alloc;
use risc0_zkvm::guest::env;
use trnm_w1_zk_relation::v2::{check_complete_relation, INPUT_BYTES};

risc0_zkvm::guest::entry!(main);
fn main() {
    let mut input = alloc::vec![0u8; INPUT_BYTES];
    env::read_slice(&mut input);
    let journal = check_complete_relation(&input)
        .expect("full native PNH1/PNW1 relation with original A/B artifact commitments");
    env::commit_slice(&journal);
}
