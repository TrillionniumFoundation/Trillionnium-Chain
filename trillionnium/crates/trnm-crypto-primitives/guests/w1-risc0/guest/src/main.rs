#![no_main]

use risc0_zkvm::guest::env;
use std::io::Read;
use trnm_w1_guest_relation::full_relation;

risc0_zkvm::guest::entry!(main);

fn main() {
    // A fixed input, one extra byte at most, and no variable-sized advice.
    let mut input = Vec::with_capacity(full_relation::INPUT_BYTES);
    env::stdin()
        .take((full_relation::INPUT_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .expect("bounded guest input");
    let result = full_relation::execute_input(&input).expect("complete W1 relation");
    // This becomes authenticated only by a real STARK of this exact image.
    // No proof randomness, PoVW nonce or receipt encoding enters W1's lottery.
    env::commit_slice(&result.journal());
}
