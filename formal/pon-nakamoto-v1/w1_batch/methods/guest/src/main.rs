#![no_main]

use risc0_zkvm::guest::env;
use std::io::Read;
use trnm_w1_batch_statement::{
    input_count, Builder, Leaf, FROZEN_LEAF_IMAGE_ID, HEADER_BYTES, INPUT_PREFIX_BYTES,
    LEAF_ENTRY_BYTES,
};

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut input = env::stdin();
    let mut prefix = [0u8; INPUT_PREFIX_BYTES];
    input.read_exact(&mut prefix).expect("exact batch prefix");
    let count = input_count(&prefix).expect("bounded nonempty leaf count");
    let mut builder = Builder::new(count).expect("bounded batch statement");
    let mut entry = [0u8; LEAF_ENTRY_BYTES];
    for _ in 0..count {
        input.read_exact(&mut entry).expect("complete leaf entry");
        let leaf = Leaf {
            header: &entry[..HEADER_BYTES],
            journal: &entry[HEADER_BYTES..],
        };
        builder
            .push(leaf)
            .expect("exact public bindings and distinct original work");
        // No conditional branch can skip this. It proves the ENTIRE existing
        // frozen W1 relation, including noise rejection, transcript prefixes,
        // range checks, multiplication and ticket. Host must resolve every
        // assumption with a real leaf receipt before a final receipt verifies.
        env::verify(FROZEN_LEAF_IMAGE_ID, leaf.journal).expect("full W1 proof assumption");
    }
    let mut trailing = [0u8; 1];
    assert_eq!(
        input.read(&mut trailing).expect("input EOF"),
        0,
        "trailing input"
    );
    let journal = builder.finish().expect("all declared leaves present");
    env::commit_slice(&journal);
}
