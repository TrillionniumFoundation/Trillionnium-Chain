use super::*;
use risc0_binfmt::Digestible;
use sha2::{Digest as _, Sha256};

const ORIGINAL: &[u8] = include_bytes!("../complete-w1-succinct.bin");

fn original_receipt() -> &'static [u8] {
    assert_eq!(ORIGINAL.len(), 273_338);
    assert_eq!(
        hex::encode(Sha256::digest(ORIGINAL)),
        "9c370089ba5203b9a8559b900c975778425839f4ccfa171387bdfb0853a3e5c9"
    );
    assert_eq!(&ORIGINAL[..8], b"PWSR0001");
    let receipt = &ORIGINAL[16 + super::super::INPUT_BYTES..];
    assert_eq!(receipt.len(), 223_682);
    assert_eq!(
        hex::encode(Sha256::digest(receipt)),
        "d2f8a217f58e3917315a0cba6a3010c813ac8934328b662f151fb936d0341b3e"
    );
    receipt
}

#[test]
fn original_real_receipt_roundtrips_without_wire_or_claim_changes() {
    let original = original_receipt();
    let receipt = decode(original).unwrap();
    assert_eq!(encode(&receipt).unwrap(), original);
    assert_eq!(
        transcode(original, Encoding::LegacyFixed).unwrap(),
        borsh::to_vec(&receipt).unwrap()
    );
    assert_eq!(
        receipt
            .claim()
            .unwrap()
            .digest::<risc0_zkvm::sha::Impl>()
            .to_string(),
        "c717de185bfb18d3990dd7b31e4f94a2831dd159d8e9366740ea74e4c8e14a03"
    );
    // The parent module's retained positive test separately performs the real
    // cryptographic verification. Codec roundtrip alone grants no authority.
}

struct Skeleton {
    wire: Vec<u8>,
    lengths: Vec<usize>,
}

impl Skeleton {
    fn u32(&mut self, value: u32) {
        self.wire.extend(value.to_le_bytes());
    }
    fn len(&mut self, value: u64) {
        self.lengths.push(self.wire.len());
        self.wire.extend(value.to_le_bytes());
    }
    fn digest(&mut self, byte: u8) {
        self.wire.extend([byte; 32]);
    }
    fn state(&mut self, pruned: bool) {
        self.u32(u32::from(pruned));
        if !pruned {
            self.u32(0x1122_3344);
        }
        self.digest(0x55);
    }
    fn journal(&mut self) {
        self.len(JOURNAL_BYTES as u64);
        self.wire.extend([0x77; JOURNAL_BYTES]);
    }
}

// Independent legacy-width construction exercises every allowed nested claim
// branch. These small false seals are syntactic test objects, never proofs.
fn skeleton(pre: bool, post: bool, exit: u32, input: bool, output: u32) -> Skeleton {
    let mut s = Skeleton {
        wire: Vec::new(),
        lengths: Vec::new(),
    };
    s.u32(1); // Succinct.
    s.len(33); // The complete fixed recursion globals, including po2.
    s.wire.extend([0; 128]);
    s.u32(18);
    s.digest(0x11); // Control ID.
    s.u32(0); // Opened ReceiptClaim.
    s.state(pre);
    s.state(post);
    s.u32(exit);
    if exit <= 1 {
        s.u32(0x5566_7788);
    }
    s.u32(u32::from(input));
    if input {
        s.digest(0x22);
    } else {
        s.wire.push(0); // Value(None).
    }
    match output {
        0 => {
            s.u32(1); // Pruned output.
            s.digest(0x33);
        }
        1 => {
            s.u32(0);
            s.wire.push(0); // Value(None).
        }
        2..=5 => {
            s.u32(0);
            s.wire.push(1); // Value(Some(Output)).
            if output < 4 {
                s.u32(0);
                s.journal();
            } else {
                s.u32(1);
                s.digest(0x44);
            }
            if output.is_multiple_of(2) {
                s.u32(0);
                s.len(0); // Value(empty assumptions).
            } else {
                s.u32(1);
                s.digest(0); // Pruned empty-assumptions digest.
            }
        }
        _ => unreachable!(),
    }
    s.len(9);
    s.wire.extend(b"poseidon2");
    s.digest(0x66); // Verifier parameters.
    s.u32(7); // Control inclusion index; this primitive remains u32.
    s.len(8);
    s.wire.extend([0x88; 8 * 32]);
    s.journal();
    s.digest(0x99); // Metadata, retained rather than reconstructed.
    s
}

#[test]
fn all_supported_claim_variants_keep_exact_legacy_bytes() {
    let mut count = 0;
    for pre in [false, true] {
        for post in [false, true] {
            for exit in 0..4 {
                for input in [false, true] {
                    for output in 0..6 {
                        let s = skeleton(pre, post, exit, input, output);
                        preflight(&s.wire).unwrap();
                        let receipt = decode(&s.wire).unwrap();
                        assert_eq!(encode(&receipt).unwrap(), s.wire);
                        assert_eq!(
                            transcode(&s.wire, Encoding::LegacyFixed).unwrap(),
                            borsh::to_vec(&receipt).unwrap()
                        );
                        count += 1;
                    }
                }
            }
        }
    }
    assert_eq!(count, 192);
}

#[test]
fn every_variable_length_refuses_before_internal_conversion() {
    let s = skeleton(false, true, 0, true, 2);
    for offset in s.lengths {
        let mut bomb = s.wire.clone();
        bomb[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            preflight(&bomb).unwrap_err().to_string(),
            "Succinct allocation budget"
        );
        assert_eq!(
            transcode(&bomb, Encoding::LegacyFixed)
                .unwrap_err()
                .to_string(),
            "Succinct allocation budget"
        );
        assert!(decode(&bomb).is_err());
    }
}

#[test]
fn every_small_shape_truncation_and_trailing_byte_refuse() {
    let s = skeleton(false, true, 0, true, 2);
    for keep in 0..s.wire.len() {
        assert!(preflight(&s.wire[..keep]).is_err(), "prefix {keep}");
        assert!(decode(&s.wire[..keep]).is_err(), "prefix {keep}");
    }
    let mut trailing = s.wire;
    trailing.push(0);
    assert_eq!(
        decode(&trailing).unwrap_err().to_string(),
        "trailing Succinct bytes"
    );
}

#[test]
fn internal_borsh_is_never_a_second_accepted_public_wire() {
    let original = original_receipt();
    let internal = transcode(original, Encoding::LegacyFixed).unwrap();
    assert_ne!(original, internal);
    assert!(decode(&internal).is_err());
    assert_eq!(transcode(&internal, Encoding::Borsh).unwrap(), original);
    let mut length_bomb = internal.clone();
    length_bomb[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(transcode(&length_bomb, Encoding::Borsh).is_err());
    let mut trailing = internal;
    trailing.push(0);
    assert!(transcode(&trailing, Encoding::Borsh).is_err());
}

#[test]
fn internal_encoder_respects_the_existing_byte_budget() {
    let mut bounded = BoundedBorsh(Vec::new());
    bounded.write_all(&vec![0; MAX_BYTES]).unwrap();
    assert!(bounded.write_all(&[0]).is_err());
    assert_eq!(bounded.0.len(), MAX_BYTES);
    let mut receipt = decode(original_receipt()).unwrap();
    receipt.journal.bytes = vec![0; MAX_BYTES + 1];
    assert!(encode(&receipt).is_err());
}

#[test]
fn malformed_kinds_dimensions_and_lengths_refuse() {
    for kind in [0u32, 2, 3, u32::MAX] {
        assert!(preflight(&kind.to_le_bytes()).is_err());
    }
    let mut raw = 1u32.to_le_bytes().to_vec();
    raw.extend(u64::MAX.to_le_bytes());
    assert!(preflight(&raw).is_err());
    assert!(preflight(&vec![0; MAX_BYTES + 1]).is_err());
}
