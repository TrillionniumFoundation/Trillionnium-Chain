//! Test framing for the unchanged original private recovery ACK codec.
use std::io::{self, BufRead};
use trnm_peer_lease::qualification_recovery_ack_codec_v1;

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        assert_eq!(line.len() % 2, 0);
        let input: Vec<u8> = (0..line.len())
            .step_by(2)
            .map(|position| u8::from_str_radix(&line[position..position + 2], 16).unwrap())
            .collect();
        let (code, output) = qualification_recovery_ack_codec_v1(&input);
        let text = output
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        println!("{code} {text}");
    }
}
