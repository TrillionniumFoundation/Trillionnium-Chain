//! Plain hex adapter calling the actual public legacy ASERT arithmetic.
use std::io::{self, BufRead};
use trnm_pon_node::research_work_schedule::{asert_target, AsertInputs};

fn fixed<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    data[offset..offset + N].try_into().unwrap()
}

fn main() -> io::Result<()> {
    for line in io::stdin().lock().lines() {
        let line = line?;
        assert_eq!(line.len(), 224);
        let input: Vec<u8> = line.as_bytes().chunks_exact(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(&input[..8], b"NASA0001");
        let value = AsertInputs {
            anchor_target: fixed(&input, 8),
            pow_limit: fixed(&input, 40),
            time_delta: i128::from_le_bytes(fixed(&input, 72)),
            intervals: u64::from_le_bytes(fixed(&input, 88)),
            spacing_seconds: u64::from_le_bytes(fixed(&input, 96)),
            half_life_seconds: u64::from_le_bytes(fixed(&input, 104)),
        };
        match asert_target(value) {
            Ok(bytes) => {
                print!("OK ");
                for x in bytes {
                    print!("{x:02x}");
                }
                println!();
            }
            Err(error) => println!("ERR {error}"),
        }
    }
    Ok(())
}
