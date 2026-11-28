use std::ffi::OsStr;
use std::io::{self, BufRead};
use std::os::unix::ffi::OsStrExt;

include!(concat!(
    env!("TRNM_SETTLEMENT_URI_SOURCE_DIR"),
    "/original.rs"
));

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for line in io::stdin().lock().lines() {
        let raw = line?;
        assert!(raw.len().is_multiple_of(2));
        let data = (0..raw.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&raw[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()?;
        println!("{}", read_only_store_uri(Path::new(OsStr::from_bytes(&data))));
    }
    Ok(())
}
