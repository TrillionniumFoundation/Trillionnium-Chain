//! Test driver: compile the unchanged native M02 source, not a second Rust model.
use std::io::{self, BufRead};

type Result<T> = std::result::Result<T, &'static str>;
fn ensure(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}

#[allow(dead_code)]
#[path = "../../trillionnium/crates/trnm-pon-node/src/consensus.rs"]
mod native;

fn bytes<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err("DRIVER_ENCODING");
    }
    let mut result = [0; N];
    for (i, cell) in result.iter_mut().enumerate() {
        *cell = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| "DRIVER_ENCODING")?;
    }
    Ok(result)
}

fn encoded(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn number(value: &str) -> Result<u64> {
    value.parse().map_err(|_| "DRIVER_ENCODING")
}

fn run(input: &str) -> Result<String> {
    if input.len() > 4096 {
        return Err("DRIVER_LENGTH");
    }
    let p: Vec<_> = input.split_whitespace().collect();
    match p.as_slice() {
        ["work", target] => Ok(encoded(&native::required_work(bytes(target)?)?.bytes())),
        ["add", a, b] => Ok(encoded(
            &native::Work::from_bytes(bytes(a)?)
                .checked_add(native::Work::from_bytes(bytes(b)?))?
                .bytes(),
        )),
        ["retarget", parent, first, last, interval, spacing, limit] => {
            Ok(encoded(&native::retarget(
                bytes(parent)?,
                number(first)?,
                number(last)?,
                number(interval)?,
                number(spacing)?,
                bytes(limit)?,
            )?))
        }
        ["time", candidate, now, skew, ancestors @ ..] => {
            let times = ancestors
                .iter()
                .map(|s| number(s))
                .collect::<Result<Vec<_>>>()?;
            native::check_time(number(candidate)?, &times, number(now)?, number(skew)?)?;
            Ok(String::new())
        }
        _ => Err("DRIVER_ENCODING"),
    }
}

fn main() {
    for line in io::stdin().lock().lines() {
        let result = line.map_err(|_| "DRIVER_IO").and_then(|line| run(&line));
        match result {
            Ok(value) => println!("ok:{value}"),
            Err(error) => println!("err:{error}"),
        }
    }
}
