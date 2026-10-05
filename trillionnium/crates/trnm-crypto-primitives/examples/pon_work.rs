//! Research/conformance command, not a daemon or production miner.
use std::{
    env, fs,
    io::{self, BufRead},
};
use trnm_crypto_primitives::pon_work::*;
fn fixed(s: &str) -> Result<Hash, String> {
    hex::decode(s)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "hash length".into())
}
fn run(line: &str) -> Result<String, String> {
    let args: Vec<_> = line.split_whitespace().collect();
    match args.as_slice() {
        ["verify", challenge, task, target, path] => {
            if fs::metadata(path).map_err(|e| e.to_string())?.len() != PROOF_BYTES as u64 {
                return Err("proof length".into());
            }
            let data = fs::read(path).map_err(|e| e.to_string())?;
            let result = verify(fixed(challenge)?, fixed(task)?, fixed(target)?, &data)
                .map_err(|e| format!("{e:?}"))?;
            Ok(format!(
                "{} {}",
                hex::encode(result.ticket()),
                hex::encode(hash(
                    b"product",
                    &[&result
                        .product()
                        .iter()
                        .flat_map(|v| v.to_le_bytes())
                        .collect::<Vec<_>>()]
                ))
            ))
        }
        ["prove", challenge, input, output] => {
            if fs::metadata(input).map_err(|e| e.to_string())?.len() != (8 * CELLS) as u64 {
                return Err("input length".into());
            }
            let data = fs::read(input).map_err(|e| e.to_string())?;
            if data.len() != 8 * CELLS {
                return Err("input length".into());
            }
            let values: Vec<u32> = data
                .as_chunks::<4>()
                .0
                .iter()
                .map(|chunk| chunk.as_slice())
                .map(|p| u32::from_le_bytes([p[0], p[1], p[2], p[3]]))
                .collect();
            let proof = prove(fixed(challenge)?, &values[..CELLS], &values[CELLS..])
                .map_err(|e| format!("{e:?}"))?;
            fs::write(output, &proof).map_err(|e| e.to_string())?;
            Ok(hex::encode(
                task_id(&values[..CELLS], &values[CELLS..]).map_err(|e| format!("{e:?}"))?,
            ))
        }
        _ => Err("usage: prove challenge input output | verify challenge task target proof".into()),
    }
}
fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    if args == ["--stream"] {
        for line in io::stdin().lock().lines() {
            match line {
                Ok(l) => println!(
                    "{}",
                    run(&l)
                        .map(|x| format!("OK {x}"))
                        .unwrap_or_else(|e| format!("ERR {e}"))
                ),
                Err(_) => break,
            }
        }
    } else {
        match run(&args.join(" ")) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2)
            }
        }
    }
}
