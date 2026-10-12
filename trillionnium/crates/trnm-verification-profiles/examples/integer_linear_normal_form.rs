//! Local component runner: no Node, ledger, signature, admission or reward path.
use std::{env, fs::File, io::Read, path::Path, process};
use trnm_verification_profiles::exact_integer_linear_v1::{
    hex, verify_integer_linear_v1, IntegerLinearContextV1, MAX_ADAPTER_BYTES, MAX_CONTRACT_BYTES,
    MAX_MULTIPLICATIONS,
};

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("INTEGER_LINEAR:Length".into());
    }
    Ok(bytes)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 2 && args.len() != 4 {
        return Err("usage: integer_linear_normal_form CONTRACT.json ADAPTER.json [--max-multiplications 771..6168]".into());
    }
    let work = if args.len() == 4 {
        if args[2] != "--max-multiplications"
            || args[3].is_empty()
            || !args[3].bytes().all(|c| c.is_ascii_digit())
        {
            return Err("INTEGER_LINEAR:WorkBudget".into());
        }
        args[3].parse::<usize>()?
    } else {
        MAX_MULTIPLICATIONS
    };
    let context =
        IntegerLinearContextV1::decode(&read_bounded(Path::new(&args[0]), MAX_CONTRACT_BYTES)?)?;
    let adapter = read_bounded(Path::new(&args[1]), MAX_ADAPTER_BYTES)?;
    let checked = verify_integer_linear_v1(&context, &adapter, work)?;
    let normal = String::from_utf8(checked.normal_bytes())?;
    println!("{{\"artifact\":\"{}\",\"consensus_authority\":false,\"contract\":\"{}\",\"factor_coefficients\":{},\"function_fingerprint\":\"{}\",\"general_model_equivalence\":false,\"normal\":{},\"product_multiplications\":{},\"rank\":{},\"reward_authority\":false,\"schema\":\"native-integer-linear-component-result-v1\"}}", hex(&checked.artifact()), hex(&context.contract_id()), checked.factor_coefficients(), hex(&checked.function_fingerprint()), normal, checked.product_multiplications(), checked.rank());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(2);
    }
}
