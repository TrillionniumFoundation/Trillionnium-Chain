use std::{env, fs, io};

fn main() -> io::Result<()> {
    let args: Vec<_> = env::args_os().collect();
    if args.len() != 3 { return Err(io::Error::new(io::ErrorKind::InvalidInput, "two raw paths required")); }
    match fs::hard_link(&args[1], &args[2]) {
        Ok(()) => println!("{{\"errno\":0,\"message\":\"\"}}"),
        Err(error) => println!("{{\"errno\":{},\"message\":{:?}}}", error.raw_os_error().unwrap_or(-1), error.to_string()),
    }
    Ok(())
}
