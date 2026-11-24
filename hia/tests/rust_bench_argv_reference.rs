// Observe exactly the Unix argv access underlying the retained Clap Args::parse.
// This standalone test executable receives only synthetic fixtures.
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mut out = io::stdout().lock();
    out.write_all(&(args.len() as u64).to_le_bytes())?;
    for arg in args {
        out.write_all(arg.as_os_str().as_bytes())?;
        out.write_all(&[0])?;
    }
    Ok(())
}
