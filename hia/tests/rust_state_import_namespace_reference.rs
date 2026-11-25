use std::io::{self, Read, Write};

// The test prepends the unchanged standalone function from the current
// trnm-state-import original source before compiling this observer.
fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut rows = raw.as_slice();
    let mut observed = Vec::new();
    while !rows.is_empty() {
        let Some((size_bytes, rest)) = rows.split_at_checked(4) else {
            return Err(io::Error::other("incomplete namespace length"));
        };
        let size = u32::from_le_bytes(size_bytes.try_into().expect("four length bytes"));
        let Some((namespace, rest)) = rest.split_at_checked(size as usize) else {
            return Err(io::Error::other("incomplete namespace bytes"));
        };
        observed.push(u8::from(forbidden_authority_namespace(namespace)));
        rows = rest;
    }
    io::stdout().write_all(&observed)?;
    Ok(())
}
