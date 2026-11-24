// The Python fixture prefixes original ReleaseBundle definitions above this
// adapter. External coreutils replaces only the sha2 digest implementation.
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};

struct Sha256(Vec<u8>);

impl Sha256 {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.0.extend_from_slice(bytes.as_ref());
    }

    fn finalize(self) -> [u8; 32] {
        let mut child = Command::new("sha256sum")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&self.0).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let text = std::str::from_utf8(&output.stdout).unwrap();
        let hex = text.split_ascii_whitespace().next().unwrap();
        assert_eq!(hex.len(), 64);
        std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
    }
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let mut out = io::stdout().lock();
    let mut frames = input.chunks_exact(193);
    for frame in &mut frames {
        let digest = |index: usize| {
            Digest32V0(frame[index * 32..(index + 1) * 32].try_into().unwrap())
        };
        let exact = ExactSourceV0 {
            repository_digest: digest(0),
            commit_digest: digest(1),
            tree_digest: digest(2),
            cargo_lock_digest: digest(3),
            toolchain_digest: digest(4),
            production_closure_digest: digest(5),
            dirty: match frame[192] {
                0 => false,
                1 => true,
                _ => panic!("an invalid fixture bool cannot be represented by Rust"),
            },
        };
        match exact.validate() {
            Ok(accepted) => {
                assert_eq!(accepted, exact);
                out.write_all(&[0])?;
                out.write_all(&accepted.canonical_digest().0)?;
            }
            Err(ReleaseBundleErrorV0::InvalidExactSource) => out.write_all(&[101])?,
            Err(other) => panic!("unexpected original error: {other:?}"),
        }
    }
    assert!(frames.remainder().is_empty());
    Ok(())
}
