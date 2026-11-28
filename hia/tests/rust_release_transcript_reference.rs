// The Python fixture prefixes original source bodies before rustc compiles this
// standalone adapter. Digests use independent coreutils at the sha2 seam.
use std::io::{self, Cursor, Read, Write};
use std::process::{Command, Stdio};

fn digest<const N: usize>(utility: &str, feed: &[u8]) -> [u8; N] {
    let mut child = Command::new(utility)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("independent digest utility");
    child.stdin.take().unwrap().write_all(feed).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let text = std::str::from_utf8(&output.stdout).unwrap();
    let encoded = text.split_ascii_whitespace().next().unwrap();
    assert_eq!(encoded.len(), 2 * N);
    std::array::from_fn(|i| u8::from_str_radix(&encoded[i * 2..i * 2 + 2], 16).unwrap())
}

struct Sha256(Vec<u8>);
impl Sha256 {
    fn new() -> Self { Self(Vec::new()) }
    fn update(&mut self, bytes: impl AsRef<[u8]>) { self.0.extend_from_slice(bytes.as_ref()); }
    fn finalize(self) -> [u8; 32] { digest("sha256sum", &self.0) }
}
struct Sha512(Vec<u8>);
impl Sha512 {
    fn new() -> Self { Self(Vec::new()) }
    fn update(&mut self, bytes: impl AsRef<[u8]>) { self.0.extend_from_slice(bytes.as_ref()); }
    fn finalize(self) -> [u8; 64] { digest("sha512sum", &self.0) }
}

struct SliceReader<'a> {
    data: &'a [u8],
    widths: Vec<u16>,
    step: usize,
    fault: usize,
    fault_mode: u8,
}
impl Read for SliceReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let index = self.widths.len();
        self.widths.push(out.len().try_into().unwrap());
        if index == self.fault {
            return match self.fault_mode {
                1 => Err(io::ErrorKind::Interrupted.into()),
                2 => Ok(out.len() + 1),
                3 => Err(io::ErrorKind::UnexpectedEof.into()),
                _ => panic!("unexpected fixture fault mode"),
            };
        }
        let n = out.len().min(self.step);
        self.data.read(&mut out[..n])
    }
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let mut input = Cursor::new(input);
    fn take<const N: usize>(reader: &mut impl Read) -> [u8; N] {
        let mut bytes = [0; N];
        reader.read_exact(&mut bytes).unwrap();
        bytes
    }
    let context = ContentContextV1 {
        profile_id: CryptoProfileId(take(&mut input)),
        instance: take(&mut input),
        generation: u64::from_le_bytes(take(&mut input)),
        kind: match take::<1>(&mut input)[0] {
            1 => ContentKind::StateSnapshot,
            2 => ContentKind::ReleaseArtifact,
            _ => unreachable!(),
        },
    };
    let mut budget = ContentReadBudget::new(
        u64::from_le_bytes(take(&mut input)), u64::from_le_bytes(take(&mut input))
    ).unwrap();
    let precharge = u64::from_le_bytes(take(&mut input));
    if precharge != 0 {
        budget.reserve(precharge).unwrap();
    }
    let step = u16::from_le_bytes(take(&mut input)) as usize;
    let fault = u16::from_le_bytes(take(&mut input)) as usize;
    let fault_mode = take::<1>(&mut input)[0];
    let meta_size = u16::from_le_bytes(take(&mut input)) as usize;
    let mut meta = vec![0; meta_size];
    input.read_exact(&mut meta)?;
    let logical = u16::from_le_bytes(meta[..2].try_into().unwrap()) as usize;
    let media = u16::from_le_bytes(meta[2..4].try_into().unwrap()) as usize;
    assert_eq!(meta.len(), 109 + logical + media);
    let artifact = ArtifactEntryV0 {
        logical_name: meta[109..109 + logical].to_vec(),
        media_type: meta[109 + logical..].to_vec(),
        size_bytes: u64::from_le_bytes(meta[4..12].try_into().unwrap()),
        executable: meta[12] != 0,
        content_digest: Digest32V0(meta[13..45].try_into().unwrap()),
        platform_digest: Digest32V0(meta[45..77].try_into().unwrap()),
        source_path_digest: Digest32V0(meta[77..109].try_into().unwrap()),
    };
    let position = input.position() as usize;
    let mut raw = SliceReader {
        data: &input.get_ref()[position..], widths: Vec::new(), step, fault, fault_mode,
    };
    let (code, claim) = match observe_release_artifact_v1(&context, &mut budget, &artifact, &mut raw) {
        Ok(observed) => (0, observed.claim.encode()),
        Err(ReleaseContentError::InvalidArtifact) => (1, vec![]),
        Err(ReleaseContentError::Content(ContentCommitmentError::Budget)) => (2, vec![]),
        Err(ReleaseContentError::Content(ContentCommitmentError::Truncated)) => (3, vec![]),
        Err(ReleaseContentError::Content(ContentCommitmentError::Io(_))) => (4, vec![]),
        Err(ReleaseContentError::Content(ContentCommitmentError::TrailingBytes)) => (5, vec![]),
        Err(ReleaseContentError::LegacyLocatorMismatch) => (6, vec![]),
        Err(other) => panic!("unexpected original outcome: {other:?}"),
    };
    let mut out = io::stdout().lock();
    out.write_all(&[code, u8::from(budget.exhausted)])?;
    out.write_all(&budget.reads.to_le_bytes())?;
    out.write_all(&budget.bytes.to_le_bytes())?;
    let consumed = (input.get_ref().len() - position - raw.data.len()) as u64;
    out.write_all(&consumed.to_le_bytes())?;
    out.write_all(&(raw.widths.len() as u16).to_le_bytes())?;
    for width in raw.widths {
        out.write_all(&width.to_le_bytes())?;
    }
    out.write_all(&claim)
}
