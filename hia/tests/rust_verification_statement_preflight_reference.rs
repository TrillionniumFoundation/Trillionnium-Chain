// Exact Rust registry, statement and pre-provider sequence are prefixed by the test.
use std::process::{Command, Stdio};

struct Sha256(Vec<u8>);
impl Sha256 {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.extend_from_slice(data.as_ref());
    }
    fn finalize(self) -> [u8; 32] {
        let mut child = Command::new("/usr/bin/sha256sum")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&self.0).unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success());
        let hex = std::str::from_utf8(&result.stdout[..64]).unwrap();
        std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
    }
}

#[derive(Default)]
struct AbsentBackend {
    calls: usize,
    selected: Option<VerificationProfileV1>,
}
impl VerificationBackendV1 for AbsentBackend {
    fn verify(
        &mut self,
        profile: VerificationProfileV1,
        _: &VerificationStatementV1,
        _: &VerificationEvidenceV1,
    ) -> VerificationBackendResultV1 {
        self.calls += 1;
        self.selected = Some(profile);
        VerificationBackendResultV1::Unavailable
    }
}

fn statement(s: &[u8]) -> VerificationStatementV1 {
    VerificationStatementV1 {
        task_id: fixed(s, 0),
        lease_id: fixed(s, 32),
        execution_receipt_id: fixed(s, 64),
        profile_id: fixed(s, 96),
        profile_version: u32_at(s, 128),
        profile_hash: fixed(s, 132),
        artifact_evidence_digest: fixed(s, 164),
        availability_certificate_digest: fixed(s, 196),
        evidence_window_start: u64_at(s, 228),
        evidence_window_end: u64_at(s, 236),
        submitted_height: u64_at(s, 244),
        statement_digest: fixed(s, 252),
    }
}
fn evidence(e: &[u8]) -> VerificationEvidenceV1 {
    VerificationEvidenceV1 {
        task_id: fixed(e, 0),
        lease_id: fixed(e, 32),
        execution_receipt_id: fixed(e, 64),
        artifact_evidence_digest: fixed(e, 96),
        availability_certificate_digest: fixed(e, 128),
        backend_payload_digest: fixed(e, 160),
    }
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let mut raw = &input[..];
    let mut out = io::stdout().lock();
    while !raw.is_empty() {
        let count = u64_at(raw, 8) as usize;
        let start = 92 + 97 * count;
        let construct = u32_at(raw, 4) == 0;
        let (frame, next) = raw.split_at(start + if construct { 252 } else { 476 });
        raw = next;
        let s = &frame[start..];
        if construct {
            match VerificationStatementV1::new(
                fixed(s, 0),
                fixed(s, 32),
                fixed(s, 64),
                fixed(s, 96),
                u32_at(s, 128),
                fixed(s, 132),
                fixed(s, 164),
                fixed(s, 196),
                u64_at(s, 228),
                u64_at(s, 236),
                u64_at(s, 244),
            ) {
                Ok(statement) => {
                    out.write_all(&[0, 0])?;
                    out.write_all(&statement.statement_digest)?;
                }
                Err(err) => out.write_all(&[error(err), 0])?,
            }
            continue;
        }
        let registry = match VerificationProfileRegistryV1::closed(
            frame[92..start].chunks_exact(97).map(decode).collect(),
        ) {
            Ok(registry) => registry,
            Err(err) => {
                out.write_all(&[error(err), 0])?;
                continue;
            }
        };
        let stmt = statement(s);
        let evidence = evidence(&s[284..]);
        let mut backend = AbsentBackend::default();
        let result =
            verify_statement_v1(&registry, &stmt, &evidence, u64_at(frame, 16), &mut backend);
        match result {
            Ok(decision) => {
                assert_eq!(backend.calls, 1);
                assert_eq!(decision.status, VerificationDecisionStatusV1::Unavailable);
                assert!(!decision.economic_authority && !decision.order_reorg_authority);
                let selected = backend.selected.unwrap();
                assert_eq!(decision.profile_kind, selected.kind);
                out.write_all(&[0, 1])?;
                out.write_all(&decision.statement_digest)?;
                emit(selected, &mut out)?;
            }
            Err(err) => {
                assert_eq!(backend.calls, 0);
                out.write_all(&[error(err), 0])?;
            }
        }
    }
    Ok(())
}
