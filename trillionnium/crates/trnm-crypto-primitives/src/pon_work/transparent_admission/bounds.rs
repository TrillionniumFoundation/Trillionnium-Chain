//! Exact bounded wire compatibility for the PWAI0001 research verifier.
//!
//! The accepted bincode-1.3 fixed-width bytes remain unchanged. One grammar
//! scans without allocation, then translates only enum/length widths to the
//! SDK's Borsh representation. It is not a general bincode implementation or a
//! new wire format. Proof checks and all old dimensions remain with the caller.
use anyhow::{bail, ensure, Result};
use risc0_zkvm::Receipt;
#[cfg(test)]
use std::io::{self, Write};

const MAX_BYTES: usize = super::MAX_CERTIFICATE_BYTES - 16 - super::INPUT_BYTES;
const MAX_WORDS: usize = MAX_BYTES / 4;
const JOURNAL_BYTES: usize = 228;

#[derive(Clone, Copy)]
enum Encoding {
    LegacyFixed,
    Borsh,
}
impl Encoding {
    fn destination(self) -> Self {
        match self {
            Self::LegacyFixed => Self::Borsh,
            Self::Borsh => Self::LegacyFixed,
        }
    }
}

struct Cursor<'a> {
    remaining: &'a [u8],
    encoding: Encoding,
    output: Option<Vec<u8>>,
}
impl<'a> Cursor<'a> {
    fn read(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.remaining.len(), "truncated Succinct field");
        let (a, b) = self.remaining.split_at(n);
        self.remaining = b;
        Ok(a)
    }
    fn emit(&mut self, bytes: &[u8]) -> Result<()> {
        if let Some(output) = &mut self.output {
            ensure!(
                bytes.len() <= MAX_BYTES - output.len(),
                "Succinct wire byte budget"
            );
            output.try_reserve_exact(bytes.len())?;
            output.extend_from_slice(bytes);
        }
        Ok(())
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let bytes = self.read(n)?;
        self.emit(bytes)?;
        Ok(bytes)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
    fn tag(&mut self, allowed: &[u32], reason: &'static str) -> Result<u32> {
        let tag = match self.encoding {
            Encoding::LegacyFixed => u32::from_le_bytes(self.read(4)?.try_into()?),
            Encoding::Borsh => u32::from(self.read(1)?[0]),
        };
        ensure!(allowed.contains(&tag), reason);
        match self.encoding.destination() {
            Encoding::Borsh => self.emit(&[u8::try_from(tag)?])?,
            Encoding::LegacyFixed => self.emit(&tag.to_le_bytes())?,
        }
        Ok(tag)
    }
    fn len(&mut self, cap: usize) -> Result<usize> {
        let n = match self.encoding {
            Encoding::LegacyFixed => u64::from_le_bytes(self.read(8)?.try_into()?),
            Encoding::Borsh => u64::from(u32::from_le_bytes(self.read(4)?.try_into()?)),
        };
        ensure!(n <= cap as u64, "Succinct allocation budget");
        match self.encoding.destination() {
            Encoding::Borsh => self.emit(&u32::try_from(n)?.to_le_bytes())?,
            Encoding::LegacyFixed => self.emit(&n.to_le_bytes())?,
        }
        Ok(n as usize)
    }
    fn state(&mut self) -> Result<()> {
        let n = match self.tag(&[0, 1], "unknown state variant")? {
            0 => 36,
            1 => 32,
            _ => bail!("unknown state variant"),
        };
        self.take(n)?;
        Ok(())
    }
    fn journal(&mut self) -> Result<()> {
        ensure!(self.len(JOURNAL_BYTES)? == JOURNAL_BYTES, "fixed PWJ1 size");
        self.take(JOURNAL_BYTES)?;
        Ok(())
    }
    fn claim(&mut self) -> Result<()> {
        // Every retained lift/join has its complete claim opened. No unknown
        // claim or pruned whole-claim object is admitted to this new profile.
        self.tag(&[0], "opened Succinct claim required")?;
        self.state()?;
        self.state()?;
        match self.tag(&[0, 1, 2, 3], "unknown exit variant")? {
            0 | 1 => {
                self.u32()?;
            }
            2 | 3 => {}
            _ => bail!("unknown exit variant"),
        }
        match self.tag(&[0, 1], "unknown input variant")? {
            0 => ensure!(self.take(1)? == [0], "unsupported claim input"),
            1 => {
                self.take(32)?;
            }
            _ => bail!("unknown input variant"),
        }
        match self.tag(&[0, 1], "unknown output variant")? {
            1 => {
                self.take(32)?;
                return Ok(());
            }
            0 => {}
            _ => bail!("unknown output variant"),
        }
        match self.take(1)? {
            [0] => return Ok(()),
            [1] => {}
            _ => bail!("unknown output option"),
        }
        match self.tag(&[0, 1], "unknown journal variant")? {
            0 => self.journal()?,
            1 => {
                self.take(32)?;
            }
            _ => bail!("unknown journal variant"),
        }
        match self.tag(&[0, 1], "unknown assumptions variant")? {
            0 => {
                self.len(0)?;
            }
            1 => ensure!(self.take(32)? == [0u8; 32], "unresolved assumptions"),
            _ => bail!("unknown assumptions variant"),
        }
        Ok(())
    }
    fn succinct(&mut self) -> Result<()> {
        let words = self.len(MAX_WORDS)?;
        ensure!(words >= 33, "truncated recursion seal globals");
        let seal = self.take(words * 4)?;
        // Pinned recursion 4.0.5 CircuitInfo::OUTPUT_SIZE=32; unlike RV32IM,
        // this generic STARK seal starts with those globals, without a version.
        ensure!(
            u32::from_le_bytes(seal[128..132].try_into()?) == 18,
            "only pinned po2=18 recursion is evaluated"
        );
        self.take(32)?; // Control ID; native SDK binds it to its allowed root.
        self.claim()?;
        ensure!(
            self.len(9)? == 9 && self.take(9)? == b"poseidon2",
            "hash suite"
        );
        self.take(32)?; // Verifier parameters, checked against the pinned SDK.
        ensure!(self.u32()? < 256, "control inclusion index");
        ensure!(self.len(8)? == 8, "fixed control inclusion depth");
        self.take(8 * 32)?;
        Ok(())
    }
}

fn scan(raw: &[u8], encoding: Encoding, output: Option<Vec<u8>>) -> Result<Option<Vec<u8>>> {
    ensure!(raw.len() <= MAX_BYTES, "Succinct wire byte budget");
    let mut c = Cursor {
        remaining: raw,
        encoding,
        output,
    };
    c.tag(&[1], "only actual Succinct receipts")?;
    c.succinct()?;
    c.journal()?;
    c.take(32)?;
    ensure!(c.remaining.is_empty(), "trailing Succinct bytes");
    Ok(c.output)
}

pub(super) fn preflight(raw: &[u8]) -> Result<()> {
    scan(raw, Encoding::LegacyFixed, None).map(|_| ())
}

fn transcode(raw: &[u8], encoding: Encoding) -> Result<Vec<u8>> {
    // No output buffer or SDK Vec is allocated until the same full grammar has
    // accepted every length, option, dimension and the exact end of the input.
    match encoding {
        Encoding::LegacyFixed => preflight(raw)?,
        Encoding::Borsh => {
            scan(raw, encoding, None)?;
        }
    }
    let mut output = Vec::new();
    output.try_reserve_exact(raw.len())?;
    match scan(raw, encoding, Some(output))? {
        Some(output) => Ok(output),
        None => bail!("missing explicit Succinct conversion output"),
    }
}

pub(super) fn decode(raw: &[u8]) -> Result<Receipt> {
    let internal = transcode(raw, Encoding::LegacyFixed)?;
    Ok(borsh::from_slice(&internal)?)
}

// Tests must alter actual typed receipt values without keeping the retired
// bincode dependency alive as a dev-dependency. This writer also bounds the
// internal serialization before reverse conversion to the original wire.
#[cfg(test)]
struct BoundedBorsh(Vec<u8>);

#[cfg(test)]
impl Write for BoundedBorsh {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BYTES - self.0.len() {
            return Err(io::Error::other("Succinct wire byte budget"));
        }
        self.0
            .try_reserve_exact(bytes.len())
            .map_err(|_| io::Error::other("Succinct allocation budget"))?;
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn encode(receipt: &Receipt) -> Result<Vec<u8>> {
    let mut output = BoundedBorsh(Vec::new());
    borsh::BorshSerialize::serialize(receipt, &mut output)?;
    transcode(&output.0, Encoding::Borsh)
}

#[cfg(test)]
mod tests;
