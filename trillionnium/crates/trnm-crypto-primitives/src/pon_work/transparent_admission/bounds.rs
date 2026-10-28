//! Allocation-free scan for the explicit PWAI0001 research verifier.
//! Adapted from the retained #534 Succinct scanner; no live packet rule changes.
use anyhow::{bail, ensure, Result};

const MAX_BYTES: usize = super::MAX_CERTIFICATE_BYTES - 16 - super::INPUT_BYTES;
const MAX_WORDS: usize = MAX_BYTES / 4;
const JOURNAL_BYTES: usize = 228;

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.0.len(), "truncated Succinct field");
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
    fn len(&mut self, cap: usize) -> Result<usize> {
        let n = u64::from_le_bytes(self.take(8)?.try_into()?);
        ensure!(n <= cap as u64, "Succinct allocation budget");
        Ok(n as usize)
    }
    fn state(&mut self) -> Result<()> {
        let n = match self.u32()? {
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
        ensure!(self.u32()? == 0, "opened Succinct claim required");
        self.state()?;
        self.state()?;
        match self.u32()? {
            0 | 1 => {
                self.u32()?;
            }
            2 | 3 => {}
            _ => bail!("unknown exit variant"),
        }
        match self.u32()? {
            0 => ensure!(self.take(1)? == [0], "unsupported claim input"),
            1 => {
                self.take(32)?;
            }
            _ => bail!("unknown input variant"),
        }
        match self.u32()? {
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
        match self.u32()? {
            0 => self.journal()?,
            1 => {
                self.take(32)?;
            }
            _ => bail!("unknown journal variant"),
        }
        match self.u32()? {
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

pub(super) fn preflight(raw: &[u8]) -> Result<()> {
    ensure!(raw.len() <= MAX_BYTES, "Succinct wire byte budget");
    let mut c = Cursor(raw);
    ensure!(c.u32()? == 1, "only actual Succinct receipts");
    c.succinct()?;
    c.journal()?;
    c.take(32)?;
    ensure!(c.0.is_empty(), "trailing Succinct bytes");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_kinds_dimensions_and_lengths_refuse() {
        for kind in [0u32, 2, 3, u32::MAX] {
            assert!(preflight(&kind.to_le_bytes()).is_err());
        }
        let mut raw = 1u32.to_le_bytes().to_vec();
        raw.extend(u64::MAX.to_le_bytes());
        assert!(preflight(&raw).is_err());
        assert!(preflight(&vec![0; MAX_BYTES + 1]).is_err());
    }
}
