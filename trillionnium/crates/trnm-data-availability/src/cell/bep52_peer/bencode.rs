//! Small borrowed parser for network headers only. Torrent info remains an
//! exact byte comparison against the independent TCM1-derived descriptor.

use super::{require, CellErrorV1, CellResultV1};

#[derive(Debug)]
pub(super) enum Value<'a> {
    Bytes(&'a [u8]),
    Integer(i64),
    List(Vec<Value<'a>>),
    Dictionary(Vec<(&'a [u8], Value<'a>)>),
}

impl<'a> Value<'a> {
    pub(super) fn dictionary(&self) -> CellResultV1<&Vec<(&'a [u8], Value<'a>)>> {
        match self {
            Self::Dictionary(values) => Ok(values),
            _ => Err(CellErrorV1::Invalid("BEP52 bencode dictionary")),
        }
    }
    pub(super) fn optional(&self, key: &[u8]) -> CellResultV1<Option<&Value<'a>>> {
        Ok(self
            .dictionary()?
            .iter()
            .find_map(|(name, value)| (*name == key).then_some(value)))
    }
    pub(super) fn number(&self, key: &[u8]) -> CellResultV1<u64> {
        self.optional(key)?
            .ok_or(CellErrorV1::Invalid("BEP52 bencode required field"))?
            .integer()
    }
    pub(super) fn integer(&self) -> CellResultV1<u64> {
        match self {
            Self::Integer(value) if *value >= 0 => Ok(*value as u64),
            _ => Err(CellErrorV1::Invalid("BEP52 bencode unsigned integer")),
        }
    }
    pub(super) fn bytes(&self) -> CellResultV1<&'a [u8]> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            _ => Err(CellErrorV1::Invalid("BEP52 bencode bytes")),
        }
    }
    pub(super) fn list(&self) -> CellResultV1<&[Value<'a>]> {
        match self {
            Self::List(values) => Ok(values),
            _ => Err(CellErrorV1::Invalid("BEP52 bencode list")),
        }
    }
    pub(super) fn field(&self, key: &[u8]) -> CellResultV1<&Value<'a>> {
        self.optional(key)?
            .ok_or(CellErrorV1::Invalid("BEP52 bencode required field"))
    }
}

pub(super) fn decode(bytes: &[u8]) -> CellResultV1<(Value<'_>, usize)> {
    let mut parser = Parser {
        bytes,
        offset: 0,
        items: 0,
    };
    let value = parser.value(0)?;
    Ok((value, parser.offset))
}

struct Parser<'a> {
    bytes: &'a [u8],
    offset: usize,
    items: usize,
}

impl<'a> Parser<'a> {
    fn value(&mut self, depth: usize) -> CellResultV1<Value<'a>> {
        require(depth <= 8 && self.items < 128, "BEP52 bencode complexity")?;
        self.items += 1;
        match self.bytes.get(self.offset).copied() {
            Some(b'0'..=b'9') => Ok(Value::Bytes(self.string()?)),
            Some(b'i') => {
                self.offset += 1;
                let start = self.offset;
                while self
                    .bytes
                    .get(self.offset)
                    .is_some_and(|byte| *byte != b'e')
                {
                    require(self.offset - start < 20, "BEP52 bencode integer bound")?;
                    self.offset += 1;
                }
                require(
                    self.bytes.get(self.offset) == Some(&b'e'),
                    "BEP52 bencode integer end",
                )?;
                let raw = &self.bytes[start..self.offset];
                require(!raw.is_empty(), "BEP52 bencode integer empty")?;
                let digits = if raw[0] == b'-' { &raw[1..] } else { raw };
                require(
                    !digits.is_empty() && digits.iter().all(u8::is_ascii_digit),
                    "BEP52 bencode integer digits",
                )?;
                require(
                    digits.len() == 1 || digits[0] != b'0',
                    "BEP52 bencode integer canonical",
                )?;
                require(raw != b"-0", "BEP52 bencode negative zero")?;
                let number = std::str::from_utf8(raw)
                    .map_err(|_| CellErrorV1::Invalid("BEP52 bencode integer"))?
                    .parse()
                    .map_err(|_| CellErrorV1::Invalid("BEP52 bencode integer overflow"))?;
                self.offset += 1;
                Ok(Value::Integer(number))
            }
            Some(b'l') => {
                self.offset += 1;
                let mut values = Vec::new();
                while self.bytes.get(self.offset) != Some(&b'e') {
                    values.push(self.value(depth + 1)?);
                }
                self.offset += 1;
                Ok(Value::List(values))
            }
            Some(b'd') => {
                self.offset += 1;
                let mut values: Vec<(&[u8], Value<'a>)> = Vec::new();
                while self.bytes.get(self.offset) != Some(&b'e') {
                    let key = self.string()?;
                    require(
                        values.last().is_none_or(|(previous, _)| *previous < key),
                        "BEP52 bencode key order/duplicate",
                    )?;
                    values.push((key, self.value(depth + 1)?));
                }
                self.offset += 1;
                Ok(Value::Dictionary(values))
            }
            _ => Err(CellErrorV1::Invalid("BEP52 bencode value")),
        }
    }

    fn string(&mut self) -> CellResultV1<&'a [u8]> {
        let start = self.offset;
        let mut length = 0usize;
        while let Some(byte) = self
            .bytes
            .get(self.offset)
            .copied()
            .filter(u8::is_ascii_digit)
        {
            require(self.offset - start < 5, "BEP52 bencode string bound")?;
            length = length * 10 + (byte - b'0') as usize;
            self.offset += 1;
        }
        require(
            self.offset > start && self.bytes.get(self.offset) == Some(&b':'),
            "BEP52 bencode string length",
        )?;
        require(
            self.offset - start == 1 || self.bytes[start] != b'0',
            "BEP52 bencode string canonical",
        )?;
        self.offset += 1;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CellErrorV1::Invalid("BEP52 bencode string overflow"))?;
        require(end <= self.bytes.len(), "BEP52 bencode string truncated")?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }
}
