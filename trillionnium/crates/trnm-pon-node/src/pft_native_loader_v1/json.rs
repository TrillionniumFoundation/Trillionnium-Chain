//! Bounded framing with duplicate checks; numeric objects never become scalars.
use super::{NativePftErrorV1 as Error, Result};
use serde_json::{Map, Value};

pub(super) fn parse(raw: &[u8]) -> Result<Value> {
    let mut parser = Parser {
        raw,
        position: 0,
        nodes: 0,
    };
    let value = parser.value(0)?;
    parser.whitespace();
    if parser.position != raw.len() {
        return Err(Error::Json);
    }
    Ok(value)
}

struct Parser<'a> {
    raw: &'a [u8],
    position: usize,
    nodes: usize,
}

impl Parser<'_> {
    fn whitespace(&mut self) {
        while self
            .raw
            .get(self.position)
            .is_some_and(|c| b" \n\r\t".contains(c))
        {
            self.position += 1;
        }
    }

    fn take(&mut self, byte: u8) -> Result<()> {
        self.whitespace();
        if self.raw.get(self.position) != Some(&byte) {
            return Err(Error::Json);
        }
        self.position += 1;
        Ok(())
    }

    fn string(&mut self) -> Result<String> {
        self.whitespace();
        let start = self.position;
        self.take(b'"')?;
        loop {
            if self.position.saturating_sub(start) > 131072 {
                return Err(Error::Limit);
            }
            match self.raw.get(self.position) {
                Some(b'\\') => self.position += 2,
                Some(b'"') => {
                    self.position += 1;
                    if self.position - start > 131072 {
                        return Err(Error::Limit);
                    }
                    return serde_json::from_slice(&self.raw[start..self.position])
                        .map_err(|_| Error::Json);
                }
                Some(_) => self.position += 1,
                None => return Err(Error::Json),
            }
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > 8 || self.nodes == 300000 {
            return Err(Error::Limit);
        }
        self.nodes += 1;
        self.whitespace();
        match self.raw.get(self.position).copied() {
            Some(b'"') => self.string().map(Value::String),
            Some(b'{') => {
                self.position += 1;
                let mut map = Map::new();
                self.whitespace();
                if self.raw.get(self.position) == Some(&b'}') {
                    self.position += 1;
                    return Ok(Value::Object(map));
                }
                loop {
                    if map.len() == 32 {
                        return Err(Error::Limit);
                    }
                    let key = self.string()?;
                    if map.contains_key(&key) {
                        return Err(Error::DuplicateKey);
                    }
                    self.take(b':')?;
                    map.insert(key, self.value(depth + 1)?);
                    self.whitespace();
                    if self.raw.get(self.position) == Some(&b'}') {
                        self.position += 1;
                        break;
                    }
                    self.take(b',')?;
                }
                Ok(Value::Object(map))
            }
            Some(b'[') => {
                self.position += 1;
                let mut values = Vec::new();
                self.whitespace();
                if self.raw.get(self.position) == Some(&b']') {
                    self.position += 1;
                    return Ok(Value::Array(values));
                }
                loop {
                    values.push(self.value(depth + 1)?);
                    self.whitespace();
                    if self.raw.get(self.position) == Some(&b']') {
                        self.position += 1;
                        break;
                    }
                    self.take(b',')?;
                }
                Ok(Value::Array(values))
            }
            Some(b'-' | b'0'..=b'9') => {
                let start = self.position;
                while self
                    .raw
                    .get(self.position)
                    .is_some_and(|c| !b" \n\r\t,]}".contains(c))
                {
                    self.position += 1;
                    if self.position - start > 128 {
                        return Err(Error::Limit);
                    }
                }
                let number = serde_json::from_slice(&self.raw[start..self.position])
                    .map_err(|_| Error::Json)?;
                Ok(Value::Number(number))
            }
            _ => {
                for (literal, value) in [
                    (b"true".as_slice(), Value::Bool(true)),
                    (b"false".as_slice(), Value::Bool(false)),
                    (b"null".as_slice(), Value::Null),
                ] {
                    if self.raw.get(self.position..self.position + literal.len()) == Some(literal) {
                        self.position += literal.len();
                        return Ok(value);
                    }
                }
                Err(Error::Json)
            }
        }
    }
}
