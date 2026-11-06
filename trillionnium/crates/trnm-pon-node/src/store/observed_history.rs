//! Test-only rejected candidate for statement-local parent material reuse.
//!
//! The recursive query reads at most 65 retained rows for a 64-header batch.
//! A row supplies its child's parent projection and then its own projection;
//! there is no second blocks-table lookup for either. Only two bounded rows
//! live in Rust. No record, ancestry, clock verdict or successful validation
//! survives this statement, and every original per-link check still runs.
//! The separate boundary arm never reads its parent's packet. That safeguard
//! costs VM work: the guarded candidate has not demonstrated an improvement.
//! The original JOIN remains the production reader; these controls are not a
//! performance qualification and cannot enable this candidate in a build.
use super::{
    bytes32, ensure, params, Error, FixedSqlBlob, Hash, HeaderProjection, Node, Result,
    StoredHeaderLink,
};
use rusqlite::types::{FromSql, FromSqlError, ValueRef};

pub(super) const HEADER_MATERIAL_SQL: &str =
    "WITH RECURSIVE ancestry(id,parent,height,chainwork,state_root,prefix,trace,packet_length,ordinal) AS (
         SELECT id,parent,height,chainwork,state_root,substr(packet,1,?4),
             substr(packet,-32),length(packet),0
         FROM blocks WHERE id=?1 AND id!=?2
         UNION ALL
         SELECT b.id,b.parent,b.height,b.chainwork,b.state_root,substr(b.packet,1,?4),
             substr(b.packet,-32),length(b.packet),a.ordinal+1
         FROM ancestry a JOIN blocks b ON b.id=a.parent
         WHERE a.id!=?2 AND a.parent!=?2 AND a.ordinal<?3-1
         UNION ALL
         SELECT b.id,b.parent,b.height,b.chainwork,b.state_root,NULL,NULL,NULL,a.ordinal+1
         FROM ancestry a JOIN blocks b ON b.id=a.parent
         WHERE a.id!=?2 AND (a.ordinal=?3-1 OR a.parent=?2) LIMIT ?3+1
     )
     SELECT parent,height,chainwork,state_root,prefix,trace,packet_length,id,ordinal
     FROM ancestry ORDER BY ordinal";

// Keep SQL storage classes and defer conversion to the ORIGINAL projection
// order. In particular, a malformed parent's own packet is not interpreted
// merely because its height/work/root are needed for its child's binding.
// Text is invalid for every requested type, so its bytes need not be copied.
enum Cell {
    Null,
    Integer(i64),
    Real(f64),
    Text,
    Blob(Vec<u8>),
}
impl Cell {
    fn capture(value: ValueRef<'_>, maximum: usize) -> Self {
        match value {
            ValueRef::Null => Self::Null,
            ValueRef::Integer(value) => Self::Integer(value),
            ValueRef::Real(value) => Self::Real(value),
            ValueRef::Text(_) => Self::Text,
            ValueRef::Blob(bytes) => Self::Blob(bytes[..bytes.len().min(maximum)].to_vec()),
        }
    }

    fn value(&self) -> ValueRef<'_> {
        match self {
            Self::Null => ValueRef::Null,
            Self::Integer(value) => ValueRef::Integer(*value),
            Self::Real(value) => ValueRef::Real(*value),
            Self::Text => ValueRef::Text(&[]),
            Self::Blob(bytes) => ValueRef::Blob(bytes),
        }
    }

    fn get<T: FromSql>(&self, column: usize, name: &str) -> rusqlite::Result<T> {
        let value = self.value();
        // Match rusqlite::Row::get, including the original JOIN's column
        // index/name. Moving a parent row must not change a typed SQL error.
        T::column_result(value).map_err(|error| match error {
            FromSqlError::InvalidType => {
                rusqlite::Error::InvalidColumnType(column, name.into(), value.data_type())
            }
            FromSqlError::OutOfRange(value) => {
                rusqlite::Error::IntegralValueOutOfRange(column, value)
            }
            FromSqlError::Utf8Error(error) => rusqlite::Error::Utf8Error(column, error),
            FromSqlError::Other(error) => {
                rusqlite::Error::FromSqlConversionFailure(column, value.data_type(), error)
            }
            error @ FromSqlError::InvalidBlobSize { .. } => {
                rusqlite::Error::FromSqlConversionFailure(
                    column,
                    value.data_type(),
                    Box::new(error),
                )
            }
            error => rusqlite::Error::FromSqlConversionFailure(
                column,
                value.data_type(),
                Box::new(error),
            ),
        })
    }
}

struct Material([Cell; 9]);
impl Material {
    fn read(row: &rusqlite::Row<'_>, header_bytes: usize, header: bool) -> rusqlite::Result<Self> {
        Ok(Self([
            Cell::capture(row.get_ref(0)?, 33),
            Cell::capture(row.get_ref(1)?, 0),
            Cell::capture(row.get_ref(2)?, 65),
            Cell::capture(row.get_ref(3)?, 33),
            if header {
                Cell::capture(row.get_ref(4)?, header_bytes)
            } else {
                Cell::Null
            },
            if header {
                Cell::capture(row.get_ref(5)?, 32)
            } else {
                Cell::Null
            },
            if header {
                Cell::capture(row.get_ref(6)?, 0)
            } else {
                Cell::Null
            },
            Cell::capture(row.get_ref(7)?, 33),
            Cell::capture(row.get_ref(8)?, 0),
        ]))
    }

    fn current(&self) -> rusqlite::Result<HeaderProjection> {
        Ok(HeaderProjection {
            parent: self.0[0]
                .get::<Option<FixedSqlBlob<32>>>(0, "parent")?
                .map(|value| value.0),
            height: self.0[1].get(1, "height")?,
            work: self.0[2].get::<FixedSqlBlob<64>>(2, "chainwork")?.0,
            root: self.0[3].get::<FixedSqlBlob<32>>(3, "state_root")?.0,
            prefix: self.0[4].get(4, "substr(b.packet,1,?4)")?,
            trace: self.0[5].get(5, "substr(b.packet,-32)")?,
            length: self.0[6].get(6, "length(b.packet)")?,
            parent_height: None,
            parent_work: None,
            parent_parent: None,
            parent_root: None,
        })
    }

    fn parent(&self, projection: &mut HeaderProjection) -> rusqlite::Result<()> {
        projection.parent_height = self.0[1].get(7, "height")?;
        projection.parent_work = self.0[2]
            .get::<Option<FixedSqlBlob<64>>>(8, "chainwork")?
            .map(|value| value.0);
        projection.parent_parent = self.0[0]
            .get::<Option<FixedSqlBlob<32>>>(9, "parent")?
            .map(|value| value.0);
        projection.parent_root = self.0[3]
            .get::<Option<FixedSqlBlob<32>>>(10, "state_root")?
            .map(|value| value.0);
        Ok(())
    }
}

pub(super) fn visit(
    node: &Node,
    start: Hash,
    maximum: u64,
    visit: &mut impl FnMut(Hash, StoredHeaderLink) -> Result<()>,
) -> Result<(Hash, u64)> {
    let genesis = node.settings.genesis();
    let header_bytes = node.settings.packet_header_length();
    let mut statement = node.db.prepare_cached(HEADER_MATERIAL_SQL)?;
    node.count_header_query();
    let mut rows = statement.query(params![
        start.as_slice(),
        genesis.as_slice(),
        maximum,
        header_bytes,
    ])?;
    let mut current = start;
    let mut checked = 0_u64;
    let mut material = rows
        .next()?
        .map(|row| Material::read(row, header_bytes, true))
        .transpose()?;
    while checked < maximum && current != genesis {
        let Some(row) = material.take() else {
            break;
        };
        let id = bytes32(row.0[7].get(11, "id")?)?;
        ensure(
            row.0[8].get::<u64>(12, "ordinal")? == checked && id == current,
            "ANCESTRY_HEIGHT",
        )
        .map_err(Error::local_integrity)?;
        // Preserve current fields' typed conversion before the parent's fields,
        // then the original header/profile/parent/root checks before callback.
        let mut projection = row.current()?;
        material = rows
            .next()?
            .map(|row| {
                // The boundary parent's header lies outside this batch. Keep
                // the original header/trace bytes delivered to Rust: only its
                // bounded record shape is needed, including at genesis.
                let header =
                    checked + 1 < maximum && row.get_ref(7)? != ValueRef::Blob(genesis.as_slice());
                Material::read(row, header_bytes, header)
            })
            .transpose()?;
        if let Some(parent) = &material {
            parent.parent(&mut projection)?;
        }
        let link = node.check_header_projection(id, projection)?;
        current = link.header.parent;
        visit(id, link)?;
        checked = checked.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
    }
    let complete = ensure(checked == maximum || current == genesis, "UNKNOWN_PARENT");
    if checked == 0 {
        complete?;
    } else {
        complete.map_err(Error::local_integrity)?;
    }
    Ok((current, checked))
}

#[cfg(test)]
mod tests;
