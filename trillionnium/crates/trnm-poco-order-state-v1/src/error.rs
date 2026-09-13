use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderStateErrorCodeV1 {
    InvalidContext,
    StoreUnavailable,
    SchemaMismatch,
    StoreTamper,
    StoreRollback,
    PermitMismatch,
    PreparedPlanMismatch,
    FinalityMismatch,
    StaleParent,
    Fork,
    DuplicateKey,
    ArithmeticOverflow,
    MembershipInvalid,
    CommitUncertain,
}

#[derive(Debug)]
pub struct OrderStateErrorV1 {
    code: OrderStateErrorCodeV1,
    detail: String,
}

impl OrderStateErrorV1 {
    pub const fn code(&self) -> OrderStateErrorCodeV1 {
        self.code
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for OrderStateErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for OrderStateErrorV1 {}

impl From<rusqlite::Error> for OrderStateErrorV1 {
    fn from(cause: rusqlite::Error) -> Self {
        error(OrderStateErrorCodeV1::StoreUnavailable, cause.to_string())
    }
}

pub type OrderStateResultV1<T> = Result<T, OrderStateErrorV1>;

pub(crate) fn error(code: OrderStateErrorCodeV1, detail: impl Into<String>) -> OrderStateErrorV1 {
    OrderStateErrorV1 {
        code,
        detail: detail.into(),
    }
}
