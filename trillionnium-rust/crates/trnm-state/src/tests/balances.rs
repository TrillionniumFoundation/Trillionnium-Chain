use super::*;

#[test]
fn balance_debit_credit_works() {
    let mut st = StateStore::new();
    st.set_balance("challenger", 15);
    assert_eq!(st.balance_of("challenger"), 15);

    st.debit_balance("challenger", 10).unwrap();
    assert_eq!(st.balance_of("challenger"), 5);

    let err = st.debit_balance("challenger", 6).unwrap_err();
    assert!(err.contains("insufficient balance"));

    st.credit_balance("challenger", 7).unwrap();
    assert_eq!(st.balance_of("challenger"), 12);
}

#[test]
fn balance_credit_overflow_rejected() {
    let mut st = StateStore::new();
    st.set_balance("treasury", u128::MAX - 1);

    let err = st.credit_balance("treasury", 2).unwrap_err();
    assert!(err.contains("balance overflow on credit"));
}
