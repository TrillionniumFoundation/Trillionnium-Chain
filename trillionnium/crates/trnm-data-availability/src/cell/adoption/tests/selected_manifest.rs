use super::*;

#[test]
fn selected_manifest_comes_from_the_catalog_under_the_original_writer_fence() {
    let mut f = setup();
    let first = bootstrap(&mut f);
    observe_next(&mut f);
    let mut other = CellAdoptionOwnerV1::open(&f.path, &f.policy, &first).unwrap();
    let current = f.anchor.commitment();
    let candidate = f.candidate.commitment();
    let encoded = f.anchor.encode();
    let observed = f
        .owner
        .with_selected_manifest_guard(&first, current, &execution(), |selected| {
            assert_eq!(selected.encode(), encoded);
            assert!(other
                .decide(
                    [2; 32],
                    &first,
                    CellAdoptionActionV1::Adopt,
                    candidate,
                    [72; 64]
                )
                .is_err());
            assert_eq!(selected.commitment(), current);
            Ok(selected.commitment())
        })
        .unwrap();
    assert_eq!(observed, current);
    assert_eq!(f.owner.snapshot().unwrap(), first);
    let next = other
        .decide(
            [2; 32],
            &first,
            CellAdoptionActionV1::Adopt,
            candidate,
            [72; 64],
        )
        .unwrap();
    let called = Cell::new(false);
    assert!(f
        .owner
        .with_selected_manifest_guard(&first, current, &execution(), |_| {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
    f.owner
        .with_selected_manifest_guard(next.after(), candidate, &execution(), |selected| {
            assert_eq!(selected, &f.candidate);
            Ok(())
        })
        .unwrap();
}

#[test]
fn wrong_selection_or_execution_never_exposes_manifest_and_errors_release_fence() {
    let mut f = setup();
    let empty = f.owner.snapshot().unwrap();
    let called = Cell::new(false);
    assert!(f
        .owner
        .with_selected_manifest_guard(&empty, f.anchor.commitment(), &execution(), |_| {
            called.set(true);
            Ok(())
        })
        .is_err());
    let first = bootstrap(&mut f);
    observe_next(&mut f);
    let current = f.anchor.commitment();
    let candidate = f.candidate.commitment();
    let mut changed = execution();
    changed.root_authority = [90; 32];
    for (commitment, environment) in [(candidate, execution()), (current, changed)] {
        assert!(f
            .owner
            .with_selected_manifest_guard(&first, commitment, &environment, |_| {
                called.set(true);
                Ok(())
            })
            .is_err());
    }
    assert!(!called.get());
    assert!(f
        .owner
        .with_selected_manifest_guard::<()>(&first, current, &execution(), |selected| {
            assert_eq!(selected.commitment(), current);
            Err(CellErrorV1::Invalid("inspection refused"))
        })
        .is_err());
    assert_eq!(f.owner.snapshot().unwrap(), first);
    let mut other = CellAdoptionOwnerV1::open(&f.path, &f.policy, &first).unwrap();
    assert!(other
        .decide(
            [2; 32],
            &first,
            CellAdoptionActionV1::Adopt,
            candidate,
            [72; 64]
        )
        .is_ok());
}
