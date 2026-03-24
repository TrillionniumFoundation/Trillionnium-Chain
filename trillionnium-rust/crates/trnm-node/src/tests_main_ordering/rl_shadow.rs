use super::*;

#[test]
fn rl_shadow_advisor_only_suggests_and_does_not_mutate_baseline_order() {
    let baseline = vec![1, 2, 3, 4];
    let advisor = ShadowOnlyRlAdvisor { topk: 2 };
    let advice = advisor
        .advise(&RlAdviceContext {
            height: 7,
            ordered_ids: baseline.clone(),
        })
        .expect("advice");

    assert_eq!(baseline, vec![1, 2, 3, 4]);
    assert_eq!(advice.suggested_ids, vec![4, 3]);
    assert_eq!(advice.reason, "shadow_reverse_baseline");
}
