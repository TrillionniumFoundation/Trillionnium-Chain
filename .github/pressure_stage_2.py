from pathlib import Path
root=Path.cwd()
def rep(a,b):
 global s
 assert s.count(a)==1, (s.count(a),a[:80])
 s=s.replace(a,b)
p=root/'scripts/ci/test_run_from_zero_native.py';s=p.read_text()
rep("elapsed_wall_ns=10, deadline_ms=2000, returned_after_deadline=False)", "elapsed_wall_ns=10, deadline_ms=2000, returned_after_deadline=False,\n                effective_deadline_at_ns=2_000_000_010, outer_deadline_at_ns=None)")
rep("calls=[dict(call, status='refused', packet_index=i,", "calls=[dict(call, status='refused', packet_index=i, outer_deadline_at_ns=4_000_000_000,")
rep("requested_window_ns=4_000_000_000, traffic_and_join_wall_ns=4_000_000_001,", "requested_window_ns=4_000_000_000, traffic_and_join_wall_ns=4_000_000_001,\n            window_started_ns=0, window_ended_ns=4_000_000_000,\n            mutation_cpu_refusals=0, budget_pressure_observed=False,")
rep("return dict(schema='public-v3-sustained-local-from-zero-v1', simulated_control=True,", "return dict(schema='public-v3-sustained-local-from-zero-v2', simulated_control=True,\n        budget_pressure_observed=False, budget_depletion_demonstrated=False,")
rep("d['phases'][0]['honest_reads'][0].update(returned_after_deadline=True, elapsed_wall_ns=2_000_000_001)", "d['phases'][0]['honest_reads'][0].update(returned_after_deadline=True, elapsed_wall_ns=2_000_000_001, ended_ns=2_000_000_011)")
rep("\nif __name__ == '__main__':", '''
    def test_sustained_pressure_is_not_depletion_qualification(self):
        self.sustained_refusal(lambda d: d.update(budget_depletion_demonstrated=True), 'SUSTAINED_SCOPE')
        self.sustained_refusal(lambda d: d.update(budget_depletion_demonstrated=0), 'SUSTAINED_SCOPE')
        self.sustained_refusal(lambda d: d['phases'][0].update(budget_depletion_observed=True), 'SUSTAINED_DEPLETION_CLAIM')

    def test_sustained_refusal_summary_must_equal_real_metric(self):
        self.sustained_refusal(lambda d: d['phases'][0].update(mutation_cpu_refusals=1), 'SUSTAINED_REFUSALS')
        self.sustained_refusal(lambda d: d['phases'][0]['service']['metrics'].update(mutation_cpu_refusals=True), 'SUSTAINED_NUMBER')

    def test_sustained_pressure_aggregate_is_recomputed(self):
        self.sustained_refusal(lambda d: d.update(budget_pressure_observed=True), 'SUSTAINED_PRESSURE_CLAIM')
        self.sustained_refusal(lambda d: d['phases'][0].update(budget_pressure_observed=True), 'SUSTAINED_PRESSURE_CLAIM')

    def test_sustained_occupied_worker_refusal_is_retained_without_depletion(self):
        def edit(d):
            d['phases'][0]['service']['metrics']['mutation_cpu_refusals'] = 1
            d['phases'][0]['mutation_cpu_refusals'] = 1
            d['phases'][0]['budget_pressure_observed'] = True
            d['budget_pressure_observed'] = True
        result, _ = self.exercise(sustained_edit=edit)
        self.assertTrue(result['passed'])
        self.assertEqual(result['sustained_report']['phases'][0]['mutation_cpu_refusals'], 1)

    def test_sustained_attack_deadline_must_clip_to_common_window(self):
        def edit(d):
            row = d['phases'][0]['attacks'][0]['calls'][0]
            row.update(started_ns=3_999_999_000, ended_ns=3_999_999_010,
                       effective_deadline_at_ns=5_999_999_000)
        self.sustained_refusal(edit, 'SUSTAINED_CALL_TIME')

    def test_sustained_outer_deadline_cannot_be_removed_or_renewed(self):
        self.sustained_refusal(lambda d: d['phases'][0]['attacks'][0]['calls'][0].update(outer_deadline_at_ns=None), 'SUSTAINED_CALL_TIME')
        self.sustained_refusal(lambda d: d['phases'][0]['attacks'][0]['calls'][0].update(outer_deadline_at_ns=6_000_000_000), 'SUSTAINED_CALL_TIME')

    def test_sustained_real_clipped_deadline_and_late_refusal_are_retained(self):
        def edit(d):
            row = d['phases'][0]['attacks'][0]['calls'][0]
            row.update(started_ns=3_999_999_000, ended_ns=4_000_000_001,
                       elapsed_wall_ns=1001, effective_deadline_at_ns=4_000_000_000,
                       returned_after_deadline=True)
        result, _ = self.exercise(sustained_edit=edit)
        self.assertTrue(result['passed'])

    def test_sustained_shifted_window_cannot_inherit_old_call_times(self):
        self.sustained_refusal(lambda d: d['phases'][0].update(window_started_ns=1000, window_ended_ns=4_000_001_000), 'SUSTAINED_CALL_TIME')

if __name__ == '__main__':''')
p.write_text(s)
