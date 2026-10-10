from pathlib import Path
root=Path.cwd()
def rep(a,b):
 global s
 assert s.count(a)==1, (s.count(a),a[:80])
 s=s.replace(a,b)
p=root/'scripts/ci/run_from_zero_native.py';s=p.read_text()
rep("doc.get('schema') == 'public-v3-sustained-local-from-zero-v1'", "doc.get('schema') == 'public-v3-sustained-local-from-zero-v2'")
rep('''    def call(value):
        require''','''    def call(value, outer=None):
        require''')
rep('''        require(number(value.get('deadline_ms')) == 2000 and elapsed >= end - start
                and value['returned_after_deadline'] == (elapsed > 2_000_000_000),
                'SUSTAINED_CALL_TIME')''','''        expected_deadline = start + 2_000_000_000
        if outer is not None:
            expected_deadline = min(expected_deadline, outer)
        require(number(value.get('deadline_ms')) == 2000 and elapsed == end - start
                and number(value.get('effective_deadline_at_ns')) == expected_deadline
                and 'outer_deadline_at_ns' in value and value['outer_deadline_at_ns'] == outer
                and value['returned_after_deadline'] == (end > expected_deadline),
                'SUSTAINED_CALL_TIME')''')
rep("'production_activation', 'ordinary_hepta_entry', 'independent_accepted', 'physical_power_loss'))", "'production_activation', 'ordinary_hepta_entry', 'independent_accepted', 'physical_power_loss',\n           'budget_depletion_demonstrated'))")
rep('''        for key in ('preparation_wall_ns', 'diagnostic_verification_wall_ns', 'reader_cpu_ns',''','''        window_start = number(phase.get('window_started_ns'))
        window_end = number(phase.get('window_ended_ns'))
        require(window_end - window_start == phase['requested_window_ns'], 'SUSTAINED_WINDOW')
        for key in ('preparation_wall_ns', 'diagnostic_verification_wall_ns', 'reader_cpu_ns',''')
rep('''                call(row)
                require(row['status'] != 'ok',''','''                call(row, window_end)
                require(number(row.get('started_ns')) >= window_start, 'SUSTAINED_WINDOW')
                require(row['status'] != 'ok',''')
rep('''        total = number(metrics.get('mutation_cpu_charged_ns'))''','''        refusals = number(metrics.get('mutation_cpu_refusals'))
        require(number(phase.get('mutation_cpu_refusals')) == refusals, 'SUSTAINED_REFUSALS')
        pressure = any(v < 100_000_000 for v in credit) or refusals > 0
        require(type(phase.get('budget_pressure_observed')) is bool
                and phase['budget_pressure_observed'] == pressure, 'SUSTAINED_PRESSURE_CLAIM')
        require('budget_depletion_observed' not in phase, 'SUSTAINED_DEPLETION_CLAIM')
        total = number(metrics.get('mutation_cpu_charged_ns'))''')
rep("    meter(doc.get('meter_before_reopen'))", "    require(type(doc.get('budget_pressure_observed')) is bool\n            and doc['budget_pressure_observed'] == any(p['budget_pressure_observed'] for p in phases),\n            'SUSTAINED_PRESSURE_CLAIM')\n    meter(doc.get('meter_before_reopen'))")
p.write_text(s)
