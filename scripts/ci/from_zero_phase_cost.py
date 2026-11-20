"""Read original phase process clocks; no new business or resource qualification."""
from __future__ import annotations

BOUNDARIES = (
    'before_setup', 'before_service_spawn', 'after_workers_and_service_join',
    'after_state_and_observation_readback',
)


def require(value: bool, error: str) -> None:
    if not value:
        raise ValueError(error)


def number(value: object) -> int:
    require(type(value) is int and 0 <= value <= (1 << 64) - 1, 'PHASE_COST_NUMBER')
    return value


def read_phase_process_cost(raw: dict) -> dict:
    require(type(raw) is dict
            and raw.get('schema') == 'public-v3-confirmation-phase-process-cost-v1'
            and raw.get('cpu_clock') == 'CLOCK_PROCESS_CPUTIME_ID'
            and number(raw.get('process_id')) > 0, 'PHASE_COST_SCHEMA')
    require(raw.get('business_acceptance_authority') is False
            and raw.get('physical_network_bytes') is None
            and raw.get('energy_joules') is None, 'PHASE_COST_AUTHORITY')
    samples = raw.get('samples')
    require(type(samples) is list and len(samples) == 4
            and all(type(row) is dict for row in samples), 'PHASE_COST_SAMPLES')
    require([row.get('boundary') for row in samples] == list(BOUNDARIES),
            'PHASE_COST_BOUNDARIES')
    walls = [number(row.get('elapsed_ns')) for row in samples]
    require(walls[0] == 0 and walls == sorted(walls), 'PHASE_COST_WALL')
    cpus = [row.get('process_cpu_counter_ns') for row in samples]
    for cpu in cpus:
        if cpu is not None:
            number(cpu)

    def check_interval(row: dict, start: int, end: int) -> None:
        require(type(row) is dict and row.get('from') == BOUNDARIES[start]
                and row.get('to') == BOUNDARIES[end]
                and number(row.get('wall_ns')) == walls[end] - walls[start],
                'PHASE_COST_INTERVAL')
        before, after = cpus[start], cpus[end]
        expected = None if before is None or after is None or after < before else after - before
        state = ('clock_unavailable' if before is None or after is None
                 else 'counter_rewind' if after < before else 'observed')
        # bool is not a valid measured zero or one.
        require(row.get('process_cpu_ns') is None or type(row['process_cpu_ns']) is int,
                'PHASE_COST_CPU_TYPE')
        require(row.get('process_cpu_ns') == expected and row.get('cpu_state') == state,
                'PHASE_COST_CPU_DELTA')

    intervals = raw.get('intervals')
    require(type(intervals) is list and len(intervals) == 3, 'PHASE_COST_INTERVALS')
    for index, row in enumerate(intervals):
        check_interval(row, index, index + 1)
    check_interval(raw.get('whole_phase'), 0, 3)

    snapshots = []
    for key in ('retained_files_before', 'retained_files_after'):
        row = raw.get(key)
        require(type(row) is dict, 'PHASE_COST_DISK')
        if row.get('state') in ('observed', 'absent'):
            number(row.get('regular_files'))
            number(row.get('logical_file_bytes'))
            require(row.get('error') is None, 'PHASE_COST_DISK_ERROR')
            if row['state'] == 'absent':
                require(row['regular_files'] == row['logical_file_bytes'] == 0,
                        'PHASE_COST_ABSENT_DISK')
            snapshots.append(row['logical_file_bytes'])
        else:
            require(row.get('state') == 'unavailable'
                    and row.get('regular_files') is None
                    and row.get('logical_file_bytes') is None
                    and type(row.get('error')) is str and bool(row['error']),
                    'PHASE_COST_UNKNOWN_DISK')
            snapshots.append(None)
    growth = (None if None in snapshots else snapshots[1] - snapshots[0])
    return {
        'schema': 'public-v3-confirmation-phase-process-cost-read-v1',
        'process_id': raw['process_id'], 'samples': samples,
        'intervals': intervals, 'whole_phase': raw['whole_phase'],
        'retained_files_before': raw['retained_files_before'],
        'retained_files_after': raw['retained_files_after'],
        'retained_logical_file_growth_bytes': growth,
        'exact_original_window_cpu_ns': None,
        'physical_disk_io_bytes': None, 'physical_network_bytes': None,
        'energy_joules': None, 'business_acceptance_authority': False,
        'scope': 'all native test-process threads across setup, traffic, failures, retries, joined shutdown and readback; '
                 'nested actor/dispatch/Host CPU must not be added; no allocation to a successful transaction or exact 4s window; '
                 'excludes child processes, cost-record serialization and final report write; '
                 'retained regular-file lengths are signed before/after growth, not physical disk I/O or peak storage; '
                 'missing and reversed clocks remain unknown',
    }
