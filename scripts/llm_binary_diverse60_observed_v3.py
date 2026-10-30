"""Explicit fixed diverse60 scalar training under the unchanged owned supervisor.

This namespace does not execute the legacy model-plan recipe. It preserves that
material plan and its parent contract, and separately binds thirty mean-gradient
updates, sixty distinct public source rows and three hundred scalar exposures.
All receipts are unsigned execution evidence, never model/product qualification.
"""
from collections import Counter
import gc
import hashlib
import json
import math
import os
from pathlib import Path
import time

import llm_initial_trainable_setup_v2 as setup
import llm_runtime_parent_step as step
import llm_runtime_pilot as runtime

SCHEMA = 'llm-runtime-parent-step-binary-diverse60-observed-input-v3'
PROFILE = 'canonical-positive-zero-binary-diverse60-observed-v3'
PLAN = 'llm-runtime-binary-diverse60-observation-plan-v3'
DATA_SCHEMA = 'llm-binary-diverse60-training-data-v3'
DATA_RELATIVE_PATH = 'config/pon/binary-diverse60-training-v3.json'
DATA_SHA256 = 'd457f4b01cc6aaa445403e81b1fa9511e24f23e4254a6ef9ff9ec29abab693cf'
OBSERVER = 'linux-owned-exit-worker-pidfd-v4'
OBSERVER_SOURCE_SHA256 = 'aae68f92393e5e88c5aaa02095b5990200c121834bec05d8b3a11cd3f09ffc50'
UPDATES, SOURCE_ROWS, MICROSTEPS, INPUT_TOKENS = 30, 60, 300, 15600
TRACE = 'binary-diverse60-training-trace-v3.jsonl'
MAX_TRACE = 1024 * 1024
RECIPE = dict(schema='binary-diverse60-scalar-mean-gradient-recipe-v3', optimizer='AdamW',
    learning_rate='0.002', weight_decay='0', optimizer_steps=UPDATES,
    source_rows=SOURCE_ROWS, rows_per_optimizer_step=10, row_exposures=MICROSTEPS,
    physical_microbatch=1, threads=4, profiler='one-CPU-record-shapes-with-flops-context-per-update',
    gradient_accumulation='sum-ten-row-binary-CE-gradients-divided-by-ten',
    initialization_seed=7, rank=4, alpha=8, dropout='0',
    answer_order=['yes', 'no'], answer_positions_per_microstep=1,
    eos_positions_per_microstep=0,
    objective='last-prompt-position-two-original-answer-token-cross-entropy',
    hypothesis='fixed-public-diverse60-six-ten-row-groups-five-passes-no-future-outcome-selection')


def is_diverse(value):
    return type(value) is dict and value.get('schema') == SCHEMA


def checked_role(role, code):
    step.closed(role, 'path sha256')
    runtime.require(type(role['path']) is str and 0 < len(role['path']) <= 4096 and
                    Path(role['path']).is_absolute(), code + '_PATH')
    step.digest(role['sha256'])
    raw = step.parent.read_regular(role['path'], step.MAX_INPUT)
    runtime.require(hashlib.sha256(raw).hexdigest() == role['sha256'], code + '_PIN')
    return raw


def load_training_data(role):
    """Only the separately offered frozen public payload is admitted; no default."""
    raw = checked_role(role, 'DIVERSE_V3_DATA')
    runtime.require(role['sha256'] == DATA_SHA256, 'DIVERSE_V3_FIXED_DATA_IDENTITY')
    data = json.loads(raw, object_pairs_hook=runtime.unique)
    step.closed(data, 'schema origin generation_rule generation_exclusion_identity training_rows '
        'ordered_training_row_sha256 training_token_ids batches_per_pass update_schedule '
        'expected_input_tokens tokenizer flags')
    runtime.require(data['schema'] == DATA_SCHEMA and runtime.canonical(data) + b'\n' == raw,
                    'DIVERSE_V3_CANONICAL_DATA')
    step.closed(data['origin'], 'development_plan_sha256 development_data_sha256 scope')
    runtime.require(data['origin'] == dict(
        development_plan_sha256='920553660721745af24963bb4d360f76e0d0bc0f6bb1a65c1c03e1cb369605b7',
        development_data_sha256='14ef3e7d54f36650910d0fec8db18a66c0539287fa29879f74a6eeb8d452b472',
        scope='fixed-public-training-inputs-not-future-evaluation'), 'DIVERSE_V3_DATA_ORIGIN')
    step.closed(data['flags'], 'model_qualification future_window complete_current_exposure_exclusion_claim')
    runtime.require(all(item is False for item in data['flags'].values()), 'DIVERSE_V3_DATA_AUTHORITY')
    step.digest(data['generation_exclusion_identity'])
    rows, tokens = data['training_rows'], data['training_token_ids']
    runtime.require(type(rows) is list and type(tokens) is list and
                    len(rows) == len(tokens) == SOURCE_ROWS, 'DIVERSE_V3_SOURCE_ROWS')
    for row, ids in zip(rows, tokens):
        step.closed(row, 'id partition prompt expected_output source_group prompt_sha256 target_output_sha256')
        for name in ('id', 'source_group', 'prompt_sha256', 'target_output_sha256'):
            step.digest(row[name])
        runtime.require(row['partition'] == 'training' and type(row['prompt']) is str and
            0 < len(row['prompt']) <= 1024 and row['expected_output'] in ('yes', 'no') and
            hashlib.sha256(row['prompt'].encode()).hexdigest() == row['prompt_sha256'] and
            hashlib.sha256(row['expected_output'].encode()).hexdigest() == row['target_output_sha256'],
            'DIVERSE_V3_ROW_BYTES')
        runtime.require(type(ids) is list and 0 < len(ids) <= 128 and
            all(type(token) is int and 0 <= token < 49152 for token in ids), 'DIVERSE_V3_TOKEN_IDS')
    runtime.require([row['id'] for row in rows] == sorted(set(row['id'] for row in rows)) and
        len(set(row['prompt_sha256'] for row in rows)) == SOURCE_ROWS and
        data['ordered_training_row_sha256'] == [runtime.identity(row) for row in rows],
        'DIVERSE_V3_ORDERED_DISTINCT_ROWS')
    labels = Counter((row['source_group'], row['expected_output']) for row in rows)
    runtime.require(len(labels) == 4 and set(labels.values()) == {15}, 'DIVERSE_V3_BALANCED_SOURCE_ROWS')
    batches, schedule = data['batches_per_pass'], data['update_schedule']
    runtime.require(type(batches) is list and len(batches) == 6 and
        all(type(batch) is list and len(batch) == 10 and
            all(type(index) is int and 0 <= index < SOURCE_ROWS for index in batch) for batch in batches) and
        sorted(index for batch in batches for index in batch) == list(range(SOURCE_ROWS)) and
        type(schedule) is list and runtime.canonical(schedule) == runtime.canonical(batches * 5),
        'DIVERSE_V3_EXACT_SCHEDULE')
    runtime.require(type(data['expected_input_tokens']) is int and
        data['expected_input_tokens'] == INPUT_TOKENS ==
        sum(len(tokens[index]) for batch in schedule for index in batch), 'DIVERSE_V3_TOKEN_TOTAL')
    step.closed(data['tokenizer'], 'tokenizer_sha256 configuration_sha256 chat_template_sha256 answer_token_ids')
    for name in ('tokenizer_sha256', 'configuration_sha256', 'chat_template_sha256'):
        step.digest(data['tokenizer'][name])
    runtime.require(data['tokenizer']['answer_token_ids'] == [10407, 4607], 'DIVERSE_V3_ANSWER_TOKENS')
    return data


def plan_record(value):
    """Freeze actual training separately from the unchanged ten-step material plan."""
    from llm_runtime_parent_step_v2 import sources
    base = runtime.validate_plan(step.read_object(value['files']['plan'], 1024 * 1024))
    data_role = value['initial_setup']['training_data']
    data = load_training_data(data_role)
    runtime.require(type(base['training_steps']) is int and base['training_steps'] == 10 and
        type(base['threads']) is int and base['threads'] == 4 and base['seed'] == 7 and
        runtime.canonical(base['tasks']) == runtime.canonical(runtime.tasks()) and
        runtime.plan_exit_profile(base) == 'strict-v1' and
        base['training_budget'] == dict(wall_seconds=1800, rss_bytes=16 * 1024**3) and
        base['inference_budget'] == dict(wall_seconds=600, rss_bytes=8 * 1024**3),
        'DIVERSE_V3_ORIGINAL_MATERIAL_PLAN_AND_BUDGETS')
    observer = runtime.exit_observation_profile(OBSERVER)
    runtime.require(observer['observer_source_sha256'] == OBSERVER_SOURCE_SHA256 and
                    observer['maximum_drain_ns'] == 100000000, 'DIVERSE_V3_CURRENT_OBSERVER')
    return dict(schema=PLAN, profile=PROFILE,
        scope='separate-fixed-public-training-work-original-material-no-qualification',
        source=sources(PROFILE), recipe=RECIPE,
        base_model_plan=dict(identity=runtime.identity(base),
            sha256=runtime.file_sha(value['files']['plan']), source=base['runtime_source'],
            unchanged=True, legacy_candidate_recipe_is_used=False),
        parent=value['parent'], parent_material=value['initial_setup']['parent_material'],
        setup_recipe=setup.RECIPE, training_data=dict(data_role), training_data_identity=runtime.identity(data),
        ordered_training_row_sha256=data['ordered_training_row_sha256'],
        update_schedule=data['update_schedule'], training_token_ids_sha256=runtime.identity(data['training_token_ids']),
        distinct_source_rows=SOURCE_ROWS, expected_source_ledger_records=120,
        actual_row_exposures=MICROSTEPS, optimizer_steps=UPDATES, physical_microbatch=1,
        expected_input_tokens=INPUT_TOKENS, observer=observer,
        training_budget=base['training_budget'], inference_budget=base['inference_budget'],
        actual_resource_costs_required=True, same_work_as_legacy_ten_single_rows=False,
        model_plan_unchanged=True, target_contract_unchanged=True, flags=step.FALSES)


def checked_plan(value):
    raw = checked_role(value['initial_setup']['diverse_plan'], 'DIVERSE_V3_PLAN')
    record = json.loads(raw, object_pairs_hook=runtime.unique)
    runtime.require(runtime.canonical(record) == runtime.canonical(plan_record(value)),
                    'DIVERSE_V3_EXACT_EXECUTION_PLAN')
    runtime.validate_exit_observation_profile(record['observer'])
    return record


def context(value):
    record = checked_plan(value)
    return dict(profile=PROFILE, plan_sha256=value['initial_setup']['diverse_plan']['sha256'],
        recipe=runtime.identity(RECIPE), observer=runtime.identity(record['observer']),
        model_plan=record['base_model_plan']['identity'], training_data=record['training_data']['sha256'],
        training_rows=runtime.identity(record['ordered_training_row_sha256']),
        training_schedule=runtime.identity(record['update_schedule']), distinct_source_rows=SOURCE_ROWS,
        row_exposures=MICROSTEPS, optimizer_steps=UPDATES, physical_microbatch=1, expected_input_tokens=INPUT_TOKENS)


def preflight(value):
    from llm_runtime_parent_step_v2 import SCHEMA as old_schema, PROFILE as old_profile, sources, preflight as original
    step.closed(value, 'schema scope attempt_id operation experiment source files parent candidate output flags initial_setup')
    runtime.require(is_diverse(value) and value['scope'] == step.SCOPE and value['operation'] == 'train' and
        value['source'] == sources(PROFILE) and value['flags'] == step.FALSES and
        all(item is False for item in value['flags'].values()), 'DIVERSE_V3_SCOPE_SOURCE')
    request = value['initial_setup']
    step.closed(request, 'profile recipe parent_material diverse_plan training_data')
    runtime.require(request['profile'] == PROFILE and request['recipe'] == setup.RECIPE,
                    'DIVERSE_V3_INITIAL_SETUP')
    # Validation-only projection, never persisted/executed/emitted as old work.
    base = dict(value, schema=old_schema, source=sources(old_profile),
        initial_setup={key: item for key, item in request.items() if key not in ('diverse_plan', 'training_data')})
    base['initial_setup']['profile'] = old_profile
    result = original(base)
    runtime.require(runtime.canonical(result[0]) == runtime.canonical(runtime.experiment_plan(result[1])),
                    'DIVERSE_V3_UNCHANGED_MATERIAL_PLAN')
    record = checked_plan(value)
    runtime.require(record['base_model_plan']['identity'] == value['experiment'] and
        record['training_budget'] == result[0]['training_budget'] and
        record['inference_budget'] == result[0]['inference_budget'], 'DIVERSE_V3_MODEL_AND_BUDGET_BINDING')
    return result


def verify_supervisor(value, result):
    """Recheck original completed ownership and full actual resource policy."""
    record = checked_plan(value)
    required = ('outcome exit_code stop_reason budget exit_observation_profile terminal_reconciliation_profile '
        'child_spawned owned_child_exit_observed waited_child_reaped owned_child_reap_resolved '
        'owned_child_echild_observed waited_child_observation_error cleanup_method sample_interval_ms '
        'observed_wall_ns child_cpu_ns observer_cpu_ns sampled_peak_rss_bytes waited_child_peak_rss_bytes')
    runtime.require(type(result) is dict and set(required.split()) <= set(result),
                    'DIVERSE_V3_REQUIRED_OWNER_FIELDS')
    runtime.require(runtime.canonical(result['exit_observation_profile']) == runtime.canonical(record['observer']) and
        result.get('terminal_reconciliation_profile') == 'explicit-' + OBSERVER and
        runtime.canonical(result['budget']) == runtime.canonical(record['training_budget']),
        'DIVERSE_V3_SUPERVISOR_BINDING')
    runtime.require(result.get('outcome') == 'success' and type(result.get('exit_code')) is int and
        result['exit_code'] == 0 and result.get('stop_reason') is None and
        all(result.get(key) is True for key in ('child_spawned', 'owned_child_exit_observed',
            'waited_child_reaped', 'owned_child_reap_resolved')) and
        result.get('owned_child_echild_observed') is False and
        result.get('waited_child_observation_error') is None and
        result.get('cleanup_method') == 'wait4' and type(result['sample_interval_ms']) is int and
        result['sample_interval_ms'] == 50,
        'DIVERSE_V3_COMPLETED_ORIGINAL_OWNER')
    for name in ('observed_wall_ns', 'child_cpu_ns', 'observer_cpu_ns',
                 'sampled_peak_rss_bytes', 'waited_child_peak_rss_bytes'):
        runtime.require(type(result.get(name)) is int and result[name] >= 0, 'DIVERSE_V3_ACTUAL_COST')
    runtime.require(result['observed_wall_ns'] <= record['training_budget']['wall_seconds'] * 1000000000 and
        result['sampled_peak_rss_bytes'] <= record['training_budget']['rss_bytes'] and
        result['waited_child_peak_rss_bytes'] <= record['training_budget']['rss_bytes'],
        'DIVERSE_V3_ORIGINAL_RESOURCE_BUDGET')
    if 'exit_cleanup_observation' in result:
        cleanup = result['exit_cleanup_observation']
        runtime.require(type(cleanup) is dict and cleanup.get('outcome') == 'terminal-wait4' and
            'error' not in cleanup and cleanup.get('retirement_closed_by') == 'exact-owned-child-terminal-wait4' and
            type(cleanup.get('completed_ns')) is int and type(cleanup.get('missing_sample_ns')) is int and
            0 <= cleanup['completed_ns'] - cleanup['missing_sample_ns'] <= 100000000,
            'DIVERSE_V3_ORIGINAL_TERMINAL_DEADLINE')


def objective_record(value, trace, tokens):
    return dict(profile=PROFILE, execution=context(value), recipe=runtime.identity(RECIPE),
        source_sha256=runtime.file_sha(__file__), optimizer_steps=UPDATES, microsteps=MICROSTEPS,
        distinct_source_rows=SOURCE_ROWS, row_exposures=MICROSTEPS,
        answer_tokens=MICROSTEPS, eos_tokens=0, actual_input_tokens=tokens,
        trace=trace, same_work_as_legacy_ten_single_rows=False,
        loss_scope='ten-row-mean-two-original-answer-token-CE-gradient-per-optimizer-step')


def trace_record(stream, value):
    raw = runtime.canonical(value) + b'\n'
    runtime.require(stream.tell() + len(raw) <= MAX_TRACE, 'DIVERSE_V3_TRACE_BOUND')
    stream.write(raw)


def finalize_live_child(value, directory, observer, report, begin, pending):
    """Attempt release and persist both records without hiding a primary error."""
    import ctypes
    primary = pending
    started = time.monotonic_ns()
    release = dict(schema='llm-parent-live-release-binary-diverse60-observed-v3',
        input=runtime.identity(value), source=value['source'],
        scope='post-training-resource-release-not-terminal-qualification',
        original_terminal_observer_required=True, outcome='failed')

    def remember(error, phase):
        nonlocal primary
        if primary is None:
            primary = error
            report.update(outcome='failed', error_type=type(error).__name__, error=str(error)[:128])
        else:
            primary.add_note('binary observed finalization ' + phase + ': ' + type(error).__name__)

    try:
        release['collected_cycles'] = observer.stage('live-model-cycle-release', gc.collect)
        libc = ctypes.CDLL(None, use_errno=True)
        trim = libc.malloc_trim
        trim.argtypes = [ctypes.c_size_t]
        trim.restype = ctypes.c_int
        release['malloc_trim_return'] = observer.stage('live-model-allocator-trim', lambda: trim(0))
        release['outcome'] = 'attempt-completed'
    except BaseException as error:
        release.update(error_type=type(error).__name__, error=str(error)[:128])
        remember(error, 'release')
    release['observed_wall_ns'] = time.monotonic_ns() - started
    try:
        runtime.save(Path(directory) / 'live-release-binary-diverse60-observed-v3.json', release)
    except BaseException as error:
        remember(error, 'release-receipt')
    report['observed_wall_ns'] = time.monotonic_ns() - begin
    try:
        runtime.save(Path(directory) / 'actual-receipt.json', report)
    except BaseException as error:
        remember(error, 'actual-receipt')
    if pending is None and primary is not None:
        raise primary



def train(value, model, tokenizer, plan, torch, device, directory):
    """Run thirty actual scalar mean-gradient updates and record all300 exposures."""
    frozen = checked_plan(value)
    runtime.require(runtime.identity(plan) == frozen['base_model_plan']['identity'], 'DIVERSE_V3_TRAINING_PLAN')
    data = load_training_data(frozen['training_data'])
    selected = data['training_rows']
    encoded_answers = [tokenizer.encode(answer, add_special_tokens=False) for answer in RECIPE['answer_order']]
    runtime.require(all(len(answer) == 1 for answer in encoded_answers), 'DIVERSE_V3_SINGLE_TOKEN_ANSWERS')
    answers = [answer[0] for answer in encoded_answers]
    runtime.require(len(set(answers)) == 2 and answers == [10407, 4607] and
        not set(answers).intersection(tokenizer.all_special_ids), 'DIVERSE_V3_ORIGINAL_ANSWER_TOKENS')
    prompts = [runtime.prompt_tokens(tokenizer, row, plan['input_tokens_max']) for row in selected]
    runtime.require(all(0 < len(prompt) <= plan['input_tokens_max'] for prompt in prompts),
                    'DIVERSE_V3_PROMPT_BOUND')
    runtime.require(prompts == data['training_token_ids'], 'DIVERSE_V3_ACTUAL_TOKEN_TRANSLATION')
    parameters = [parameter for parameter in model.parameters() if parameter.requires_grad]
    runtime.require(sum(parameter.numel() for parameter in parameters) == 230400,
                    'DIVERSE_V3_ORIGINAL_TRAINABLE_FACTORS')
    optimizer = torch.optim.AdamW(parameters, lr=float(RECIPE['learning_rate']), weight_decay=0)
    losses, tokens, supervised = [], 0, 0
    model.train()
    trace_path = Path(directory) / TRACE
    profiled_flops = 0
    with trace_path.open('xb') as trace:
        trace_record(trace, dict(event='start', profile=PROFILE, input=runtime.identity(value),
            recipe=runtime.identity(RECIPE), plan_sha256=value['initial_setup']['diverse_plan']['sha256'],
            source=runtime.file_sha(__file__), source_rows=frozen['ordered_training_row_sha256'],
            training_data_sha256=frozen['training_data']['sha256'],
            update_schedule_sha256=runtime.identity(frozen['update_schedule']),
            pid=os.getpid(), start_monotonic_ns=time.monotonic_ns()))
        for update in range(UPDATES):
            # Bound retained profiler observations to one actual ten-row update.
            # Every microstep remains profiled; aggregate only measured operator FLOPs.
            with torch.profiler.profile(
                    activities=[torch.profiler.ProfilerActivity.CPU],
                    record_shapes=True, with_flops=True) as profiler:
                optimizer.zero_grad(set_to_none=True)
                current_losses = []
                for ordinal, source_row_index in enumerate(frozen['update_schedule'][update]):
                    row, prompt = selected[source_row_index], prompts[source_row_index]
                    target = RECIPE['answer_order'].index(row['expected_output'])
                    ids = torch.tensor([prompt], dtype=torch.int64, device=device)
                    output = model(input_ids=ids, attention_mask=torch.ones_like(ids, dtype=torch.bool), use_cache=False)
                    scores = output.logits[:, -1, answers]
                    runtime.require(tuple(scores.shape) == (1, 2) and bool(torch.isfinite(scores).all()),
                                    'DIVERSE_V3_FINITE_ANSWER_SCORES')
                    loss = torch.nn.functional.cross_entropy(scores, torch.tensor([target], dtype=torch.int64, device=device))
                    runtime.require(torch.isfinite(loss).item(), 'DIVERSE_V3_FINITE_LOSS')
                    (loss / 10).backward()
                    observed_loss = loss.detach().item()
                    current_losses.append(observed_loss)
                    tokens += ids.numel()
                    supervised += 1
                    trace_record(trace, dict(event='microstep', optimizer_step=update, row_ordinal=ordinal,
                        source_row_index=source_row_index,
                        source_row_sha256=runtime.identity(row), input_ids=ids.detach().cpu().tolist()[0],
                        answer_token_ids=answers, target_index=target,
                        answer_logits=[format(number, '.17g') for number in scores.detach().cpu().tolist()[0]],
                        loss=format(observed_loss, '.17g'), backward_completed=True,
                        completed_monotonic_ns=time.monotonic_ns(), completed_process_cpu_ns=time.process_time_ns()))
                gradient_square = 0.0
                for parameter in parameters:
                    if parameter.grad is not None:
                        runtime.require(bool(torch.isfinite(parameter.grad).all()), 'DIVERSE_V3_FINITE_GRADIENT')
                        gradient_square += parameter.grad.detach().double().square().sum().item()
                runtime.require(math.isfinite(gradient_square) and gradient_square > 0, 'DIVERSE_V3_ACTUAL_GRADIENT')
                optimizer.step()
                runtime.require(all(bool(torch.isfinite(parameter).all()) for parameter in parameters),
                                'DIVERSE_V3_FINITE_UPDATED_FACTORS')
                losses.append(format(math.fsum(current_losses) / 10, '.17g'))
                trace_record(trace, dict(event='optimizer-step', optimizer_step=update, microsteps=10,
                    gradient_l2_squared=format(gradient_square, '.17g'), optimizer_completed=True,
                    completed_monotonic_ns=time.monotonic_ns(), completed_process_cpu_ns=time.process_time_ns()))
            profiled_flops += sum(event.flops for event in profiler.key_averages())
            del profiler
            gc.collect()
            trace.flush()
            os.fsync(trace.fileno())
        trace_record(trace, dict(event='complete', optimizer_steps=UPDATES, microsteps=MICROSTEPS,
            tokens=tokens, supervised_tokens=supervised, completed_monotonic_ns=time.monotonic_ns()))
        trace.flush()
        os.fsync(trace.fileno())
    runtime.synchronize(torch, plan['backend'])
    model.eval()
    del optimizer
    gc.collect()
    trace_pin = dict(path=str(trace_path), bytes=trace_path.stat().st_size, sha256=runtime.file_sha(trace_path))
    result = dict(steps=UPDATES, loss=losses, tokens=tokens, supervised_tokens=supervised,
        supported_profile_flops=profiled_flops,
        flop_scope='profiler-supported-operators-only-not-total-work',
        objective=objective_record(value, trace_pin, tokens))
    verify_training(value, plan, result)
    return result



def verify_training(value, plan, training):
    """Recount the actual trace without loading a model or granting authority."""
    frozen = checked_plan(value)
    runtime.require(runtime.identity(plan) == frozen['base_model_plan']['identity'], 'DIVERSE_V3_TRAINING_PLAN')
    data = load_training_data(frozen['training_data'])
    step.closed(training, 'steps loss tokens supervised_tokens supported_profile_flops flop_scope objective')
    objective = training['objective']
    step.closed(objective, 'profile execution recipe source_sha256 optimizer_steps microsteps distinct_source_rows '
        'row_exposures answer_tokens eos_tokens actual_input_tokens trace same_work_as_legacy_ten_single_rows loss_scope')
    pin = objective['trace']
    step.closed(pin, 'path bytes sha256')
    runtime.require(pin['path'] == str(Path(value['output']) / TRACE) and type(pin['bytes']) is int and
        0 < pin['bytes'] <= MAX_TRACE, 'DIVERSE_V3_TRACE_ROLE')
    raw = step.parent.read_regular(pin['path'], MAX_TRACE)
    runtime.require(len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256'] and
        raw.endswith(b'\n'), 'DIVERSE_V3_TRACE_PIN')
    records = [json.loads(line, object_pairs_hook=runtime.unique) for line in raw.splitlines()]
    selected = data['training_rows']
    runtime.require(len(records) == UPDATES * 11 + 2, 'DIVERSE_V3_COMPLETE_TRACE')
    first = records[0]
    step.closed(first, 'event profile input recipe plan_sha256 source source_rows training_data_sha256 update_schedule_sha256 pid start_monotonic_ns')
    runtime.require(first['event'] == 'start' and first['profile'] == PROFILE and
        first['input'] == runtime.identity(value) and first['recipe'] == runtime.identity(RECIPE) and
        first['plan_sha256'] == value['initial_setup']['diverse_plan']['sha256'] and
        first['source'] == runtime.file_sha(__file__) and
        first['source_rows'] == [runtime.identity(row) for row in selected] and
        first['training_data_sha256'] == frozen['training_data']['sha256'] and
        first['update_schedule_sha256'] == runtime.identity(frozen['update_schedule']) and
        type(first['pid']) is int and first['pid'] > 0 and
        type(first['start_monotonic_ns']) is int and first['start_monotonic_ns'] > 0,
        'DIVERSE_V3_TRACE_CONTEXT')
    position, tokens, previous_clock, previous_cpu = 1, 0, first['start_monotonic_ns'], 0
    observed_losses = []
    for update in range(UPDATES):
        current_losses = []
        for ordinal, source_row_index in enumerate(frozen['update_schedule'][update]):
            row = selected[source_row_index]
            item = records[position]
            position += 1
            step.closed(item, 'event optimizer_step row_ordinal source_row_index source_row_sha256 input_ids answer_token_ids target_index '
                'answer_logits loss backward_completed completed_monotonic_ns completed_process_cpu_ns')
            ids = item['input_ids']
            runtime.require(item['event'] == 'microstep' and type(item['optimizer_step']) is int and
                item['optimizer_step'] == update and type(item['row_ordinal']) is int and item['row_ordinal'] == ordinal and
                type(item['source_row_index']) is int and item['source_row_index'] == source_row_index and
                item['source_row_sha256'] == runtime.identity(row) and item['answer_token_ids'] == [10407, 4607] and
                type(item['target_index']) is int and item['target_index'] == RECIPE['answer_order'].index(row['expected_output']) and
                type(ids) is list and 0 < len(ids) <= plan['input_tokens_max'] and
                all(type(token) is int and 0 <= token < 49152 for token in ids) and
                item['backward_completed'] is True and type(item['answer_logits']) is list and
                len(item['answer_logits']) == 2 and all(type(number) is str and math.isfinite(float(number)) for number in item['answer_logits']) and
                type(item['loss']) is str and math.isfinite(float(item['loss'])) and float(item['loss']) >= 0,
                'DIVERSE_V3_ACTUAL_MICROSTEP')
            logits = [float(number) for number in item['answer_logits']]
            difference = logits[1 - item['target_index']] - logits[item['target_index']]
            expected_loss = max(difference, 0) + math.log1p(math.exp(-abs(difference)))
            runtime.require(math.isfinite(expected_loss) and
                abs(float(item['loss']) - expected_loss) <= 0.00001 * max(1, expected_loss),
                'DIVERSE_V3_LOGIT_LOSS_CONSISTENCY')
            runtime.require(type(item['completed_monotonic_ns']) is int and item['completed_monotonic_ns'] >= previous_clock and
                type(item['completed_process_cpu_ns']) is int and item['completed_process_cpu_ns'] >= previous_cpu,
                'DIVERSE_V3_TRACE_ORDER')
            previous_clock, previous_cpu = item['completed_monotonic_ns'], item['completed_process_cpu_ns']
            runtime.require(ids == data['training_token_ids'][source_row_index], 'DIVERSE_V3_EXACT_TOKEN_TRANSLATION')
            tokens += len(ids)
            current_losses.append(float(item['loss']))
        item = records[position]
        position += 1
        step.closed(item, 'event optimizer_step microsteps gradient_l2_squared optimizer_completed completed_monotonic_ns completed_process_cpu_ns')
        runtime.require(item['event'] == 'optimizer-step' and type(item['optimizer_step']) is int and
            item['optimizer_step'] == update and type(item['microsteps']) is int and item['microsteps'] == 10 and
            item['optimizer_completed'] is True and type(item['gradient_l2_squared']) is str and
            math.isfinite(float(item['gradient_l2_squared'])) and float(item['gradient_l2_squared']) > 0 and
            type(item['completed_monotonic_ns']) is int and item['completed_monotonic_ns'] >= previous_clock and
            type(item['completed_process_cpu_ns']) is int and item['completed_process_cpu_ns'] >= previous_cpu,
            'DIVERSE_V3_ACTUAL_OPTIMIZER_STEP')
        previous_clock, previous_cpu = item['completed_monotonic_ns'], item['completed_process_cpu_ns']
        observed_losses.append(format(math.fsum(current_losses) / 10, '.17g'))
    last = records[position]
    step.closed(last, 'event optimizer_steps microsteps tokens supervised_tokens completed_monotonic_ns')
    runtime.require(last['event'] == 'complete' and type(last['optimizer_steps']) is int and last['optimizer_steps'] == UPDATES and
        type(last['microsteps']) is int and last['microsteps'] == MICROSTEPS and type(last['tokens']) is int and last['tokens'] == tokens and
        type(last['supervised_tokens']) is int and last['supervised_tokens'] == MICROSTEPS and
        type(last['completed_monotonic_ns']) is int and last['completed_monotonic_ns'] >= previous_clock,
        'DIVERSE_V3_FINAL_TRACE_COUNTS')
    runtime.require(type(training['steps']) is int and training['steps'] == UPDATES and training['loss'] == observed_losses and
        type(training['tokens']) is int and training['tokens'] == tokens and
        type(training['supervised_tokens']) is int and training['supervised_tokens'] == MICROSTEPS and
        0 < training['supervised_tokens'] <= tokens == INPUT_TOKENS and
        type(training['supported_profile_flops']) is int and training['supported_profile_flops'] >= 0 and
        training['flop_scope'] == 'profiler-supported-operators-only-not-total-work' and
        runtime.canonical(objective) == runtime.canonical(objective_record(value, pin, tokens)),
        'DIVERSE_V3_EXACT_TRAINING_COUNTS')
