"""Explicit ten-update binary-answer batch experiment under the original owner.

The base model plan still identifies the original material and forward
interface. This separately frozen recipe performs one hundred microsteps on
ten independent source rows. It does not claim the old single-row workload,
model gain, evaluation authority, installation or rewards.
"""
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

SCHEMA = 'llm-runtime-parent-step-binary-observed-input-v2'
PROFILE = 'canonical-positive-zero-binary-batch-observed-v2'
PLAN = 'llm-runtime-binary-answer-observation-plan-v2'
OBSERVER = 'linux-owned-exit-worker-pidfd-v4'
RECIPE = dict(schema='binary-answer-full-batch-recipe-v1', optimizer='AdamW',
    learning_rate='0.002', weight_decay='0', optimizer_steps=10,
    source_rows=10, rows_per_optimizer_step=10, row_exposures=100,
    gradient_accumulation='sum-ten-row-binary-CE-gradients-divided-by-ten',
    initialization_seed=7, rank=4, alpha=8, dropout='0',
    answer_order=['yes', 'no'], answer_positions_per_microstep=1,
    eos_positions_per_microstep=0,
    objective='last-prompt-position-two-original-answer-token-cross-entropy',
    hypothesis='one-fixed-batch-recipe-no-holdout-driven-parameter-search')
TRACE = 'binary-training-trace-v2.jsonl'
MAX_TRACE = 1024 * 1024


def is_binary(value):
    return type(value) is dict and value.get('schema') == SCHEMA


def rows(plan):
    runtime.require(plan['training_steps'] == 10 and plan['seed'] == 7 and
        runtime.canonical(plan['tasks']) == runtime.canonical(runtime.tasks()),
        'BINARY_V2_ORIGINAL_TRAINING_SOURCE')
    offered = [row for row in plan['tasks'] if row['partition'] == 'training']
    selected = offered[:10]
    runtime.require(len(offered) == 12 and len(selected) == 10 and
        sum(row['expected_output'] == 'yes' for row in selected) == 5 and
        sum(row['expected_output'] == 'no' for row in selected) == 5,
        'BINARY_V2_TEN_BALANCED_SOURCE_ROWS')
    return selected


def plan_record(value):
    """Freeze new training work separately from the unchanged material plan."""
    from llm_runtime_parent_step_v2 import sources
    base = runtime.validate_plan(step.read_object(value['files']['plan'], 1024 * 1024))
    selected = rows(base)
    runtime.require(runtime.plan_exit_profile(base) == 'strict-v1' and
        base['training_budget'] == dict(wall_seconds=1800, rss_bytes=16 * 1024**3) and
        base['inference_budget'] == dict(wall_seconds=600, rss_bytes=8 * 1024**3),
        'BINARY_V2_ORIGINAL_BUDGETS')
    return dict(schema=PLAN, profile=PROFILE,
        scope='new-training-work-original-material-and-independent-terminal-owner-no-qualification',
        source=sources(PROFILE), recipe=RECIPE,
        base_model_plan=dict(identity=runtime.identity(base),
            sha256=runtime.file_sha(value['files']['plan']), source=base['runtime_source'],
            unchanged=True, legacy_candidate_recipe_is_used=False),
        parent=value['parent'], parent_material=value['initial_setup']['parent_material'],
        setup_recipe=setup.RECIPE, training_rows=selected,
        ordered_training_row_sha256=[runtime.identity(row) for row in selected],
        independent_source_rows=10, source_ledger_records=20, actual_row_exposures=100,
        observer=runtime.exit_observation_profile(OBSERVER),
        training_budget=base['training_budget'], inference_budget=base['inference_budget'],
        actual_resource_costs_required=True, same_work_as_legacy_ten_single_rows=False,
        model_plan_unchanged=True, target_contract_unchanged=True, flags=step.FALSES)


def checked_plan(value):
    role = value['initial_setup']['binary_plan']
    step.closed(role, 'path sha256')
    runtime.require(type(role['path']) is str and 0 < len(role['path']) <= 4096 and
                    Path(role['path']).is_absolute(), 'BINARY_V2_PLAN_PATH')
    step.digest(role['sha256'])
    raw = step.parent.read_regular(role['path'], step.MAX_INPUT)
    runtime.require(hashlib.sha256(raw).hexdigest() == role['sha256'], 'BINARY_V2_PLAN_PIN')
    record = json.loads(raw, object_pairs_hook=runtime.unique)
    runtime.require(runtime.canonical(record) == runtime.canonical(plan_record(value)),
                    'BINARY_V2_EXACT_EXECUTION_PLAN')
    runtime.validate_exit_observation_profile(record['observer'])
    return record


def context(value):
    record = checked_plan(value)
    return dict(profile=PROFILE, plan_sha256=value['initial_setup']['binary_plan']['sha256'],
        recipe=runtime.identity(RECIPE), observer=runtime.identity(record['observer']),
        model_plan=record['base_model_plan']['identity'],
        training_rows=runtime.identity(record['ordered_training_row_sha256']),
        independent_source_rows=10, row_exposures=100, optimizer_steps=10)


def preflight(value):
    from llm_runtime_parent_step_v2 import SCHEMA as old_schema, PROFILE as old_profile, sources, preflight as original
    step.closed(value, 'schema scope attempt_id operation experiment source files parent candidate output flags initial_setup')
    runtime.require(is_binary(value) and value['scope'] == step.SCOPE and
        value['operation'] == 'train' and value['source'] == sources(PROFILE) and
        value['flags'] == step.FALSES and all(v is False for v in value['flags'].values()),
        'BINARY_V2_SCOPE_SOURCE')
    request = value['initial_setup']
    step.closed(request, 'profile recipe parent_material binary_plan')
    runtime.require(request['profile'] == PROFILE and request['recipe'] == setup.RECIPE,
                    'BINARY_V2_INITIAL_SETUP')
    # This projection is used only by the original material/setup validator.
    # It is never persisted, executed or emitted as an old training receipt.
    base = dict(value, schema=old_schema, source=sources(old_profile),
        initial_setup={key: item for key, item in request.items() if key != 'binary_plan'})
    base['initial_setup']['profile'] = old_profile
    result = original(base)
    record = checked_plan(value)
    runtime.require(record['base_model_plan']['identity'] == value['experiment'] and
        record['training_budget'] == result[0]['training_budget'] and
        record['inference_budget'] == result[0]['inference_budget'],
        'BINARY_V2_MODEL_AND_BUDGET_BINDING')
    return result


def verify_supervisor(value, result):
    record = checked_plan(value)
    runtime.require(result.get('exit_observation_profile') == record['observer'] and
        result.get('terminal_reconciliation_profile') == 'explicit-' + OBSERVER and
        result.get('budget') == record['training_budget'], 'BINARY_V2_SUPERVISOR_BINDING')


def objective_record(value, trace, tokens):
    return dict(profile=PROFILE, execution=context(value), recipe=runtime.identity(RECIPE),
        source_sha256=runtime.file_sha(__file__), optimizer_steps=10, microsteps=100,
        independent_source_rows=10, row_exposures=100,
        answer_tokens=100, eos_tokens=0, actual_input_tokens=tokens,
        trace=trace, same_work_as_legacy_ten_single_rows=False,
        loss_scope='ten-row-mean-two-original-answer-token-CE-gradient-per-optimizer-step')


def trace_record(stream, value):
    raw = runtime.canonical(value) + b'\n'
    runtime.require(stream.tell() + len(raw) <= MAX_TRACE, 'BINARY_V2_TRACE_BOUND')
    stream.write(raw)


def finalize_live_child(value, directory, observer, report, begin, pending):
    """Attempt release and persist both records without hiding a primary error."""
    import ctypes
    primary = pending
    started = time.monotonic_ns()
    release = dict(schema='llm-parent-live-release-binary-observed-v2',
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
        runtime.save(Path(directory) / 'live-release-binary-observed-v2.json', release)
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
    """Run ten actual mean-gradient updates; report all one hundred microsteps."""
    frozen = checked_plan(value)
    selected = rows(plan)
    encoded_answers = [tokenizer.encode(answer, add_special_tokens=False) for answer in RECIPE['answer_order']]
    runtime.require(all(len(answer) == 1 for answer in encoded_answers), 'BINARY_V2_SINGLE_TOKEN_ANSWERS')
    answers = [answer[0] for answer in encoded_answers]
    runtime.require(len(set(answers)) == 2 and answers == [10407, 4607] and
        not set(answers).intersection(tokenizer.all_special_ids), 'BINARY_V2_ORIGINAL_ANSWER_TOKENS')
    prompts = [runtime.prompt_tokens(tokenizer, row, plan['input_tokens_max']) for row in selected]
    runtime.require(all(0 < len(prompt) <= plan['input_tokens_max'] for prompt in prompts),
                    'BINARY_V2_PROMPT_BOUND')
    parameters = [parameter for parameter in model.parameters() if parameter.requires_grad]
    runtime.require(sum(parameter.numel() for parameter in parameters) == 230400,
                    'BINARY_V2_ORIGINAL_TRAINABLE_FACTORS')
    optimizer = torch.optim.AdamW(parameters, lr=float(RECIPE['learning_rate']), weight_decay=0)
    losses, tokens, supervised = [], 0, 0
    model.train()
    trace_path = Path(directory) / TRACE
    profiled_flops = 0
    with trace_path.open('xb') as trace:
        trace_record(trace, dict(event='start', profile=PROFILE, input=runtime.identity(value),
            recipe=runtime.identity(RECIPE), plan_sha256=value['initial_setup']['binary_plan']['sha256'],
            source=runtime.file_sha(__file__), source_rows=frozen['ordered_training_row_sha256'],
            pid=os.getpid(), start_monotonic_ns=time.monotonic_ns()))
        for update in range(10):
            # Bound retained profiler observations to one actual ten-row update.
            # Every microstep remains profiled; aggregate only measured operator FLOPs.
            with torch.profiler.profile(
                    activities=[torch.profiler.ProfilerActivity.CPU],
                    record_shapes=True, with_flops=True) as profiler:
                optimizer.zero_grad(set_to_none=True)
                current_losses = []
                for ordinal, (row, prompt) in enumerate(zip(selected, prompts)):
                    target = RECIPE['answer_order'].index(row['expected_output'])
                    ids = torch.tensor([prompt], dtype=torch.int64, device=device)
                    output = model(input_ids=ids, attention_mask=torch.ones_like(ids, dtype=torch.bool), use_cache=False)
                    scores = output.logits[:, -1, answers]
                    runtime.require(tuple(scores.shape) == (1, 2) and bool(torch.isfinite(scores).all()),
                                    'BINARY_V2_FINITE_ANSWER_SCORES')
                    loss = torch.nn.functional.cross_entropy(scores, torch.tensor([target], dtype=torch.int64, device=device))
                    runtime.require(torch.isfinite(loss).item(), 'BINARY_V2_FINITE_LOSS')
                    (loss / 10).backward()
                    observed_loss = loss.detach().item()
                    current_losses.append(observed_loss)
                    tokens += ids.numel()
                    supervised += 1
                    trace_record(trace, dict(event='microstep', optimizer_step=update, row_ordinal=ordinal,
                        source_row_sha256=runtime.identity(row), input_ids=ids.detach().cpu().tolist()[0],
                        answer_token_ids=answers, target_index=target,
                        answer_logits=[format(number, '.17g') for number in scores.detach().cpu().tolist()[0]],
                        loss=format(observed_loss, '.17g'), backward_completed=True,
                        completed_monotonic_ns=time.monotonic_ns(), completed_process_cpu_ns=time.process_time_ns()))
                gradient_square = 0.0
                for parameter in parameters:
                    if parameter.grad is not None:
                        runtime.require(bool(torch.isfinite(parameter.grad).all()), 'BINARY_V2_FINITE_GRADIENT')
                        gradient_square += parameter.grad.detach().double().square().sum().item()
                runtime.require(math.isfinite(gradient_square) and gradient_square > 0, 'BINARY_V2_ACTUAL_GRADIENT')
                optimizer.step()
                runtime.require(all(bool(torch.isfinite(parameter).all()) for parameter in parameters),
                                'BINARY_V2_FINITE_UPDATED_FACTORS')
                losses.append(format(math.fsum(current_losses) / 10, '.17g'))
                trace_record(trace, dict(event='optimizer-step', optimizer_step=update, microsteps=10,
                    gradient_l2_squared=format(gradient_square, '.17g'), optimizer_completed=True,
                    completed_monotonic_ns=time.monotonic_ns(), completed_process_cpu_ns=time.process_time_ns()))
            profiled_flops += sum(event.flops for event in profiler.key_averages())
            del profiler
            gc.collect()
            trace.flush()
            os.fsync(trace.fileno())
        trace_record(trace, dict(event='complete', optimizer_steps=10, microsteps=100,
            tokens=tokens, supervised_tokens=supervised, completed_monotonic_ns=time.monotonic_ns()))
        trace.flush()
        os.fsync(trace.fileno())
    runtime.synchronize(torch, plan['backend'])
    model.eval()
    del optimizer
    gc.collect()
    trace_pin = dict(path=str(trace_path), bytes=trace_path.stat().st_size, sha256=runtime.file_sha(trace_path))
    result = dict(steps=10, loss=losses, tokens=tokens, supervised_tokens=supervised,
        supported_profile_flops=profiled_flops,
        flop_scope='profiler-supported-operators-only-not-total-work',
        objective=objective_record(value, trace_pin, tokens))
    verify_training(value, plan, result)
    return result


def verify_training(value, plan, training):
    """Recount the actual trace without loading a model or granting authority."""
    step.closed(training, 'steps loss tokens supervised_tokens supported_profile_flops flop_scope objective')
    objective = training['objective']
    step.closed(objective, 'profile execution recipe source_sha256 optimizer_steps microsteps independent_source_rows '
        'row_exposures answer_tokens eos_tokens actual_input_tokens trace same_work_as_legacy_ten_single_rows loss_scope')
    pin = objective['trace']
    step.closed(pin, 'path bytes sha256')
    runtime.require(pin['path'] == str(Path(value['output']) / TRACE) and type(pin['bytes']) is int and
        0 < pin['bytes'] <= MAX_TRACE, 'BINARY_V2_TRACE_ROLE')
    raw = step.parent.read_regular(pin['path'], MAX_TRACE)
    runtime.require(len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256'] and
        raw.endswith(b'\n'), 'BINARY_V2_TRACE_PIN')
    records = [json.loads(line, object_pairs_hook=runtime.unique) for line in raw.splitlines()]
    selected = rows(plan)
    runtime.require(len(records) == 112, 'BINARY_V2_COMPLETE_TRACE')
    first = records[0]
    step.closed(first, 'event profile input recipe plan_sha256 source source_rows pid start_monotonic_ns')
    runtime.require(first['event'] == 'start' and first['profile'] == PROFILE and
        first['input'] == runtime.identity(value) and first['recipe'] == runtime.identity(RECIPE) and
        first['plan_sha256'] == value['initial_setup']['binary_plan']['sha256'] and
        first['source'] == runtime.file_sha(__file__) and
        first['source_rows'] == [runtime.identity(row) for row in selected] and
        type(first['pid']) is int and first['pid'] > 0 and
        type(first['start_monotonic_ns']) is int and first['start_monotonic_ns'] > 0,
        'BINARY_V2_TRACE_CONTEXT')
    position, tokens, previous_clock, previous_cpu = 1, 0, first['start_monotonic_ns'], 0
    prompts, observed_losses = {}, []
    for update in range(10):
        current_losses = []
        for ordinal, row in enumerate(selected):
            item = records[position]
            position += 1
            step.closed(item, 'event optimizer_step row_ordinal source_row_sha256 input_ids answer_token_ids target_index '
                'answer_logits loss backward_completed completed_monotonic_ns completed_process_cpu_ns')
            ids = item['input_ids']
            runtime.require(item['event'] == 'microstep' and type(item['optimizer_step']) is int and
                item['optimizer_step'] == update and type(item['row_ordinal']) is int and item['row_ordinal'] == ordinal and
                item['source_row_sha256'] == runtime.identity(row) and item['answer_token_ids'] == [10407, 4607] and
                type(item['target_index']) is int and item['target_index'] == RECIPE['answer_order'].index(row['expected_output']) and
                type(ids) is list and 0 < len(ids) <= plan['input_tokens_max'] and
                all(type(token) is int and 0 <= token < 49152 for token in ids) and
                item['backward_completed'] is True and type(item['answer_logits']) is list and
                len(item['answer_logits']) == 2 and all(type(number) is str and math.isfinite(float(number)) for number in item['answer_logits']) and
                type(item['loss']) is str and math.isfinite(float(item['loss'])) and float(item['loss']) >= 0,
                'BINARY_V2_ACTUAL_MICROSTEP')
            logits = [float(number) for number in item['answer_logits']]
            difference = logits[1 - item['target_index']] - logits[item['target_index']]
            expected_loss = max(difference, 0) + math.log1p(math.exp(-abs(difference)))
            runtime.require(math.isfinite(expected_loss) and
                abs(float(item['loss']) - expected_loss) <= 0.00001 * max(1, expected_loss),
                'BINARY_V2_LOGIT_LOSS_CONSISTENCY')
            runtime.require(type(item['completed_monotonic_ns']) is int and item['completed_monotonic_ns'] >= previous_clock and
                type(item['completed_process_cpu_ns']) is int and item['completed_process_cpu_ns'] >= previous_cpu,
                'BINARY_V2_TRACE_ORDER')
            previous_clock, previous_cpu = item['completed_monotonic_ns'], item['completed_process_cpu_ns']
            if ordinal not in prompts:
                prompts[ordinal] = ids
            runtime.require(prompts[ordinal] == ids, 'BINARY_V2_EXACT_ROW_REUSE')
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
            'BINARY_V2_ACTUAL_OPTIMIZER_STEP')
        previous_clock, previous_cpu = item['completed_monotonic_ns'], item['completed_process_cpu_ns']
        observed_losses.append(format(math.fsum(current_losses) / 10, '.17g'))
    last = records[position]
    step.closed(last, 'event optimizer_steps microsteps tokens supervised_tokens completed_monotonic_ns')
    runtime.require(last['event'] == 'complete' and type(last['optimizer_steps']) is int and last['optimizer_steps'] == 10 and
        type(last['microsteps']) is int and last['microsteps'] == 100 and type(last['tokens']) is int and last['tokens'] == tokens and
        type(last['supervised_tokens']) is int and last['supervised_tokens'] == 100 and
        type(last['completed_monotonic_ns']) is int and last['completed_monotonic_ns'] >= previous_clock,
        'BINARY_V2_FINAL_TRACE_COUNTS')
    runtime.require(type(training['steps']) is int and training['steps'] == 10 and training['loss'] == observed_losses and
        type(training['tokens']) is int and training['tokens'] == tokens and
        type(training['supervised_tokens']) is int and training['supervised_tokens'] == 100 and
        0 < training['supervised_tokens'] <= tokens <= 100 * plan['input_tokens_max'] and
        type(training['supported_profile_flops']) is int and training['supported_profile_flops'] >= 0 and
        training['flop_scope'] == 'profiler-supported-operators-only-not-total-work' and
        runtime.canonical(objective) == runtime.canonical(objective_record(value, pin, tokens)),
        'BINARY_V2_EXACT_TRAINING_COUNTS')
