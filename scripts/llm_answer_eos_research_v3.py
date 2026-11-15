"""One frozen public diagnostic objective, under the original parent-step owner.

The unchanged pilot plan describes material/forward interfaces and controls.
Its legacy candidate recipe does not describe this explicitly named V3 arm.
Nothing here owns evaluation, process supervision, credentials or installation.
"""
import gc
import hashlib
import json
from pathlib import Path

import llm_initial_trainable_setup_v2 as setup
import llm_runtime_parent_step as step
import llm_runtime_pilot as runtime

SCHEMA = 'llm-runtime-parent-step-input-v3'
PROFILE = 'canonical-positive-zero-answer-eos-balanced-v3'
PLAN = 'llm-runtime-answer-eos-research-plan-v3'
RECIPE = dict(schema='answer-eos-balanced-loss-v1', learning_rate='0.001',
    optimizer='AdamW', weight_decay='0', initialization_seed=7, batch_size=1,
    steps=10, rank=4, alpha=8, dropout='0', answer_weight=[1, 2],
    each_eos_weight=[1, 6], answer_tokens_per_step=1, eos_tokens_per_step=3,
    rationale='equal-answer-and-termination-mass-with-established-control-learning-rate')
SCOPE = 'public-fixture-single-prespecified-six-arm-diagnostic-no-independent-quality-or-installation'


def is_research(value):
    return type(value) is dict and value.get('schema') == SCHEMA


def plan_record(value):
    """Deterministic pre-execution record; the caller must freeze and pin it."""
    from llm_runtime_parent_step_v2 import sources
    baseline = step.read_object(value['files']['plan'], 1024 * 1024)
    runtime.require(baseline['training_steps'] == 10 and baseline['seed'] == 7 and
        runtime.canonical(baseline['tasks']) == runtime.canonical(runtime.tasks()), 'RESEARCH_V3_FIXED_TASKS')
    return dict(schema=PLAN, scope=SCOPE, source=sources(PROFILE), recipe=RECIPE,
        material_and_control_plan=dict(identity=runtime.identity(baseline),
            file_sha256=runtime.file_sha(value['files']['plan']),
            legacy_candidate_recipe_is_used=False),
        parent=value['parent'], parent_material=value['initial_setup']['parent_material'],
        training_tasks=runtime.identity([r for r in baseline['tasks'] if r['partition'] == 'training']),
        evaluation_tasks=runtime.identity([r for r in baseline['tasks'] if r['partition'] != 'training']),
        participants=list(runtime.PARTICIPANTS) + ['actual-current-incumbent'],
        schedule=dict(steps=10, tokens=526, supervised_tokens=40, nonzero_weight_tokens=40),
        evaluation_scope='already-public-four-calibration-and-four-evaluation-not-independent-holdout',
        actual_resource_costs_must_be_measured=True, flags=step.FALSES)


def context(value):
    role = value['initial_setup']['research_plan']
    return dict(plan_sha256=role['sha256'], recipe=runtime.identity(RECIPE), profile=PROFILE)


def preflight(value):
    from llm_runtime_parent_step_v2 import preflight as original, sources, PROFILE as original_profile, SCHEMA as original_schema
    step.closed(value, 'schema scope attempt_id operation experiment source files parent candidate output flags initial_setup')
    runtime.require(value['schema'] == SCHEMA and value['scope'] == step.SCOPE and
        value['source'] == sources(PROFILE) and value['flags'] == step.FALSES and
        all(v is False for v in value['flags'].values()), 'RESEARCH_V3_SCOPE_SOURCE')
    runtime.require(value['operation'] == 'train', 'RESEARCH_V3_TRAIN_ONLY')
    request = value['initial_setup']
    step.closed(request, 'profile recipe parent_material research_plan')
    runtime.require(request['profile'] == PROFILE and runtime.canonical(request['recipe']) ==
                    runtime.canonical(setup.RECIPE), 'RESEARCH_V3_SETUP_RECIPE')
    role = request['research_plan']
    step.closed(role, 'path sha256')
    runtime.require(type(role['path']) is str and 0 < len(role['path']) <= 4096 and
                    Path(role['path']).is_absolute(), 'RESEARCH_V3_PLAN_PATH')
    step.digest(role['sha256'])
    raw = step.parent.read_regular(role['path'], step.MAX_INPUT)
    runtime.require(hashlib.sha256(raw).hexdigest() == role['sha256'], 'RESEARCH_V3_PLAN_PIN')
    # Validation-only reuse, never persisted, executed or emitted as a V2 claim.
    base = dict(value, schema=original_schema, source=sources(),
        initial_setup={k: v for k, v in request.items() if k != 'research_plan'})
    base['initial_setup']['profile'] = original_profile
    checked = original(base)
    frozen = json.loads(raw, object_pairs_hook=runtime.unique)
    runtime.require(runtime.canonical(frozen) == runtime.canonical(plan_record(value)), 'RESEARCH_V3_EXACT_PLAN')
    return checked


def objective_record():
    return dict(profile=PROFILE, recipe=runtime.identity(RECIPE),
        source_sha256=runtime.file_sha(__file__), answer_tokens=10, eos_tokens=30,
        nonzero_weight_tokens=40, per_step_weight_sum=[1, 1],
        loss_scope='causal-CE-answer-half-three-EOS-half-every-target-weight-positive')


def verify_training(training):
    runtime.require(runtime.canonical(training['objective']) == runtime.canonical(objective_record()) and
        (training['steps'], training['tokens'], training['supervised_tokens']) == (10, 526, 40),
        'RESEARCH_V3_OBJECTIVE_COUNTS')


def weighted_loss(logits, labels, prompt_length, torch):
    """Same causal labels and forward shape; all four target losses remain live."""
    runtime.require(type(prompt_length) is int and prompt_length > 0 and
        logits.ndim == 3 and logits.shape[0] == 1 and labels.ndim == 2 and
        tuple(labels.shape) == tuple(logits.shape[:2]) and
        labels.shape[1] == prompt_length + 4 and
        bool((labels[:, :prompt_length] == -100).all()) and
        bool((labels[:, prompt_length:] >= 0).all()), 'RESEARCH_V3_LOSS_SHAPE')
    losses = torch.nn.functional.cross_entropy(
        logits[:, :-1, :].contiguous().view(-1, logits.shape[-1]),
        labels[:, 1:].contiguous().view(-1), reduction='none', ignore_index=-100)
    weights = torch.zeros_like(losses)
    weights[prompt_length - 1] = .5
    weights[prompt_length:prompt_length + 3] = 1 / 6
    return (losses * weights).sum()


def train(model, tokenizer, plan, torch, device):
    """Pure objective implementation; the existing child owns the runtime."""
    runtime.require(plan['training_steps'] == 10 and plan['seed'] == 7 and
        runtime.canonical(plan['tasks']) == runtime.canonical(runtime.tasks()), 'RESEARCH_V3_FIXED_TASKS')
    rows = [row for row in plan['tasks'] if row['partition'] == 'training']
    optimizer = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad],
                                 lr=float(RECIPE['learning_rate']), weight_decay=0)
    losses, tokens, supervised = [], 0, 0
    model.train()
    with torch.profiler.profile(activities=[torch.profiler.ProfilerActivity.CPU],
                                record_shapes=True, with_flops=True) as profiler:
        for number in range(10):
            row = rows[number]
            prompt = runtime.prompt_tokens(tokenizer, row, plan['input_tokens_max'])
            answer = tokenizer.encode(row['expected_output'], add_special_tokens=False)
            runtime.require(len(answer) == 1 and tokenizer.eos_token_id not in answer,
                            'RESEARCH_V3_ANSWER_TOKEN_SHAPE')
            target = answer + [tokenizer.eos_token_id] * 3
            runtime.require(len(prompt) + len(target) <= plan['input_tokens_max'], 'RUNTIME_TRAINING_TOKEN_LIMIT')
            ids = torch.tensor([prompt + target], dtype=torch.int64, device=device)
            labels = torch.tensor([[-100] * len(prompt) + target], dtype=torch.int64, device=device)
            optimizer.zero_grad(set_to_none=True)
            result = model(input_ids=ids, attention_mask=torch.ones_like(ids, dtype=torch.bool), use_cache=False)
            loss = weighted_loss(result.logits, labels, len(prompt), torch)
            runtime.require(torch.isfinite(loss).item(), 'RUNTIME_TRAINING_NONFINITE')
            loss.backward(); optimizer.step()
            losses.append(format(loss.detach().item(), '.12g'))
            tokens += ids.numel(); supervised += len(target)
    runtime.synchronize(torch, plan['backend'])
    model.eval(); del optimizer; gc.collect()
    training = dict(steps=10, loss=losses, tokens=tokens, supervised_tokens=supervised,
        supported_profile_flops=sum(event.flops for event in profiler.key_averages()),
        flop_scope='profiler-supported-operators-only-not-total-work', objective=objective_record())
    verify_training(training)
    return training
