"""Concrete operation histories for the actual default TransactionPrefix methods."""
import copy,struct
from hia.platform.execution_application.cases import H as fx_H, base as fx_base, histories as fx_histories, public as fx_public, tape as fx_tape, u64 as fx_u64, wire as fx_wire
from hia.platform.execution_batch.mandatory_cases import cases as whole_cases
from hia.platform.execution_state.cases import map_bytes
def operation(op,**kw):return {'op':op,**kw}
def initial(state,*,height=10,timestamp=None,miner=bytes([1])*32,parent=bytes([2])*32,actions=()):
    return operation(1,state_hex=state.hex(),height=height,timestamp=timestamp,miner_hex=miner.hex(),parent_id_hex=parent.hex(),actions=list(actions))
def execute(txs=(),*,actions=(),requires_ready=True):
    return operation(2,transactions=[t.hex() for t in txs],actions=list(actions),requires_ready=requires_ready)
def inspect():return operation(3,requires_ready=True)
def close():return operation(4)
def action(sequence,classification):return {'sequence':sequence,'class':classification,'token':70000+sequence*10+classification}
def state_rows(rows):
    result=fx_u64(len(rows))
    for key,value in sorted(rows,key=lambda row:row[0]):
        result+=fx_u64(len(key))+fx_u64(len(value))+key+value
    return result
def histories():
    result=[]
    def add(name,commands,properties=()):
        result.append({'schema':'trnm.transaction-prefix-history.v1','name':name,'commands':commands,'properties':list(properties)})
    funded={**fx_base(),'meta:issued':10000000};state=map_bytes(funded)
    tx=lambda nonce,amount=100:fx_wire(1,fx_public(1)+fx_u64(amount),nonce=nonce)
    good=[tx(1),tx(2,200),tx(3,300)]
    add('append-repeat-error-retry-binding',[initial(state),execute(),execute(good[:1]),execute(good[:1]),
        execute([good[0],tx(3)]),inspect(),execute(good[:2]),execute([good[1],good[0]]),inspect(),
        execute(good),execute(good),close()],('exact_same_object','failed_suffix_rollback','accepted_prefix_not_reverified'))
    for row in whole_cases():
        if row['name']=='workers-before-state-and-count':continue
        commands=[initial(map_bytes(row['rows']),height=row['height']),
                  execute([bytes.fromhex(t) for t in row['transactions']]),inspect(),
                  execute([bytes.fromhex(t) for t in row['transactions']]),close()]
        add('whole-input-'+row['name'],commands,('mandatory_once','full_root_and_finalizer','repeat_retains_state'))
    selected={'transfer-valid','transfer-to-self','reserve-task-valid','cancel-task-valid','task-receipt-valid',
        'task-settlement-valid','task-reserve-then-cancel','task-complete-three-signers','contribution-valid',
        'evaluate-incomplete-valid','evaluate-completes-minimum','release-1-leaves','release-2-leaves','release-3-leaves','release-16-leaves',
        'claim-valid','claim-repeat-keeps-settled-state','quota-reserve-valid','quota-use-valid','quota-use-unfunded-provider',
        'quota-use-spent','quota-reserve-use-same-private-state','work-valid','quota-use-uppercase-consumer',
        'quota-use-mixedcase-consumer','unknown-typed-fields-and-root-refusal'}
    actual=set()
    for row in fx_histories():
        name=row['name']
        if not (name in selected or name.startswith(('evaluate-votes-','claim-claims-','unbounded-unknown-account-','claim-full-u128-','claim-proof-width-'))):continue
        actual.add(name)
        rawrows=[(bytes.fromhex(item['key_hex']),bytes.fromhex(item['value_hex'])) for item in row['base']]
        rawrows.append((b'meta:issued',fx_tape(10000000)))
        source=state_rows(rawrows)
        txs=[bytes.fromhex(item['wire_hex']) for item in row['transactions']]
        height=row['transactions'][0]['height']
        commands=[initial(source,height=height),execute(txs),inspect(),execute(txs),close()]
        add('application-write-domain-'+name,commands,('real_patch_writes','real_panic_or_finalizer_error_rolls_back'))
    if not selected<=actual:raise ValueError('Missing exact fixture names '+repr(selected-actual))
    for classification in (1,2):
        for point in (1,2):
            add('constructor-action-'+str(classification)+'-'+str(point),
                [initial(state,actions=[action(point,classification)]),initial(state),execute(),close()],
                ('constructor_fail_reclaims_state','actual_progress_action'))
        # Two fresh suffixes have twelve original callbacks; the first accepted
        # transaction belongs to the earlier successful operation.
        for point in range(1,13):
            add('accepted-prefix-action-'+str(classification)+'-'+str(point),
                [initial(state),execute(good[:1]),execute(good,actions=[action(point,classification)]),
                 inspect(),execute(good),execute(good),close()],
                ('accepted_prefix_survives_failure','partial_group_or_reward_rollback','same_raw_retry'))
        for point in range(1,5):
            add('empty-finalizer-action-'+str(classification)+'-'+str(point),
                [initial(state),execute(actions=[action(point,classification)]),inspect(),execute(),close()],
                ('empty_prefix_reward_rollback','no_signature_work'))
    add('limit-before-prefix-binding',[initial(state),execute(good[:1]),execute([b'']*257),inspect(),
        execute([]),execute([good[0][:-1]+bytes([good[0][-1]^1])]),execute(good[:2]),close()],
        ('original_limit_priority','complete_raw_binding'))
    add('many-rejected-attempts-retain-one-owner',[initial(state),execute(good[:1])]
        +[execute([good[0],tx(4)]) for _ in range(32)]+[inspect(),execute(good[:2]),close()],
        ('rejected_retry_arena_reuse','real_close_zero_live_objects'))
    for timestamp in (0,1,(1<<64)-1):
        add('legacy-context-timestamp-'+str(timestamp),[initial(state,timestamp=timestamp),execute(good[:1]),execute(good[:2]),close()],
            ('same_private_context','legacy_timestamp_kept'))
    for marker in (0,255):
        add('private-miner-parent-'+str(marker),[initial(state,miner=bytes([marker])*32,parent=bytes([255-marker])*32),execute(good[:1]),execute(good[:2]),close()],
            ('internal_reward_binding',))
    reward='reward:'+fx_H(b'reward',bytes([2])*32,fx_u64(10),bytes([1])*32).hex()
    old={'maturity':100,'amount':0,'owner':fx_public(0).hex(),'unknown':'keep'}
    add('temporary-reward-restores-existing-entire-value',[initial(map_bytes({**funded,reward:old})),execute(good[:1]),execute(good[:2]),inspect(),close()],
        ('before_reward_exact_value','whole_output_and_unfinalized_state_differ'))
    add('complete-malformed-raw-suffix-drained',[initial(state),execute([b'x'*2049]),inspect(),execute(good[:1]),close()],
        ('no_early_transport_close','original_decode_first_maximum'))
    names=[row['name'] for row in result]
    if len(set(names))!=len(names):raise ValueError('duplicate history name')
    return result
