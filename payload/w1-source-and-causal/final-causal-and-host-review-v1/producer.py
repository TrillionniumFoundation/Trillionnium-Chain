import os,sys,json,hashlib,pathlib,stat,datetime
BASE=pathlib.Path('/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1')
OUT=BASE/'final-causal-and-host-review-v1'
if OUT.exists(): raise RuntimeError('create-only output already exists')
if BASE.resolve(strict=True)!=BASE: raise RuntimeError('noncanonical input root')
OUT.mkdir(mode=0o700)
def write(name, data):
    if isinstance(data,str): data=data.encode()
    if len(data)>65536: raise RuntimeError('small-output cap: '+name)
    fd=os.open(OUT/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        with os.fdopen(fd,'wb') as f: f.write(data);f.flush();os.fsync(f.fileno())
    except BaseException: raise
    return {'path':str(OUT/name),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
def enc(o):return (json.dumps(o,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
inputs={}
def read(p, expected=None, size=None, cap=4*1024*1024):
    p=pathlib.Path(p)
    if p.resolve(strict=True)!=p:raise RuntimeError('noncanonical '+str(p))
    a=os.lstat(p)
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK),'rb') as f:
        b=os.fstat(f.fileno())
        if ident(a)!=ident(b) or not stat.S_ISREG(b.st_mode) or b.st_nlink!=1 or b.st_size>cap:raise RuntimeError('unsafe source '+str(p))
        raw=f.read(cap+1)
        if len(raw)!=b.st_size or ident(b)!=ident(os.fstat(f.fileno())) or ident(b)!=ident(os.lstat(p)):raise RuntimeError('source changed '+str(p))
    h=hashlib.sha256(raw).hexdigest()
    if expected is not None and h!=expected:raise RuntimeError('source digest '+str(p))
    if size is not None and len(raw)!=size:raise RuntimeError('source size '+str(p))
    pin={'path':str(p),'bytes':len(raw),'sha256':h,'identity':ident(b)}
    if str(p) in inputs and inputs[str(p)]!=pin:raise RuntimeError('repeated input changed')
    inputs[str(p)]=pin
    return raw
def jread(rel,sha,size=None):return json.loads(read(BASE/rel,sha,size))
outputs=[]
outputs.append(write('producer.py',sys.argv[1]))
draft=json.loads(sys.argv[2]);outputs.append(write('analysis-input.json',enc(draft)))
static=jread('static-scope-review-v1/summary.json','a2ca3bb9b666e5803794d5b87903644ba989f1a102531f5571257ff825762bd9',13316)
dist=jread('cpu-distribution-v1/cpu-distribution.json','bcd5f458156b83605558c37feabbfcc3bbd42f81a27ef4c8f62b6fc2798c2acc',145135)
attack=jread('cpu-distribution-v1/attacker-breakdown.json','db0b779d4f32ea5ef6e9f84960d3713addf7c52b964b6286f8d5bd4a66bf448d',90714)
host_counters=jread('measurement-boundaries-v1/whole-child-host-counter-references.json','dfa9ce8d9ce0b786014a8d86277467083aaf511179bec5f93862d6f81c4bff98',6675)
idxs=[
 ('runtime-critical-path-source-v1/source-index.json','aa8fe048fffa5b107b9bd969c808bf3732cc3eb1e7a22e7114a9bd07a6c0f392',2016),
 ('server-history-progress-source-v1/source-index.json','95da2ae5d6ca32e6a442a0fdf48ea586e715f21d5066536ba0e407b02ac7dd19',979),
 ('history-progress-controls-source-v1/source-index.json','216cb73a28adcb21eecad8df6c78eaad5ef4535117668265dca5a3883fe3e235',2290),
 ('measurement-boundaries-v1/source-index.json','aa52a11cf2417e13414b2e8a9fbd71faadc8fc3208cf4855068e3b6565026427',1479),
 ('history-contract-documentation-selected-v1/source-index.json','e4bf56c1e5de3f0f2f192b7934121b202b9807c1ffccbc83b0cb495afaa243b2',2241)]
sources=[]
for x in static['captured_source_files']:
    q=dict(x);q['capture']=q.pop('path');q['path']=pathlib.Path(q['capture']).name.replace('--','/');sources.append(q)
for rel,h,n in idxs:
    v=jread(rel,h,n)
    sources.extend(v if isinstance(v,list) else v.get('files',[v]))
# Preserve source inputs already read from immutable Git, without rerunning Git or their code.
source_text={}
normalized=[]
for x in sources:
    p=x['path'];raw=read(x['capture'],x['sha256'],x['bytes'],2*1024*1024)
    oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    if oid!=x['git_blob']:raise RuntimeError('Git blob identity '+p)
    if p in source_text:
        if source_text[p]!=raw.decode():raise RuntimeError('duplicate source mismatch')
        continue
    source_text[p]=raw.decode()
    normalized.append({'source':draft['source']['head'],'path':p,'git_blob':oid,'bytes':len(raw),'sha256':x['sha256'],'capture':x['capture'],'url':'https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/'+draft['source']['head']+'/'+p})
if len(dist['rows'])!=8 or len(attack['rows'])!=4:raise RuntimeError('report roster')
for r in dist['rows']:
    if r['requested_window_ns']!=4000000000:raise RuntimeError('window drift')
    if r['phase_index']==1 and len(r['workers'])!=16:raise RuntimeError('worker roster')
cpu=[]
for r in dist['rows']:
    cpu.append({k:r[k] for k in ('mode','variant','phase','phase_index','pointer','requested_window_ns','finite_business_target_met','attacker_workers_cpu_ns','attacker_workers_cpu_scope','reader_cpu_ns','independent_replay_and_confirmation_cpu_ns','independent_replay_and_confirmation_wall_ns','independent_page_cpu','service_cpu_fields','service_selected_counts','initial_meter','final_meter','accounting_closed')})
    cpu[-1].update(
      attacker_workers=[{'worker':w['worker'],'calling_thread_cpu_ns':w['calling_thread_cpu_ns'],'calls':w['calls']['count'],'pointer':w['pointer']} for w in r['workers']],
      honest_submit_calls=r['honest_submit_calls'],honest_history_calls=r['honest_history_calls'],
      original_report={'zip':r['original_zip'],'zip_sha256':r['zip_sha256'],'member':r['member'],'bytes':r['report_bytes'],'sha256':r['report_sha256']},
      independent_replay_rows=r['independent_pages'])
atk=[]
for r in attack['rows']:
    z={k:v for k,v in r.items()if k not in ('workers','construction_coverage_original','root_cpu_scope_fields')}
    z['per_worker']=[{k:w[k]for k in ('worker','pointer','calling_thread_cpu_ns','calls_count','call.client_thread_cpu_ns','metrics.solution_search_thread_cpu_ns','metrics.solution_trials','from_zero_construction.attacker_cpu_ns','residual_after_client_and_construction_cpu_ns')}for w in r['workers']]
    atk.append(z)
# Split fixed data so each direct-read file remains <=64KiB.
outputs.append(write('cpu-phases.json',enc({'schema':'trnm-r1-eight-original-phase-cpu-summary-v1','rows':cpu,'scopes_not_additive':True})))
outputs.append(write('attacker-cpu.json',enc({'schema':'trnm-r1-four-pressure-attacker-cpu-summary-v1','rows':atk,'nulls_never_filled_with_zero':True})))
# Replace rounded illustrative replay CPU fields with actual original page values, retaining detailed pointers.
for t in draft['timings']:
    mode,var=t['case'].split('/')
    r=next(r for r in dist['rows'] if r['mode']==mode and r['variant']==var and r['phase_index']==1)
    t['original_replay_rows']=r['independent_pages']
    t['exact_cpu_scope_reference']={'path':str(OUT/'cpu-phases.json'),'row':cpu.index(next(z for z in cpu if z['mode']==mode and z['variant']==var and z['phase_index']==1))}
    for k in ('last_replay_thread_cpu_ns','first_replay_thread_cpu_ns','rounded_last_replay_cpu','rounded_first_replay_cpu','page_cpu_wait_wall_ns','durable_begin_first_wall_ns','rounded_auxiliary_wall_values'):t.pop(k,None)
draft['outer_host_originals']=host_counters
draft['reviewed_static_controls']=[
 {'path':'trillionnium/crates/trnm-pon-node/src/ingress.rs','methods':['public_loopback_history_requires_real_fixed_host_parent','host_owner_failure_during_w1_tile_does_not_commit_or_poison_retry','history_valid_w1_cannot_commit_after_m06_host_owner_rejection'],'executed_by_this_review':False},
 {'path':'trillionnium/crates/trnm-pon-node/src/ingress/history_import_tests.rs','methods':['history_w1_checks_host_once_at_every_real_progress_boundary','history_w1_host_change_at_selected_and_unselected_boundaries_refuses_and_retries','history_w1_original_deadline_precedes_resource_and_complete_work','history_w1_checks_host_once_at_every_native_boundary_without_refill'],'executed_by_this_review':False}]
draft['earlier_static_report_preserved']={'path':str(BASE/'static-scope-review-v1/summary.json'),'sha256':'a2ca3bb9b666e5803794d5b87903644ba989f1a102531f5571257ff825762bd9','update':'That initial report correctly left inner cause unknown; this closure uses subsequently preserved complete inner originals. Its bytes are unchanged.'}
draft['sealed_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
outputs.append(write('summary.json',enc(draft)))
boundaries=[
 ('trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs',[(1280,1322),(1433,1475)]),
 ('trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs',[(1991,2011),(2385,2403),(2575,2587),(2818,2831)]),
 ('trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs',[(550,573),(637,650),(1570,1583)]),
 ('trillionnium/crates/trnm-pon-node/src/ingress.rs',[(2660,2745),(3718,3732)]),
 ('trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs',[(20,43),(299,340)]),
 ('trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs',[(664,681),(877,889),(914,928)])]
def excerpts(specs):
    parts=[]
    for p,ranges in specs:
        n=next(x for x in normalized if x['path']==p)
        lines=source_text[p].splitlines()
        parts.append('SOURCE '+p+'\nGIT_BLOB '+n['git_blob']+'\nSHA256 '+n['sha256']+'\nURL '+n['url'])
        for a,b in ranges:parts.append('\n'.join(str(i+1)+': '+s for i,s in enumerate(lines) if a<=i+1<=b))
    return '\n\n'.join(parts)+'\n'
outputs.append(write('current-entry-and-progress-excerpts.txt',excerpts(boundaries)))
docspecs=[
 ('docs/protocol/pon-nakamoto-v1/details/REMOTE_SYNC_W1_HOST_GUARD.md',[(8,25),(129,166)]),
 ('docs/protocol/pon-nakamoto-v1/details/PUBLIC_POOL_INTAKE_V3.md',[(1061,1085)]),
 ('docs/protocol/pon-nakamoto-v1/details/HISTORY_W1_SHARED_CPU_HOST_20261027.md',[(1,7),(25,54)]),
 ('docs/protocol/pon-nakamoto-v1/details/W1_P0_P1_STRICT_INTEGRATION_20261027.md',[(1,8),(15,42)]),
 ('trillionnium/crates/trnm-pon-node/src/ingress/history_import_tests.rs',[(259,329),(333,457),(460,561)])]
outputs.append(write('original-controls-and-design-excerpts.txt',excerpts(docspecs)))
hostpath='trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs'
outputs.append(write('host-check-operation-excerpts.txt',excerpts([(hostpath,[(120,375),(513,573)])])))
def ms(x):return format(x/1000000,'.3f')
lines=['# R1 原报告 CPU 小表','',
'所有 CPU 数值由已封原字段转换为毫秒。不同列有嵌套或不同终止边界，不是可相加的“四秒总 CPU”；详见 summary.json 和下面范围说明。','',
'|来源|阶段|攻击线程合计|reader|Submit 客户端|History 客户端|独立 replay + confirmation|server mutation charged|其中 server full W1|',
'|---|---|---:|---:|---:|---:|---:|---:|---:|']
for r in dist['rows']:
    m=r['service_cpu_fields']
    vals=[r['attacker_workers_cpu_ns'],r['reader_cpu_ns'],r['honest_submit_calls']['client_cpu']['known_sum_ns'],r['honest_history_calls']['client_cpu']['known_sum_ns'],r['independent_replay_and_confirmation_cpu_ns'],m['mutation_cpu_charged_ns'],m['mutation_full_work_cpu_ns']]
    lines.append('|'+r['mode']+'/'+r['variant']+'|'+r['phase']+'|'+'|'.join(ms(v)for v in vals)+'|')
lines+=['','## 压力攻击线程分解','',
'|来源|实际 calls（每 worker 范围）|whole worker CPU|call.client_thread_cpu_ns 合计|solution_search_thread_cpu_ns 已知合计 / 未知项|solution_trials|fresh attacker_cpu_ns|未独立分解残差|',
'|---|---|---:|---:|---:|---:|---:|---:|']
for r in attack['rows']:
    search=r['metrics.solution_search_thread_cpu_ns'];con=r['from_zero_construction']['attacker_cpu_ns']
    vals=[r['mode']+'/'+r['variant'],str(r['calls_total'])+' ('+str(r['calls_per_worker_min'])+'–'+str(r['calls_per_worker_max'])+')',ms(r['attacker_workers_cpu_ns']),ms(r['call.client_thread_cpu_ns']['known_sum']),ms(search['known_sum'])+' / '+str(search['null_or_missing_count']),str(r['metrics.solution_trials']['known_sum']),ms(con['known_sum'])if r['variant']=='fresh'else'不适用',ms(r['residual_after_client_and_construction_cpu_ns'])]
    lines.append('|'+'|'.join(vals)+'|')
lines+=['','## 范围与不能相加的关系','',
'- 攻击 whole worker CPU 包括 prepare/clone 或 fresh 构造、所有 client call、调用后诊断转换、compact_pressure_call 序列化及哈希、循环和记录。原包构造在 original 模式阶段前，fresh 构造在 worker 循环内。残差不是“纯 JSON 成本”。',
'- client_thread_cpu_ns 在身份派生前开始、结果诊断 JSON 转换前结束；solution_search_thread_cpu_ns 是其内部子区间。未知值保留未知，未补零。fresh attacker_cpu_ns 已包含在 whole worker CPU 内。',
'- 部分攻击调用和清理延伸到约 4.09 秒；reader 持续到原窗口；service 在 drain/shutdown 后取得。不能把这些合计除以四秒或以 0.25 CPU 供给解释为精确占比。',
'- independent_replay_and_confirmation_cpu_ns 包含 History RPC、replay、确认和记录；各 replay 和最后确认是内部子范围。server full W1 是 mutation charged 的内部子范围；body/response CPU 也嵌套其中。',
'- scalar 账本 initial credit=2 秒 CPU、refill=250ms CPU/s、reserve=100ms CPU、worker limit=2 是原账户策略，不是物理 CPU 配额测量。所有八阶段 mutation CPU refusal=0；这不能证明没有物理竞争。',
'- PQ authentication CPU=0 仅说明该 PQ 计量字段；它不证明经典 reactor authentication CPU 为零。',
'- cpu.stat 前后值覆盖整个 original+fresh 子命令及其源校验，不能分配给单次四秒 phase、某次 replay 或某个函数。',
'- 每个 worker 的原纳秒数、calls 与字段完整指针保存在 cpu-phases.json 和 attacker-cpu.json；完整旧派生原件保持不变。','']
outputs.append(write('cpu-tables.md','\n'.join(lines)))
review='''# R1 W1 fresh-service：只读因果与 Host 合同闭合

## 当前结论

这两项 R1 hosted job 的业务门禁真实失败。两份 original 原 Rust test 返回 0，但报告未达到原窗口的独立六深度确认，wrapper 报 CONFIRMATION_TARGET；两份 fresh test 在保留原四秒/六深度断言处返回 101。四份 baseline 都完成，四份 pressure 都收到 7 个诚实 Submit ACK，最后一次独立 History replay 均拒绝 PUBLIC_REQUEST_DEADLINE。ACK 不能代替独立确认。

没有新增测试、native/Host 运行、采样、网络下载、源或 Git/ref 修改、stage 修改。本目录只封存既有原报告的读后归纳。尚无经过测量足以修复四秒结果的安全优化方案，也没有实现性能修改。

## 实际两条路径的区别

实际 fixture 绑定 127.0.0.1:0。Public V3 listener 按真实 local_addr 调 require_for_listener；对 loopback 返回 None，所以这次服务端 kernel_for_worker 和条件 50ms reactor Host verify 都没有运行。外层 hosted controller 的固定 cgroup 和原有限资源仍真实生效；不能将“外层限额生效”写成“loopback listener 内部持有 Some HostKernelBudget”。

普通服务端 full W1 仍有任务存活、账户 CPU checkpoint 等检查；该 ordinary checkpoint 的 resource callback 为空。严格 public History 入口则无论 source 是否 loopback，显式要求固定 Host parent。其 W1 进度 control 每次按原 absolute deadline → fresh resource → 同一 deadline 检查。实际独立 replay 是 Owner::Exclusive，没有共享 Node owner-wait，未启用另一条 wait 分支。

完整 W1 实际 1099 个边界检查不能等同 policy.id 调用次数，也不能套到提前中断的 replay。两个 original pressure 完整首包中，W1 calling-thread CPU 为 81.728/80.844ms，嵌套 Host CPU 为 78.012/77.032ms。baseline server 七包 full-W1 CPU 合计约 10.24–10.38ms，而七次严格 History replay 总线程 CPU 约 555–571ms。这些不是等价检查合同的速度比较，不能据此移除 History 检查。

## 当前合同及原控制依据

REMOTE_SYNC_W1_HOST_GUARD.md 的 Current API boundary 明示四个 exported public History 入口即使 loopback 也要求固定 Host。理由是 loopback locator 不证明来源，代理可携带远端不可信 proof；普通本地 serving 保留单独的开发兼容合同。PUBLIC_POOL_INTAKE_V3.md 的 listener 段与实际 None 选择一致。

当前 history_import_tests 的原控制明确要求每个真实 W1/native 边界检查一次，并覆盖原始非抽样边界上的 Host 变更拒绝、原 deadline 优先、错误保留、失败后重试。它们是源码审阅引用，不是本轮新运行的测试。

旧文档中“bounded cadence”及“每64 tile”是保留的历史候选叙述；当前 API 段已经警告旧例外不描述现有 public surface。不能用历史措辞替换当前每边界的语义。对应完整原选段见 original-controls-and-design-excerpts.txt。

## Host 每次成功检查的源级成本

checked_parent 的成功短文本路径有 8 次 fresh open（boot、parent、当前线程 membership、五个 limit），6 次 FD metadata、一次末尾 parent 路径 metadata、7 个完整 EOF 文本流/UTF-8 校验、4 个 u64 解析。以上是源码级成功操作计数。短读/EINTR/系统实现会改变实际 syscall 数；“各文件一次 payload read 加一次 EOF，共14次 read”仅是条件示例，绝非已测值。

短文本快速路径已使用 stack/Cow、held-parent-relative openat 和不可变身份。源码没有该路径上的 BTreeMap 计数解析或重复路径拼接，也没有可证明多余的相邻 Host callback。显式项目级短路径堆分配为零，不推断标准库内部零分配；较长 boot/membership 保留原同 FD 堆回退。

boot、parent 前身份、当次线程 membership、五个新鲜 limit、EOF/UTF-8/regular-file、parent 后身份和最终 limits 等价各自具有独立拒绝作用。前后 metadata fence 时间不同，不能合并。这里没有重复的 descriptor/source framing 哈希可安全删除，也没有可量化收益的 parser 替代已获证明。

## CPU 证据的范围

cpu-tables.md 给出八个 phase 与四组攻击线程分解。攻击 whole-worker CPU 约351–382ms；client-call 合计约187–298ms，包含 solution-search 已知约9–14ms；fresh 构造另约95ms，其中 packet encoding 约77ms。这些是嵌套计量，不可再相加。记录/转换/clone/循环等残差约70–85ms，未被单独测成纯 JSON。

各段 wall/CPU 来自不同 clock 和结束边界，某些调用延伸到原四秒后，service 包含 drain；不能拼成严格四秒 CPU 饼图。whole-child cpu.stat 证明该完整子命令存在节流，却无法把其全部节流时间归因给某次 W1。原报告缺少逐 syscall、parser、scheduler 或 classic reactor auth 的专用观测。

当前 first durable begin 约0.6–1.4ms，不能把旧 C0 的95ms样本继承为这次原因。大 wall 与小 calling-thread CPU 的差额本身也不能把 CFS 定为唯一原因。保留原 CPU 账户、refill、paid settlement、冷启动和全部检查。

## 处置

继续保留原四秒、16 worker、两秒 RPC、七包/六深度、原 absolute deadline 和所有 fresh Host/工作/签名验证。R1 中已有 PublicPolicy immutable-prefix cache，但本轮失败不支持宣称它已修复业务门禁。停止无证据的小哈希、降频或缓存 OS verdict 方案；不将本诊断或组件 PASS 升格为 hosted qualification。

summary.json 是当前紧凑事实；source-and-evidence-refs.json 给出固定 Git blob 与完整证据 pins；两份 excerpt 文件和 host-check-operation-excerpts.txt 供直接复审。所有新单文件均小于64KiB。大型原 ZIP/report 只引用，不重复复制。
'''
outputs.append(write('review.md',review))
# Pin existing input/source captures; no raw large report or ZIP is duplicated here.
refs={'schema':'trnm-r1-w1-causal-readonly-reference-roster-v1','source':draft['source'],'immutable_sources':normalized,'prior_large_report_references':[{k:r[k] for k in ('mode','variant','original_zip','zip_sha256','member','report_bytes','report_sha256')}for r in dist['rows']if r['phase_index']==1],
      'prior_outer_job_evidence':static['outer_job_evidence'],'input_files':list(inputs.values()),'new_controls_executed':False,'new_profile_executed':False}
outputs.append(write('source-and-evidence-refs.json',enc(refs)))
# A final per-file fence protects the closed captures read above, not unrelated paths.
for p,pin in list(inputs.items()):read(p,pin['sha256'],pin['bytes'])
for o in outputs:
    raw=read(o['path'],o['sha256'],o['bytes'],65536)
    if len(raw)>65536:raise RuntimeError('output cap')
pin=write('OUTPUT_INDEX.json',enc({'schema':'trnm-r1-causal-closure-output-index-v1','files':outputs,'file_count':len(outputs),'total_bytes':sum(x['bytes']for x in outputs),'source_inputs_stable':True,'no_runtime_or_tests_executed':True}))
print(json.dumps({'status':'CLOSED_READONLY_OUTPUTS_WRITTEN','directory':str(OUT),'index':pin,'files':outputs,'file_count_excluding_index':len(outputs),'total_bytes_excluding_index':sum(x['bytes']for x in outputs)},ensure_ascii=False))
