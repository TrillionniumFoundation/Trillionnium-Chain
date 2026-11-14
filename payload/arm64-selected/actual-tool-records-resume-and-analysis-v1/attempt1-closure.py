import hashlib,json,os,stat,sys
from pathlib import Path
values,scripts=json.loads(sys.argv[1])
base=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1')
out=base/'actual-tool-records-v1';out.mkdir(mode=0o700)
def put(p,b):
 with p.open('xb')as f:f.write(b)
 if p.read_bytes()!=b:raise ValueError('READBACK')
 return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def putj(p,v):return put(p,(json.dumps(v,sort_keys=True,indent=2)+'\n').encode())
files=[]
for name,value in values.items():files.append(putj(out/name,value))
for name,value in scripts.items():files.append(put(out/name,value.encode()))
index=putj(out/'EVIDENCE_INDEX.json',{'schema':'trnm-H5DF-arm-actual-tool-record-index-v1','files':files,'count':len(files),'self_excluded':True,'original_tool_responses_not_synthesized':True,'target_reexecution':False})
review=base/'attempt1-review-v1';review.mkdir(mode=0o700)
facts={'schema':'trnm-H5DF-arm-cost-attempt1-bounded-review-v1','status':'INNER_CAUSE_UNKNOWN_ACQUISITION_HOLD','head':'5df7ae6f482157c5f7fdcbcd52222117a965053f','tree':'6be4940d38cc88782657f2684cbefe48866f8b9f','run_id':43621754143,'run_attempt':1,'job_id':132528769087,'artifact_id':14124468052,'artifact_declared_bytes':9909858,'artifact_declared_sha256':'3b093c989b92fb7d657195826ae6faed9e641840dbe8f48c7721aebcf7804d7d','outer_job_status':'failure','source_before_after_exact':True,'host_controller':{'systemd_run_exit':1,'failure':None,'final_host_errors':[],'native_build_exit':0,'native_build_wall_seconds':236.352278583},'directory':{'metadata_GET_exit':0,'tail_GET_exit':0,'status':206,'range':'bytes 9844301-9909857/9909858','tail_bytes':65557,'actual_entries':161,'central_directory_offset':9894647,'central_directory_bytes':15189},'selected_attempt':{'actual_GETs':1,'remaining_ranges_not_requested':7,'range':'bytes=1390399-1391464','gh_exit':1,'error':'GH_GET_NONZERO','http_status':None,'stdout_bytes':0,'stderr_bytes':151,'stderr_sha256':'6a34549a398e4e1f1561ae0ef4974af1f30ee9e14bea907a56f6b70c88860859','stderr_raw_preserved':False,'stderr_raw_policy':'reviewed original helper preserves count/hash only to avoid signed URL/auth/header disclosure','selected_members_obtained':0,'per_GET_seconds':180,'combined_elapsed_seconds':134.283419,'original_combined_budget_seconds':900,'deadline_reset':False,'automatic_retry':False},'facts_not_established':{'five_native_selectors_exits':'UNKNOWN','manifest_failure':'UNKNOWN','confirmation_error':'UNKNOWN','baseline_pressure_timing':'UNKNOWN','per_phase_CPU_Host_checkpoints':'UNKNOWN','whole_artifact_SHA_verified':False,'selected_member_CRC_verified':False,'whole_artifact_member_CRC_verified':False},'boundaries':['Do not inherit x64 failure cause','No whole ZIP, ELF or SQLite acquired','No native, build, probe, source/ref/config/stage mutation','Original failed attempt kept; no retry was started'],'references':{'outer_summary':{'path':'/private/tmp/chain-H5DF-arm64-cross-cost-original-evidence-20261114-v1/outer-analysis-v1/summary.json','bytes':9393,'sha256':'696ac99d76571c92097e068f696d0095a0f00cadd51a0a3824fec22c37b1a414'},'directory_summary':{'path':str(base/'directory-v1/summary.json'),'bytes':6078,'sha256':'71d2ba7895fd2c00303255fbddcd665de79a861aa96b5e4e5646ad6a478587c3'},'selected_summary':{'path':str(base/'selected-v1/summary.json'),'bytes':3669,'sha256':'c90c5d78f244e73c7e513186bced2fc1475a5905ce994c2e339cbac6bb5c522b'},'actual_tool_records':index},'actual_selected_terminal':{'session_id':'dpty-6c8a5d24a6ed6b321d48fdf0c0fd04db36d0762c12ff239ba6f0b67b5b6426d9','exit_code':1,'output_complete':True,'bytes':1082,'sha256':'fe3017f2c61a1915ae9d38164f125d96eaaf6928e59c83ab776732c6dde6fa74'}}
for row in facts['references'].values():
 p=Path(row['path']);b=p.read_bytes()
 if len(b)!=row['bytes']or hashlib.sha256(b).hexdigest()!=row['sha256']:raise ValueError('REFERENCE_PIN')
fp=putj(review/'review.json',facts)
text='''# H5DF ARM64：第一次有界取证结果

本次固定 run 43621754143 / job 132528769087 / artifact 14124468052。外层原始日志确认源码前后 H5DF / tree 6be4940d38cc88782657f2684cbefe48866f8b9f 一致，Host 准备及原构建成功，内部 systemd 命令退出 1；failure=null、final_host_errors=[] 不解释内部业务原因。

目录获取成功：精确正范围返回 206，完整 ZIP 目录含 161 项。整包 SHA 与所有成员 CRC 均未验证。随后原计划中的首个成员范围 GET 退出 1，没有 HTTP 状态或正文；后面七项未请求。既审 helper 仅保存该 stderr 的 151 字节计数及 SHA，不保存可能包含临时 URL 的原文本，因此不能从这份回执确定具体网络错误串。真实 owner 终态 exit 1 / 完整 EOF 已原样保留。

没有取得任何所选成员。五个原 native controls、业务 failure、baseline/pressure 时序和 CPU/Host 指标仍为 UNKNOWN。不得把 x64 的 CONFIRMATION_TARGET 继承为 ARM64 原因。原失败输出不被修改；没有自动重试、整包/ELF/SQLite下载或任何测试、构建、probe、源码/ref/config/stage 写入。

这份文档仅闭合第一次目录＋成员读取尝试；如 root 后续明确批准独立再次读取，必须使用新的输出目录与真实回执，不能回写本次结果。
'''
rp=put(review/'README.md',text.encode())
print(json.dumps({'status':facts['status'],'review':fp,'README':rp,'actual_records_index':index},sort_keys=True))
