# Postcommit receipt manifest v1

这是供 root 审阅的后续保存准备清单。只创建本目录清单与 README；原始 payload 仍在精确 source_path，未复制、未新打包，未写 Git/remote，未改候选或排队状态。

固定候选参考：dc42ce4df5cff79cc61c5addbaf01074b56b06ca。此任务不重新查询其 Git 身份；沿用 root 已提供的固定身份。显式纳入请求中的 318527 原失败，以保留真实修复前历史。

## 实际找到并冻结的文件

共 258 个文件，21635495 B，78 个不同 SHA256；29 个已有固定 SHA 全部对照。

| 组 | 文件数 | bytes | 原状态 / 范围 |
| --- | ---: | ---: | --- |
| 01-original-318527-seven-gate-failure | 17 | 12623 | failed_original |
| 02-raw-receipt-representation-repair | 10 | 5513 | completed_representation_only |
| 03-doc-318527-335blob-receipts | 2 | 94910 | completed_prior_scan |
| 04-dc42-single-index-receipts | 2 | 69363 | completed_prior_incremental_scan |
| 05-v3-original-37-step-run | 79 | 197659 | terminated_before_atomic_push |
| 06-v3-no-publication-reconciliation | 7 | 132813 | confirmed-no-publication |
| 07-v4-unknown-original-45-step-run | 101 | 1340596 | UNKNOWN |
| 08-v4-independent-prci-review | 7 | 108466 | completed_static_and_pure_controls |
| 09-v4-ci-minimal-patch-review | 2 | 4905 | completed_static_review |
| 10-e40d-complete-two-original-artifact-zips | 6 | 19365229 | complete_original_failed_hosted_run_evidence |
| 11-e40d-to-318527-causal-review | 5 | 150397 | completed_readonly_review |
| 12-protected-merge-cleanup-design | 2 | 129577 | completed_design_no_execution |
| 13-dc42-seven-gate-dependency-closure | 17 | 12864 | passed_original_local_source_gates |
| 14-original-seven-gate-producer | 1 | 10580 | fixed_producer_source |

逐文件 source host/path、建议未来归档相对路径、大小、SHA256、读取观察时间、原 stat 和 scope 均在 postcommit-receipt-manifest-v1.json。其 SHA256 为 1662d4cf9e40a47f8faf6dc85df4540d2dc26c8825b525c490fc90f9b5a4fd14。

## 原始状态保持

- 318527 原七 gate 保留 repository-check exit2；14 outputs 和前后两份 source receipt 全部在清单。
- rawrename 仅表示原 0B 网络回执的文件名/index 修复，不修改原 payload。dc42 原已完成七 gate 的17文件与原producer作为出版receipt引用闭合另列；没有重跑。
- v3 保留原37steps、原脚本、74outputs与后来 confirmed-no-publication 的独立核对；未到 atomic-publish。
- v4 原 summary 保持 UNKNOWN，push_exit=124、archive_remote_verified=false；45steps、90outputs、两份0B atomic流、hook/expected、archive/spec/source前后都保留，不能写成成功。
- 两e40d完整ZIP是原失败 hosted run 的完整证据，不是新candidate执行。只选full-v2两ZIP/各index/completion审阅6件，不纳signedURL headers、range分块或auth调试。
- 架构因果review保持 sealed_at=2026-11-14T05:56:41.688542+00:00；4outputs+index。merge/cleanup仅设计，未发生真实hook、push、merge、delete。

## 读取检查与局限

逐文件通过普通文件检查、读取前后 fstat 和最终 stat；独立文件快照不是全目录原子快照。原318527/dc42的14+14输出、v3的74输出、v4的90输出只做已有receipt SHA对照，共192原始流；没有再次执行任何gate。
当前 missing_files=0，issues=0，ready_for_root_review=true。
只有文件的实际读取观察时间与原summary明确时间被记录。mtime不冒充执行时间；summary写下的UNKNOWN/失败没有被归一化为成功。

## 明确排除

- all active or future diagnostic runs, dry-run/Trace2 preparations and results：outside fixed completed scope; append a new version only after authoritative completion。
- new ROG validation or future actual publication/merge/delete results：not completed observations in this manifest; UNKNOWN is not upgraded。
- signed download URLs, download response headers, authentication diagnostics, credentials：explicitly excluded; no such transport/auth file selected。
- e40d partial ZIPs and transport range/part files：only two completed full-v2 ZIPs, their indexes and completion review/summary selected。
- live-status snapshots publication-live-status-0246-v1.json / publication-v4-live-status-0253-v1.json：completed original run/reconciliation receipts selected instead; live snapshots not completion evidence。
- new Git tag/commit/ref or modified candidate：this preparation performs no Git/remote writes; actual execution custody must be separate。
- new scan/fsck/native results or recursive ZIP content inspection：not performed; existing completed receipt packages are hashed as bytes only。

## 后续保存方式

Root 逐项审阅后，实际组装时按清单精确 source_path 重读并核大小/SHA，再复制到 proposed_archive_path。不得以目录glob补进后来文件。若源文件改变或缺失，保留本清单并追加更正，不覆盖旧失败。
清单、README及后来execution tag自身对象不包含在较早scan/fsck/归档/运行证明内；后来真正publish结果、diagnostic、ROG结果必须另加完成后的overlay。
