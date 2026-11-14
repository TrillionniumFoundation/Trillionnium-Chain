# C0 cross-cost 完整原件归档清单

本清单固定 run43567821538 / attempt1 / source dc42ce4df5cff79cc61c5addbaf01074b56b06ca，供后续独立 execution archive 保存；这里只封清单，没有复制进 Git 或发布任何 refs。

两份原始 ZIP 现在均已与初始 GitHub API size/SHA256 完全相符，并分别验证161个member的全部解压字节、长度、CRC32和SHA256。先前9个关键member和最初partial前缀与完整ZIP一致。原诊断摘要封存时 whole_zip_verified=false 的字节完全保留；completion-overlay.json 仅追加之后完成的事实。

清单包含2个完整ZIP、2个完整member index、两份完整cost job原log、既有因果review、完整分页的PR847/run只读刷新、及新找到的Host聚合原件。原provider signed URL、HTTP重定向头、认证debug和网络私有stderr均不纳入。保留的小失败receipt仅含公开命令、size/SHA/返回码；原范围和私有失败数据仍留原目录，没有覆盖。

额外原件证实整个 native child command 的cgroup cpu.stat计数存在；producer inside() 在完整run_from_zero_native.py前后采集。它们不能提供某一次4s phase或1.797s Work的kernel时间分解。未发现逐work/phase的cpu.stat序列、syscall或off-CPU原始追踪。原strict runner仍CONFIRMATION_TARGET；x64 replay1record/0accepted、arm5records/4accepted。五个Rust不变量测试通过不等于业务目标通过。

PR刷新是08:28:55.373552至08:29:25.519741 UTC的非原子分页观察：PR仍draft/blocked，head dc42、base dd6e；run仍in_progress，19jobs=7success/7failure/5running；head165checks=126success/31failure/5running/3skipped。此处不声称运行已终止，也不预判后续head。

新增prospective protocol日志、新M4诊断及未来修复/测试未包含，需另封实际完成凭据。没有native、dispatch、cancel、PR修改或remote写入。
