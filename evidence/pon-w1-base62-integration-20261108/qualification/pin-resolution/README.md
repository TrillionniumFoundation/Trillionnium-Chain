# Base62 冲突解决与提交前 pin 控制

本包保留 C5 与 base62 的隔离整合工作树中，两文件三处 pin 冲突解决及其实际检查。workflow 仅更新 store.rs pin；PQ corpus 相对 C5 仅更新 workflow、store.rs 和 legacy reorg 测试三个 pin。全部 645 个 pin 键与其它 corpus 字段保留，C5 新增 W1 profile pin 未删除。

实际 preflight、diff --check、CI contract 和 PQ checker 均 exit 0；PQ checker 继续返回 HOLD_NO_GO。InlineSourcePinTests 3 项与 W1PostwinLaneTests 10 项共 13/13 通过；PQ 负控 39/39 通过，均无 skip。

这些是提交前的 52 个控制方法。执行时 HEAD 仍为 C5，MERGE_HEAD 为 base62，合并尚未提交；因此不计入 C6 冻结后重新资格的分母。复核代理未提交、push、改运行时源码或计划文档；最终 C6 提交及精确资格由 root 另行完成。

raw-logs.tar.gz 保留原始 stdout/stderr、逐命令记录、resolution、窄 diff 与权威 job status。逐命令输出从原 validation 原件提取，已核对原大小及 SHA256；raw-output-index.json 逐输出绑定。没有 ELF、SQLite、完整 state 或环境 dump。manifest.json 绑定本目录除它自身之外的文件。
