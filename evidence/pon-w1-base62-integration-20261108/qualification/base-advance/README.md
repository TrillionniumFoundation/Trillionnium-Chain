# Base62 前进的只读审查

这是 C6 整合之前的历史原始记录。新 base 62d2d90c9e1f4c8450c89843f1e08360a24283ce 是旧 base cb314bb4656e5da4844325cd83994ab4764fe8e9 的直接子提交，改动共享 store.rs、legacy reorg 测试及两个精确 pin 文件，并非仅文档变化。

原 git merge-tree 实际 exit 1，workflow 与 PQ corpus 共两个文件存在冲突。产生的 1b74d8046125d3fc23d9849af0046feb090a716d 是含冲突标记的树对象，不是合并资格。彼时实际 PR merge ref 仍为旧 base 与 C5 的 991168a…；这是有时间范围的历史观察，不能当成当前远端状态。

本审查只读取提交、patch、父关系和远端身份，未 merge/rebase、改源码、运行测试、启动 operation 或 push。随后 C6 的实际整合与重新资格单独记录。

raw-logs.tar.gz 保留原始 command JSONL 与权威 job statuses；raw-output-index.json 逐输出绑定大小和 SHA256。原始 JSONL 保留完整整数时间戳，不使用重新序列化后的时间值替代原件。manifest.json 绑定本目录除它自身之外的文件。
