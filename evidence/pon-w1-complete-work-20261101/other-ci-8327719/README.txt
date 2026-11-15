8327719 其他 CI 失败证据包

五个 retained-artifact-<id>-contents.tar.xz 无损保留原 GitHub ZIP 的全部文件成员；
每个文件的 SHA256、大小、ZIP CRC、原 ZIP 摘要与大小，以及重新打开验证的结果，
都在 RETAINED_CAPTURE_INDEX.json。原 ZIP 容器不重复收入公开包。

完整失败 job 日志、Actions 元数据、原生报告、二进制和数据库均保留。
原 artifact 的每个成员都未删减、重写或脱敏；全部成员通过已列出的凭据模式扫描。
未保存连接器临时下载 URL、物化 URL 或下载凭据。本目录不含任何传输请求收据。

triage-report.json 是只读分析；conclusion.zh.txt 是结论。
source/ 保存 8327719 的精确 Python 阅读器及依赖，用于报告复算。
如需复算，先将五个 tar.xz 分别解到 artifacts/<artifact-id>/，
再运行 python3 analyze.py。分析脚本只读 artifact，并写本地 triage-report.json。
其中一个结果对比只归一化本地输入文件路径；其余字段需精确相同。

失败仍是失败。这里没有新的原生验证执行、跨 Host 性能因果证明、难度成本证明或资格通过。
所有原始 deadline、预算、确认分母及服务条件保留。先读具体条件，不从 workflow 名称推断历史。
