# H5DF ARM64：第一次有界取证结果

本次固定 run 43621754143 / job 132528769087 / artifact 14124468052。外层原始日志确认源码前后 H5DF / tree 6be4940d38cc88782657f2684cbefe48866f8b9f 一致，Host 准备及原构建成功，内部 systemd 命令退出 1；failure=null、final_host_errors=[] 不解释内部业务原因。

目录获取成功：精确正范围返回 206，完整 ZIP 目录含 161 项。整包 SHA 与所有成员 CRC 均未验证。随后原计划中的首个成员范围 GET 退出 1，没有 HTTP 状态或正文；后面七项未请求。既审 helper 仅保存该 stderr 的 151 字节计数及 SHA，不保存可能包含临时 URL 的原文本，因此不能从这份回执确定具体网络错误串。真实 owner 终态 exit 1 / 完整 EOF 已原样保留。

没有取得任何所选成员。五个原 native controls、业务 failure、baseline/pressure 时序和 CPU/Host 指标仍为 UNKNOWN。不得把 x64 的 CONFIRMATION_TARGET 继承为 ARM64 原因。原失败输出不被修改；没有自动重试、整包/ELF/SQLite下载或任何测试、构建、probe、源码/ref/config/stage 写入。

这份文档仅闭合第一次目录＋成员读取尝试；如 root 后续明确批准独立再次读取，必须使用新的输出目录与真实回执，不能回写本次结果。
