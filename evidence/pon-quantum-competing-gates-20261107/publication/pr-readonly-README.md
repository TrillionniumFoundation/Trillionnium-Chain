## 只读 PR 定位诊断

本轮已推送分支 `fix/chain-quantum-closure-api-20261107-c9b4`，GraphQL ref 读回的提交为 `a56889a54aac5f14141bb45fb602141dd6a37645`。此前创建 draft PR 返回 HTTP 422，并明确声称该 head 已有 PR。

本轮只读检查中，精确 head 的 gh/REST/GraphQL 查询、已知提交及 ref 的关联 PR、指定 base 查询和标题搜索都未返回可读的匹配 PR。最近 100 个 PR 的有限检查也未发现本轮分支。当前证据不足以给出 PR 编号、URL、draft 或 state；不能用其他相似 PR 代替。

最后一项 pull-ref 查询发生网络 i/o timeout，exit 1；其 stdout/stderr 和进程状态原样保留。其余六项 GitHub 只读查询 exit 0、stderr 为空。没有再次 POST、修改 PR、remote 或配置。没有采集或打包 GET user profile。diagnostics.json 中仅含相关 GitHub 查询返回值及耐久进程收据，GraphQL 曾返回公开 login ProfHepta。

先前 422 原始响应仍在相邻 pr-a568-reconciliation/4-response.json；本目录仅引用其路径和 SHA-256。空结果与 422 的不一致被保留为未解决观察，不推断其服务端原因。
