# 908 分支交付补充：PR 盘点与当前整合状态

主账和原 ZIP 保持原字节不变。本附录绑定 current-source-overlay-v1.json 的5c04c60e463462d9df8884786e0d5bb32af08a64 / tree8f26631e80c14a3c750210019606df13327d633f。表内明确列出的60个移植提交全部在该提交祖先中，T03 898532亦已实际合入；这不是用祖先关系证明历史功能等价，也不是测试总数。

## 开放 PR

协调者 GraphQL 完整分页于2026-11-14 04:50:42.630337–04:52:21.898537 UTC取得579个open PR：569 draft、10 non-draft；80以main为base、499以其它分支为base；579个head均来自同一仓库。每页totalCount均为579，但分页不是原子快照。

固定normalized清单SHA256：5a0ad93370510112238f2a0a7870f03f9018b9486f63abceaa6c265bb728daaf。另一次GitHub插件只读REST分页取得相同579个编号；按head SHA、head ref、base名称、draft和head仓库逐项比对，差异数为0。与remote0170的head名称→SHA映射差异数为0。PR的base提交字段不代替实际git ref读回；额外只读main和candidate仍分别为dd6e1c3c…与e40d7071…。

## 解释与执行边界

579个PR不代表579份待逐头覆盖安装的当前实现。各分支的功能取舍仍由908主账和296终端分表决定，原草稿、依赖PR和不同base关系保留为发布计划输入。清理前仍需刷新完整refs与每个预期SHA，验证新归档、受保护main的实际集成和原required head/prospective CI；保护侧分支禁止删除的实际规则不因盘点而改变。原4秒失败未由本附录消除。未做远端写、未重复native测试。
