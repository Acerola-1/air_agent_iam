# 后台交互约定

本文件记录UI后果；授权规则以`openspec/changes/add-tenant-resource-entitlements/design.md`及`http-contract.md`为准。视觉见[DESIGN.md](DESIGN.md)。

| 能力 | 统一拥有者 | 变体与验证 |
|---|---|---|
| Select/Listbox | Element Plus ElSelect | 单选/多选、中文标签、键盘；机器权限从明确目标企业的有效选项选择 |
| Form | ElForm、useWriteScope | 打开时固定会话上下文；切账号/企业/代次后关闭旧表单；失败保留有效输入 |
| Toast | ElMessage、ElAlert | 成功说明实际变化，关键失败内联保留，409不重放写操作 |
| CRUD | 当前列表、TenantEntitlementDialog | 保存后刷新所属列表；开通目标取明确企业，不借操作者当前企业推导 |
| Dataset navigation | usePagedList、CursorPager | 服务端游标；会话/目标变化重新加载，迟到结果丢弃 |
| Scrollbar | 浏览器与Element Plus表格 | 表格自身横向滚动，不隐藏滚动条或锁死共享主区域 |

平台“资源开通”与企业只读“企业资源”分开。开通不自动赋予主体读取权；回收确认说明目标和影响。角色编辑保留并展示既有失效配置，可显式取消，不能把不可新增码复制给另一目标。

401要求重新登录，403说明无权，409要求刷新上下文或修订，503说明服务暂不可用。没有完整响应的保存不能显示成功或自动重试。弹窗支持Tab、Escape及窄屏；权限变更使用应用确认框。
