# I1a 首次交付独立评估：mimo 2.6 pro

日期：2026-10-16（Asia/Shanghai）。本报告固定首次交付成绩，后续协调者修复不回填。

## 判定与评分

**未通过，需修复。诊断分 43/100。** 存在运行中合成管理员凭据进入可提交源码、旧企业上下文写入新企业、重要授权流程无法完成及交付完成声明缺乏对应实证等门槛问题。不是生产放行结论。

| 维度 | 分数 | 依据 |
|---|---:|---|
| 契约正确性与业务可用 | 14/30 | 有资源登记、开通、机器权限实时求交、回收恢复；首次成员授权断点、混合权限误拒、平台开通页面缺失、分页漏项 |
| 权限和数据边界 | 11/25 | 同修订并发、回收、旧引用ABA、审计回滚、依赖失败关闭正向成立；旧上下文与企业修订未接入资源授权入口，企业RLS可DELETE开通记录，凭据进入源码 |
| 测试与验证可信度 | 4/20 | 现有前端19项、契约40项及固定向量通过；新增资源测试仅assertNotNull，全量76项错误，作者多项PASS只有代码解释/截图，部分证据被秘密扫描覆盖 |
| 可维护性与项目契合 | 10/15 | 延续MVC/MyBatis、DTO/VO/DO及增量迁移；状态返回常量、异常细节外泄、N+1查询、历史注释与新行为不一致 |
| 范围控制与交付完整 | 4/10 | 保持IAM边界、未修改消费者；全部勾选与实际缺口不符，OpenAPI快照未扩展，运行/证据交接不足 |
| 合计 | **43/100** | 门槛未过，分数仅用于诊断 |

模型标签由用户在评审前提供，故本轮不是严格盲评；不猜供应商API版本。用户报告首次实施 **2小时16分钟/136分钟**，作为正式耗时来源。作者报告另写约4h+30min+15min+45min，口径冲突，保留来源，不相加、不替代用户实测。实施/等待/验证拆分、Token及工具次数未采集。

首次独立送审；模型后续修复轮数0。此前作者内部调试不算独立修复轮。2026-10-16用户追加授权协调者边验边改，后续成果归协调者，不给模型补发完成分。

## 输入与隔离

- 协议：`/Users/acerola/Dev/Python/air_agent/docs/flash-blind-evaluation.md`；历史评分表同仓库`docs/reviews/anonymous-model-scorecard.md`。
- Change：`openspec/changes/add-tenant-resource-entitlements/`的proposal/design/spec/http-contract/tasks/acceptance/implementation-goal。
- 实际dev@`8b40d702ca85798cb8f113202e240bcd0d62bb2d`，与规划HEAD一致；未提交改动包括新文件。基线迁移V19，候选V20/V21。
- 冻结：[input-manifest.json](evidence/run/i1a-independent-20261016/input-manifest.json)、[tracked diff](evidence/run/i1a-independent-20261016/candidate-tracked.patch)。私有源码副本保留原始新文件；公开证据仅存指纹，避免复制硬编码秘密。
- OCR预览43个可审文件全部审查；默认排除的测试、锁文件及规划报告另审；秘密文件只核对匹配/忽略状态，不回显内容。产品未补修时702项冻结文件指纹复核一致。
- 自有PG/Redis为`iam-i1a-review-x7h8-pg`/`iam-i1a-review-x7h8-redis`，回环49132/49179；候选49100，基线49102；库iam_review/iam_test/iam_baseline/iam_upgrade，资源记录见[resources.json](evidence/run/i1a-independent-20261016/resources.json)。作者391xx及既有191xx/291xx和共享数据未操作。

## 已复现的主要问题

1. **P1 凭据进入源码。** `web/e23-browser-test.cjs:25,83,105`的fallback口令与`.env.i1a`中实际运行管理员密码相同；`.env.i1a`未被Git忽略且权限0644。仅记录命中文件/字段/行号，未回显值。作者秘密扫描仅读取`.env.local`，不能证明本轮独立凭据零命中。[secret-scan.json](evidence/run/i1a-independent-20261016/secret-scan.json)
2. **P1 首次授权闭环不通。** A管理员有资源管理+角色写/成员写而没有air读码，创建资源角色201，但授给已有成员或建成员附该角色均403；`TenantAdminServiceImpl:695`仍用原权限全集子集判断。原方法未改并不免除本轮必须接通新资源授权的责任。资源+自身已有普通权限一起建角色也403，`RoleAdminServiceImpl:419`以整批allMatch判断导致误拒。[http-counterexamples.jsonl](evidence/run/i1a-independent-20261016/http-counterexamples.jsonl)
3. **P1 上下文与CAS缺失。** 角色、成员、服务账号DTO/服务未接入要求的资源写expected_context/expected_tenant_revision。携带A旧上下文的请求在切B后201，实际角色tenant_id=B；企业修订0也被忽略。新端点正确检查上下文不代表旧授权入口已覆盖。[http-followups.jsonl](evidence/run/i1a-independent-20261016/http-followups.jsonl)
4. **P1 全量回归被改坏。** 清洁同环境、补齐跨语言向量且启用测试限流后，基线81/81通过；候选82项中6通过、76错误。46个语法错误来自AdminApi/InternalClient/BrowserSession中的`iam.service_accounts, , iam.auth_sessions`；其余12个外键错误、18个最后管理员保护错误来自改坏的清理过程。新增ResourceAdminIntegrationTest只assertNotNull，不验证创建或授权。[baseline-test-summary.json](evidence/run/i1a-independent-20261016/baseline-test-summary.json)、[test-summary.json](evidence/run/i1a-independent-20261016/test-summary.json)
5. **P1 平台开通核心页面未实现。** API封装存在，但PlatformTenantsView没有开通入口或管理弹窗；真实浏览器只有原企业操作。E20不能完成。企业资源页用camelCase访问snake_case响应，编码、目录状态、时间为空。[browser-review.json](evidence/run/i1a-independent-20261016/browser-review.json)、[截图](evidence/run/i1a-independent-20261016/browser/tenant-resource-fields-blank.png)
6. **P1 企业开通RLS非只读。** V20 entitlements策略的USING允许本企业，WITH CHECK只限制INSERT/UPDATE；真实iam_app在A上下文DELETE本企业开通成功（探针回滚）。删除亦无对应修订/审计保障。未发现跨企业行泄露，不夸大为跨租户读取。[http-followups.jsonl](evidence/run/i1a-independent-20261016/http-followups.jsonl)
7. **P2 失效状态失真。** 回收后配置确实保留、实际机器权限为空，但RoleAdminServiceImpl:468将所有permission_states固定为configured/effective/grantable=true。旧角色编辑器未呈现失效叶子，无法可靠解释/显式移除隐藏配置。
8. **P2 分页漏项。** ResourceCatalogMapper.xml:35以code过滤，却按sort/code排序。limit=1只遍历出3项，而一次列表有6项。游标亦未绑定目标企业/过滤范围。
9. **P2 状态与响应契约缺口。** suspended企业新开通返回200/effective=true；同状态PUT没有changed=false字段；未知写字段被接受；不存在企业返回500；空权限元素返回500并回显Java类/方法细节。GlobalExceptionHandler把异常类和message直接交给客户端。
10. **P2 契约/报告与实证不一致。** OpenAPI快照无新resources/entitlements端点；新增Swagger声明不存在的bearer方案。作者E09只有重新开通200、E15只有锁函数描述、E16只有代码解释，不能代替旧引用/竞争/审计失败实测；baseline.txt及e01-e16证据现内容为秘密扫描，不能佐证所称17/17。任务全勾选与这些缺口矛盾。

## 独立验证与矩阵

有正对照的实际通过行为：目录登记/重复/坏码、开通不自动赋读码、企业管理员不能开通、布尔修订拒绝、未开通资源拒绝、机器精确air权限、回收配置保留及B不变、机器恢复、旧引用回收/ABA拒绝、永久凭据不复活、目录停用/恢复、权限停用求交、同revision并发200/409、审计故障全回滚、iam_app A隔离与回滚后无上下文、PG锁/Redis暂停503及恢复、浏览器登记刷新/CSRF/合法旧revision409。人类资源读取正例通过langgraph-runtime复核。

| 项目 | 独立状态 | 范围/缺口 |
|---|---|---|
| E01 | 部分 | 登记/重复/坏码通过；空元素和未知字段失败 |
| E02 | 部分 | 超管正例、企业管理员403；完整平台资格拆分矩阵未全跑 |
| E03 | 通过（采样） | A开通未给管理员读码；回收时B不变 |
| E04 | 失败 | 角色创建后授给成员403 |
| E05 | 失败 | 合法混合权限403；未开通负例通过，完整组合未覆盖 |
| E06 | 失败 | 成员附资源角色正常路径403；后续人类探针明确使用SQL夹具，不冒充公开授权流程成功 |
| E07 | 部分 | 人类runtime/机器、目录/权限求交成立；Cookie资源角色全链未完成 |
| E08 | 通过（采样） | 回收后机器失去读码、人类旧会话无效、配置/B不变 |
| E09 | 通过（采样） | 旧ref回收及ABA均拒绝，永久撤销凭据不复活 |
| E10 | 部分 | A/B受影响、机器失效恢复；无关联企业及异常缺开通行扇出未全覆盖 |
| E11 | 失败 | 保留旧码/拒绝搬运通过，状态和页面失效展示错误 |
| E12 | 部分 | 真API创建/签发/精确knowledge核验及错受众拒绝；页面资源选择未升级、上下文缺失 |
| E13 | 通过（采样） | 同机器令牌回收/恢复、永久撤销反例通过 |
| E14 | 部分 | 真实并发200/409；响应缺changed字段；首次缺行竞争未全跑 |
| E15 | 未验证完整 | 未以屏障跑三方竞争；作者代码解释不算通过 |
| E16 | 通过（采样） | 独立注入审计触发器失败，状态/修订/审计计数全回滚，随后解除 |
| E17 | 失败 | 真实受限角色跨企业写拒绝，但可DELETE自身开通；取消复用未全跑 |
| E18 | 通过（故障采样） | PG有界锁317.246ms 503、Redis暂停454.702ms 503；恢复正例成立 |
| E19 | 失败 | 分页漏项、未知字段、缺字段/目标404、状态处理不完整 |
| E20 | 失败 | 浏览器目录登记刷新成立；企业开通管理入口不存在 |
| E21 | 失败 | 企业资源字段空、失效角色呈现/资源选择未完成 |
| E22 | 失败 | 真CSRF拒绝成立，但A旧请求可写B；双标签迟到完整矩阵未完成 |
| E23 | 部分 | 桌面/390×844、Tab/Escape及刷新执行；不是完整交互矩阵或物理设备验收 |
| E24 | 未完整验证 | 作者只给内省，没有受控资源请求计数；独立消费者探针初次把service_account写成service，错误不扣产品分，初次文件保留；中断后服务需恢复 |
| E25 | 部分 | 空库启动、V19合成存量→V21、UUID/配置保留、重复0迁移通过；兼容拒绝回退演练未交付 |
| E26 | 失败 | 基线81全过/候选76错误；Vue19、build、契约40和bcrypt/rt-v1双向通过；秘密扫描失败，完整资源负载前后矩阵未闭合 |

检查文件详见同目录的http-counterexamples/http-followups/browser-review/migration-review/contract及cross-language记录。评审准备中的两项缺失向量、限流开关与少数探针状态码/受众/类型错误均单列保留，不算产品缺陷，最终后端数取清洁正确配置复跑。

## 性能、稳定性与效率分开

运行参考采样是平台空企业上下文、permissions=[]的人类内省，30预热，并发1/10/30各100×3；相同PG/Redis容器、JVM堆/池，两个数据库特性夹具不同，基线先、候选后，不是完整资源负载配对或因果性能回归证明。1800请求全部身份正确、0错误、无>500ms样本，失败未剔除。

| 版本 | 并发 | P50 ms | P95 ms | P99 ms |
|---|---:|---:|---:|---:|
| V19基线 | 1 | 4.759 | 6.645 | 9.087 |
| V19基线 | 10 | 13.933 | 30.135 | 42.587 |
| V19基线 | 30 | 35.184 | 111.792 | 157.131 |
| V21候选 | 1 | 6.716 | 9.510 | 11.087 |
| V21候选 | 10 | 16.802 | 39.127 | 46.642 |
| V21候选 | 30 | 44.198 | 139.557 | 189.227 |

[原始样本](evidence/run/i1a-independent-20261016/performance-raw.json)、[口径](evidence/run/i1a-independent-20261016/performance-summary.json)。历史P50≤10/P95≤30与总deadline门禁保留；不能由本采样宣称生产性能通过，也不由此比较AI实施速度。

实现稳定性：首次关键闭环、跨上下文和全量回归较弱；只有一个新任务样本，修复能力未知。实施效率暂记 **2/5（本轮诊断）**：136分钟完成跨层框架但未交付可靠闭环，达验收总用时未知；不把作者估算或协调者后续耗时加进模型成绩。

## 模型使用建议与接管边界

本轮不足以把mimo 2.6 pro选为核心IAM跨层改造主力。可继续用冻结接口的小模块任务检验其局部实施能力，但必须强审查与真实负例。与旧轮次任务不同，不据43分或136分钟声称普遍排名。原历史成绩与此前有条件的使用建议保持。

本报告完成前评审者只增加独立探针/证据，没有补修产品；用户随后授权直接修复。后续修复另写`iam-i1a-takeover-validation.md`，不改43分、不把协调者新增代码或通过场景计给实施模型。不commit/push/合并/归档。
