# IAM I4：GPT-6 Luna max 独立验收

日期：2026-10-18。任务 `separate-iam-business-databases`。主控规划、Luna 实施、主控独立验收；模型身份已知，属于实名工作流实验。未执行生产迁移、正式切换、提交、推送或归档。

## 首次交付（原成绩固定）

**需修复，66/100。** 重要流程回归、实际资源校验与中断恢复门槛未过，不能用总分代替通过。首交封存后才进行测试及缺陷反馈；评审者未修改首交产品代码。后续修复不回填此分数。

| 维度 | 分数 | 独立依据 |
|---|---:|---|
| 契约正确性与业务可用 | 20/30 | 实际 Flyway22/Alembic0020、纯业务库转换、反馈/台账/偏好并发通过；菜单503、快照半完成不能续跑，活动应用排空失败。 |
| 权限和数据边界 | 16/25 | UUID、业务FK、RLS、ACL、撤销和删除保留有实证；容器客户端与预检连接不绑定同一集群，未知身份函数未阻断。 |
| 测试与验证可信度 | 12/20 | 作者真实隔离演练且如实披露未完成项；独立原回归绿，但作者未覆盖上述反例、统一管理回归和 live RAG，不能视为充分验收。 |
| 可维护性与项目契合 | 10/15 | 前向迁移及 remote/local 分流清楚；迁移脚本职责集中、硬编码实验角色/容器前缀、失败写入状态描述与事实不符。 |
| 范围控制与交付完整 | 8/10 | 未碰 RAG 原数据和其他工作，未谎称生产迁移；中断续跑/live RAG 等必需验证仍缺。 |

### 输入和首交冻结

- IAM HEAD `8da8ba1127b7ea7aa9c0a9f7289d90cbcc96a368`，Agent HEAD `8e172de724709ac970e0fa0939d75d6c7dcdf0f5`，RAG HEAD `1aa52b04976a94ad6e969775ced07cf1828ca81e`，三者均为 dev，未移动。
- 主控的方案、验收矩阵与分工在 `openspec/changes/separate-iam-business-databases/`；原始基线在本 run 的 `baseline.json`。先核对方案和真实差异，再检查代码/复跑，不以作者报告为结论。
- 原始三仓 Git 文件基线 722/1568/13393。首交相对基线 IAM 两文件（任务清单、作者报告），Agent 12 文件，RAG 0 文件；既有脏文件纳入基线保留。
- 首交原件与冻结 Agent checkout：`docs/reviews/evidence/run/i4-luna-20261018/first-delivery/manifest.json`。完整差异、文件内容和作者证据一并封存；验收运行此冻结副本。
- 作者未提供不可变的最终产品哈希清单。全部12个产品文件当前 mtime 早于作者封笔时间，HEAD/status/改动范围连续，当前哈希已冻结；这支持首交连续性，不将 mtime 冒充此前已存在的加密快照。见 reviewer/first-delivery/first-freeze-provenance.json。
- 中途状态检查不是首次交付。此前主控只提供基线环境事实，没有提供候选缺陷或补修代码。

### 独立复现的首交缺陷

1. **P1：容器工具操作集群与预检集群不一致。** `i4_separation.py` 的 `_dump/_restore` 容器分支只使用数据库名，忽略 DSN host/port；容器名前缀不是实际资源身份。评审 DSN 都指向50532，而工具容器在50533，两个集群有同名库：工具实际复制了50533的 `wrong_archive_sentinel`，50532目标却被记为 snapshotted。详见 `mismatch-snapshot-aligned.log`、`partial-snapshot-and-wrong-cluster.json`。这是自建反例库，未触及其他环境。
2. **P1：未知身份函数未阻断。** 源库新建真实 PL/pgSQL 函数，函数体读取 `public.users`，只读 inventory 仍退出0。PostgreSQL正则将 `\b` 当退格，不能照搬 Python 单词边界。视图同类反例能拒绝。见 `negative-unknown-function.log`、`negative-unknown-view.log`。
3. **P1：菜单正常路径回归。** 真 IAM50501、非owner业务DB、实际 FastAPI：`GET /auth/menus` 返回503；该未改动路由继续通过 `load_permissions` 读取已删除的旧权限表。其余18个独立场景通过。见 `live.json` 与 auth.py 的 menus 调用链。界面菜单结构可以来自非授权性静态定义，但不得恢复旧身份数据库授权。
4. **P1：部分完成的 snapshot 无法重入。** IAM 已 snapshotted、Agent 恢复后收尾失败；补齐隔离部署角色后重试，直接拒绝“iam_target 的在线快照已完成”。前置阶段白名单排除了 snapshotted，使后面的 reuse 分支不可达。见 `main-snapshot-native-path.log`、`main-snapshot-declared-roles.log` 与持久状态观测。最初缺少角色属于主控夹具准备问题；工具不能从该真实中断点继续属于产品问题，分开归因。
5. **P1：活动服务排空失败时栅栏回滚。** 真实源 IAM 运行时 freeze 两次失败“源连接未排空”，随后 finalize 确认 iam_app 仍可 CONNECT。REVOKE 与排空在同一未提交事务中，其他连接尚看不到拒绝，异常又回滚栅栏；终止连接后的统计也未等待稳定。停止主控自己的源服务后 freeze/finalize 可通过。见 `positive-freeze.log`、`positive-finalize.log` 及 stopped-app/source-offline 对照。

另有代码审查关注：recover 先在目标仍开放时比对，再撤销连接，存在检查与解栅栏之间的写入竞争；跨阶段也应重新绑定四库真实身份和 run 所有权。首交未独立完成这些竞争复现，不把推断写为已发生的数据丢失，修复后须验证。

### 已通过的独立证据

证据目录均相对 `docs/reviews/evidence/run/i4-luna-20261018/reviewer/first-delivery/`。

- 同一统一环境，原基线管理 API **189 passed/7 skipped**，首交也 **189/7**；root remote 五文件基线49、首交 **49 passed**。未删原测试或替换授权断言。见 admin-regression/root-remote-regression 日志。
- 实际原Alembic0018升级到0020；新建本地库完整建库通过。正向在另建空目标执行在线快照，随后使用真 IAM API 新建并停用一个用户、撤销快照前服务凭据，业务插入/删除，再停止主控自建源服务完成冻结和最终复制。`positive-*.log`、delta-source/target.json。
- 目标纯业务库无 users/tenants/memberships/roles/permissions/auth_sessions；37个非身份业务FK、56条业务RLS策略未变，原728个表权限位及4696个列权限位中无额外业务授权；运行角色非owner/非superuser/无BYPASSRLS，不继承IAM owner，不能连接IAM目标。历史业务/审计/台账内容逐行保留，删除引用不会级联删除历史。见 catalog.json。
- catalog 探针最初对7张表全要求 FORCE，3张既有业务表原本只有 ENABLE，故该单项原始 false 是评审断言超出本轮新增要求；不是 I4 引入的 RLS 回归。新增引用表 FORCE 均为真；实际非owner A/B/null 读边界通过。不据该原始 false 扣分。
- live 19项中18通过：身份、租户列表、台账、确认回答、反馈CAS回读、偏好5项/6项拒绝、错误tenant409、CSRF403、两个真实并发整体替换、20次串行身份、无platform=on、A/B/null归属。菜单为唯一该组失败。SQL捕获初版未含 permissions，因此其“无旧身份SQL”只适用于其记录集合，不能替菜单调用消除反证。
- 目标端实际内省：快照前撤销的机器凭据 inactive，快照后创建且停用的人类 inactive，保留的人类 active；新业务行存在，快照后删除的审计行未复活。目标有新写时 `recover --execute` 明确拒绝。源服务停机且源运行CONNECT保持拒绝。见 delta-target.json、positive-recover-after-new-writes.log。
- 同库别名、非空无主目标、未知版本、同名异UUID拒绝。测试未知身份的第一次fixture插入缺display_name失败，属于主控脚本，补齐后实际反例通过；保留原输出，不归给作者。
- RAG原文件基线完全保留。独立既有定向回归90通过；首交作者58项为离线合成，不能视为live地址/记录边界验收。P10待后续补验，不因此声称生产RAG已切换。

### 稳定性、实施耗时、性能分开

| 类别 | 首交记录 |
|---|---|
| 稳定性 | 原回归绿，但正常导航与迁移反例有缺陷；独立 live 18/19，通过率仅指这组19场景。首交不通过，尚无修复后稳定性结论。 |
| 实施墙钟 | 作者记录03:23:15Z开始、04:56:48Z封笔，**5613.566秒，约93分34秒**，含中途暂停与等待；最后只读秘密扫描04:57:13Z。不是有效编码时间。派发03:22:57Z到首次观察完成约04:58:42Z约95分45秒，来源不同单列。 |
| 暂停/反馈 | 主控中途检查04:47:41Z，恢复04:48:53Z；是状态检查，非修复轮次。独立首交冻结与评审在额度恢复后继续，此间隔不计Luna实施用时。 |
| 应用性能 | 独立20次串行 me 全200，首交P50约29.057ms/P95约37.958ms；此前源服务同组基线约21.398/25.142ms。目标服务/时刻不同，样本小且负载未固定，不能推断性能退化比例或宣称生产性能通过。 |
| Token、成本、工具总次数 | 未采集；不从代码量、文件时间或模型档位估算。 |

首交分数和上述事实固定。不同任务不能据66与其他模型跨任务分数直接宣布能力排名；本次较强的部分是权限边界与真实演练、范围和未完成项披露，短板是工具跨阶段状态机及关键负例覆盖。

## 后续修复

待同一 Luna max 定向修复并独立复验。主控追加的验收脚本、夹具、额外测试证据不计实施模型代码成果；如需主控直接补修，会另行记录，不算 Luna 独立完成。


### 首交评分后追加复现（原66分不改）

此前标为代码疑点的恢复竞争现已独立复现：四个新建最小 PostgreSQL 库，运行封存首交；在真实零delta检查返回后、目标栅栏前，用真实非owner iam_app/air_agent_runtime连接提交会话撤销及业务新写，再继续原恢复函数。恢复返回成功，源IAM CONNECT重新开放，但源会话未撤销、目标已撤销，源ledger1行、目标2行。调度钩子只固定交错点，没有替换数据比对、权限检查或SQL执行；这是恢复函数的PG竞争反例，不冒充完整Java API迁移。见 reviewer/first-delivery/recovery-race.json 与可复跑脚本。必须修复，未对真实业务执行回切；原成绩66固定保留。

主控补验P10：真实RAG RemoteProvider/IamClient连接两套自建Java IAM（50502旧地址合成副本、50501新目标），UUID/映射/记录绑定一致，实际磁盘记录可以续读；跨租户、同主体不同凭据、local混用和错误tenant均拒绝，12/12。仅自建合成注册/记录，未访问现有文档/索引/模型，不代表现网已切换。见 reviewer/rag-live/results.json。这是评审者补充的独立验证，不回填为首交作者已完成live实测。


首交追加原生路径对照：真实Java IAM签票、业务库ticket绑定、Native authenticate、运行同步/异步复查、root线程归属A/B与新线程引用FK均通过（native-live-fresh.json）；该组24项23通过，仍只有菜单503。首次追加探针使用了合成授权变更后已inactive的旧会话，正向夹具失败并保留输出；重新真实登录后复验，未修改产品或跳过认证。新一组me20次P50/P95约23.737/27.096ms，显示小样本波动，不能据此前29.057/37.958或本次值做速度结论。


P08发布窗口追加真实崩溃复现：全新四库、真实Flyway22/Alembic0020、原CLI快照/冻结。在首交_finalize实际开放两方ACL后、持久ready控制标记前，用真实非owner iam_app上下文将合成用户停用，runtime插入新线程，再os._exit(97)模拟进程kill（没有cleanup）。重试原CLI，IAM restore先成功，用户由disabled恢复active；Agent恢复随后因新增引用FK阻止drop而失败（退出2），线程仍在，目标封闭。**已证实IAM停用写入被覆盖，未声称业务线程丢失。** 见publish2-crash.json；前一只写业务的publish-crash.json显示重试失败但业务行保留，两个原始结果都保留。不依赖一次restore碰巧失败作安全保证，发布意图必须在任何开放前持久化，重试不可覆盖已开放目标。原66分保留，缺陷纳入必须修复门槛。


首交模式/引用边界补验14/14：真实非owner连接验证local/remote各自正向与误连拒绝、A/B/无ctx只见各自成员引用、错误成员重绑失败且原绑定逐行不变，以及runtime/ledger worker实际连接IAM均被PG拒绝。见reviewer/first-delivery/boundary-live.json。封存首交14个公开改动文件对58个已知私密值比较零命中，见sealed-public-secret-scan.json；中途扫描当前修复工作区的结果另存interim，未冒充封存首交扫描。

## Luna 修复1正式独立验收（保留原66分）

**仍需修复，79/100（25/20/14/11/9）。** 修复1于09:17:36Z停止产品编辑、09:19:20Z完成扫描，10:34:34Z由主控冻结，六个修复产品文件哈希与作者清单逐个相符。此次冻结含主控报告、评分表等评审文件，不能全部归给实施者。中间 `repair-checkpoint-0847` 不是交付轮次。

| 维度 | 分数 | 依据 |
|---|---:|---|
| 契约正确性与业务可用 | 25/30 | 最终冻结管理回归205通过/7跳过、root remote49通过，菜单静态目录适配、真实部分snapshot续跑和活跃事务栅栏改善；校准服务503、ready后续跑失败仍阻断。 |
| 权限和数据边界 | 20/25 | 实际未知函数/带引号函数/逗号FROM、未知users与roles FK、旧表触发器、视图、同名异UUID/版本均写前拒绝；错误工具集群虽被拒绝，却先修改目标控制表与CONNECT，未达到写前校验。 |
| 测试与验证可信度 | 14/20 | 作者披露最后小改未重跑整套，主控冻结后重跑通过；实际kill96/95通过，但kill95后不能续跑，与作者单独场景成功的覆盖范围不同。 |
| 可维护性与项目契合 | 11/15 | 服务文件和CLI错误阶段记录改善；转换阶段授予agent_migrator CONNECT与封闭断言相矛盾，工具身份验证位置仍过晚。 |
| 范围控制与交付完整 | 9/10 | 生产和原RAG未动，报告/哈希清楚；仍未满足全路径交付，未批准生产切换。 |

### 修复1剩余三项（真实独立复现）

1. 错工具集群：返回“DSN host/port与工具容器实际发布端口不一致”，但两目标已经claimed并撤销CONNECT，`committed_steps`达`agent_target:target_fenced`。此次没有错误集群数据复制，但“所有资源验证在目标写前”的门槛仍失败。见 `reviewer/repair-1/adversarial-wrong-tool-cluster.log`。首次夹具缺少错误集群`iam_migrate`角色，修正该自有夹具后重新执行；旧夹具异常文件保留，第二次JSON写入因禁止覆盖报错也保留，评分依据原CLI实际结果和真实catalog，不混为产品异常。
2. 真实进程kill96（转换提交）后能继续，kill95（remote/ready标记提交）后下一次finalize拒绝“agent目标应用角色仍可CONNECT：agent_migrator”。转换函数自己提前授予该角色CONNECT，而本环境工具migrator为postgres；此前作者采用另一角色配置的正例不能覆盖此合法部署。没有开放业务流量，也没有在此场景发生数据丢失。见`crash-path-checks.json`、`crash-after-activation-new-writes.log`。
3. 实际FastAPI `POST /agent/reconcile/ticket`，有效内部令牌、配置独立校准密钥、纯业务库：503；SQL捕获旧`tenants`查询与`platform=on`均为真。该服务级只读校准接口未被remote管理路由屏蔽。见`reconcile-live.json`；不能将缺密钥时提前503当作此路径已适配。

真实源IAM快照之后创建/停用人类、撤销机器凭据、业务插入/删除已成功提交；删除墓碑已注入；freeze对真实活跃事务超时后仍保留栅栏、不杀死该事务，原事务提交后同run继续成功。由于后续ready续跑失败，不能把这些源端证据写为最终目标全路径完成。冻结25个公开变更文件对59个已知私密值零命中；OpenSpec strict通过。

实施时间：作者修复07:38:37Z→09:17:36Z产品封笔，**98分59秒**，扫描结束09:19:20Z（100分43秒）。是含等待、两次协调中断的墙钟，非有效编码时长。后续主控验收等待/审批额度失败不计入Luna实施时间。修复版完整应用性能未测；失败前不发布性能结论。Token/成本未知。

主控向Luna提供了明确缺陷、真实复现点和部分实现约束；本次分数是“在定向反馈下的修复交付”，不能表述成自主发现全部问题。修复1仍无主控产品补丁。后续修复2另行冻结、评分。

## Luna 修复2最终独立验收

**隔离候选通过，90/100（29/24/16/12/9）。** 首交66分、修复1的79分保持原样。实施及两轮产品修复均为同一 `gpt-6-luna/max`；主控未修改产品代码，负责方案、定向缺陷反馈、独立夹具/复验、评分和部署交接。不能把主控发现问题与补充实证算成Luna自主验证。

### 五维评分

| 维度 | 分数 | 最终依据与限制 |
|---|---:|---|
| 契约正确性与业务可用 | 29/30 | 真Java IAM V23、Agent0020、纯业务库24/24真实API/native路径通过；快照/排空/三处硬退出后能继续。V22须先升级、独立登记校准客户端是明确部署前置条件。 |
| 权限和数据边界 | 24/25 | 非owner14/14、旧源真实拒绝重连3/3、无旧身份SQL/平台投影、目标历史/ACL/RLS和撤销/删除保全有实证；证明范围是本次单机隔离资源和已构造反例。 |
| 测试与验证可信度 | 16/20 | 作者如实披露Java集成、V23实迁移、全链和秘密扫描未完成；主控独立补验均通过。最终全链、RAG live及秘密扫描不是作者自行完成的成果，定向反馈依赖较大。 |
| 可维护性与项目契合 | 12/15 | 新Java路径遵循Controller→Service→MyBatis、DTO/VO与文档，前向V23和专用scope；迁移单脚本仍约130KB、角色/工具假设较多，维护成本是保留短板。 |
| 范围控制与交付完整 | 9/10 | 代码、哈希、原报告和分轮证据明确，原RAG和实际配置保留。正式生产身份对账/切换独立放行；本次未执行。 |

### 冻结与可复跑证据

修复2作者13:05:01Z封笔，主控随即冻结 `repair-2/manifest.json`（IAM相对原基线15文件、Agent25文件、RAG0；含主控文档，不能将40文件全部归模型）。主控构建前核对30个产品/测试文件与冻结哈希全部一致；最终运行冻结Agent副本与从相同Java源码构建的jar，jar哈希见`reviewer/repair-2/built-artifact.json`。后续主控仅追加报告、任务状态与交接文档。

独立证据相对 `docs/reviews/evidence/run/i4-luna-20261018/reviewer/repair-2/`：

- 管理API **218 passed/7 skipped**，root remote **49 passed**；Java自有测试库、Redis DB2，**87 tests/0 errors/0 failures**及package通过。见admin-regression、root-remote-regression、java-tests-build-isolated日志。第一次Java执行未注入数据库凭据，85项初始化错误，属于主控运行配置问题，未发生已认证数据库写入，原日志保留；正确隔离环境重跑，不归咎模型。
- 新源50506实际从V22升级V23，再执行四库流程，源/目标均是实际Flyway与Alembic，不用最小伪schema代替。校准客户端由夹具显式赋予`tenant:status:read`，其独立登记不由bootstrap覆盖；该权限随IAM库复制，未在目标启动后补权限来掩盖部署缺陷。见repair2-v23-source-preparation.json。
- 前置拒绝13/13；错误工具集群明确`write_effect:not_started`且四目标未变，1/1；部分snapshot故障、同run继续、异run拒绝等5/5；真实事务排空超时保留栅栏、原事务不被杀且提交后继续5/5。见adversarial-*.json。
- `os._exit(96/95/97)`分别固定在真实转换事务提交、ready标记提交、开放两方后真实非owner用户停用+业务插入提交。每次后续重试运行原CLI，最终完成；IAM停用、新业务行和冻结前已确认事务均保留，发布后未产生新归档，自动recover拒绝且状态/数据未变。**12/12**，见crash-path-checks.json及observations；没有替换数据校验或SQL结果。
- 另建有效V23、相同UUID的源副本，实际freeze在任何写入前报绑定源身份变化，错误源CONNECT保持不变；没有靠旧V22版本错误冒充资源绑定验证。见valid-v23-source-swap.json。
- 实际目标Java50507+非owner业务库+FastAPI，**24/24**：菜单、身份、租户、台账、反馈CAS、偏好并发与上限/错误租户/CSRF、真实签票、native认证、运行同步/异步复查及线程归属通过，无九类旧身份SQL，无platform=on。模式误连、成员绑定、A/B/null及真实运行角色不能连接IAM **14/14**。见live.json、boundary-live.json。
- 实际Java内省确认快照前被撤销机器凭据、快照后新建并停用人类均inactive，保留的人类active；快照后业务插入保留。业务旧身份表移除，37条无关FK、56条业务RLS未变，728表权限位/4696列权限位中无扩大，引用FORCE RLS，历史审计/台账/业务内容保留。catalog **18/18**；非空部门、MCP绑定、墓碑及线程不复活 **5/5**。见delta-target.json、catalog.json、extra-business-preservation.json、delta-audit-final.json。
- 新IAM端点真正缺/坏客户端401、缺专用scope403、坏/缺UUID400、未知tenant inactive；实际iam_app查询函数恢复全部先前上下文，**8/8**。校准实际无用户会话200且签名范围限定；真实IAM企业suspended而引用仍active时403，IAM不可用503，缺/坏内部令牌和缺/坏校准key拒绝；业务库无旧身份SQL/平台上下文，**11/11**。见iam-tenant-contract.json、reconcile-live.json。
- 最终V23新增自有知识服务主体和两套IAM地址50508/50507，真实RAG RemoteProvider/IamClient、相同canonical UUID/映射/credential绑定与真实磁盘记录切地址续读；B→A、同主体另一凭据、local混用等拒绝，**12/12**。仅自建合成记录，未触达既有文档/PG检索/向量/图存储或模型。见rag-live/results.json。rag-setup.log有旧固定提示“50502”，实际进程/配置与测试代码使用50508；不以该提示作为端口证据。

主控两处反例夹具问题如实保留：克隆源此前已删除auth.login，第一次增量断言因此false；随后选择在线快照中真实存在的历史审计行，再删除并确认最终目标不复活（delta-audit-corrected/final.json），未篡改原false记录。校准停用反例最初错用了用户枚举disabled，真实tenant CHECK只接受active/suspended；事务回滚后改为suspended重跑11/11。二者均未修改产品，也不计模型失败或修复成果。原始pipeline异常日志留存，不把整个第一次pipeline退出写成成功。

### 稳定性、耗时、性能

| 类别 | 修复2记录 |
|---|---|
| 稳定性 | 本次已构造迁移/恢复反例及正常路径通过，三处硬退出同一产物续跑通过；非长期运行、跨机、生产负载或所有故障组合证明。 |
| 实施时间 | 作者最初开始未采集；已记录续接12:48:27Z→13:05:01Z，**16分34秒**。先前有额度错误和未分离间隔，完整修复2耗时未知；不据mtime倒推，不把主控测试时间算实施时间。 |
| 主控贡献 | 方案、逐轮实际反例/定位反馈、隔离资源、测试、交接文档；没有主控产品代码补丁。不能把主控提供的修复思路描述成模型自主发现。 |
| 运行性能 | 最终20次串行me均200，P50 **32.911ms**、P95 **42.852ms**；此前采样不同时刻/服务/负载，不能据此排速度或认定退化。完整负载/内存/资源基准未知。 |
| Token与成本 | 未采集；不估算总费用或声称一定节省。 |

### 当前交付边界与工作流结论

代码和隔离候选验收通过。原成绩为 **66→79→90**，不是一次交付90分；两轮定向修复后完成。这个样本支持“主控规划+Luna实施+主控独立验收”可作为有人严格把关的实施方式，尚不支持无人验收或一次自动执行。跨任务分数不能推出优于其他全部模型；本轮最明显短板是跨阶段状态机、遗漏接口和自检覆盖，且发现关键问题依赖主控。

部署顺序与回退限制见 `docs/handoffs/i4-physical-separation-release.md`。生产UUID对账、真实数据迁移与正式流量切换仍独立放行；不把隔离通过写成生产完成。不归档、不commit/push。忽略目录保留原交付、归档和失败反例，不能作为垃圾过程文件清理。最终测试进程停止但不删除数据库/归档，原共享资源不清理。

最终收尾：三仓dev HEAD、原RAG13393文件、6份既有配置、30个冻结产品/测试文件及两个控制ready/业务remote-ready标记共43/43核对通过。当前41个公开变更文件对67个已知私密值零命中，IAM额外18个配置秘密比对PASS。仅停止本轮主控自建的6个Java实例与3个测试容器，数据库/归档原件保留；停止结果见owned-services-stop.json。最终结构化结果为reviewer/acceptance-final.json；作者自建504xx资源不冒称已由主控清理。


## 后续真实部署（不修改历史评分）

用户另行授权提交和真实切库后，协调者已完成本机目标库启用与应用切流，并新增部署产品适配；上文“主控未改产品/现网未切换”只描述冻结验收时刻。原66→79→90分不变，不能把后续修补归Luna。当前结果见 [正式切换记录](iam-i4-live-cutover.md)。
