# 当前正式环境

本文件及同目录`runtime-manifest.json`是三仓唯一运行态基准。I4已切库，旧环境已在本次用户授权下实际删除；历史规划、评分、归档和私有评审证据用于溯源，不是启动指令或活跃数据源。

| 域 | 唯一正式数据库 | 数据容器 / 命名卷 | 应用入口 |
|---|---|---|---|
| 身份 | 127.0.0.1:19132/iam_identity | iam-pg17 / iam-pg17-data | API19100，管理页19101 |
| Agent业务 | 127.0.0.1:15432/air_agent_business | air-agent-postgres / air-agent_pgdata | 原生2024，API8100，聊天3000，后台3100 |
| 知识资料 | 127.0.0.1:5432/rag | lightrag-postgres / lightrag_pg | 网关8099（remote IAM） |

PG内部保留postgres/template0/template1系统维护库，它们不是第二份业务数据。IAM的iam/iam_auth是schema名，不是已经删除的旧iam数据库。

## 保留的组件

- IAM：iam-pg17、iam-redis7。
- Agent：air-agent-postgres、air-agent-redis、air-agent-langgraph-api。
- 知识：lightrag-postgres、lightrag-qdrant、lightrag-neo4j；lightrag-air/water/coastal分别服务三个资料范围，不是重复副本。三个实例仍为按需组件，旧网络地址未完成重启复验；不要通过重新初始化/重新入库来修复连接。
- 观测：仅保留air-agent-langfuse-*的v4六组件及对应数据卷；当前按需停止，保留正式历史观测数据，不是旧v2评测栈。
- buildkit是容器构建工具，不是第二份应用或数据源。系统init/builder镜像是运行时依赖，不作业务库清理。

合计17个应用/存储组件及1个构建器。完整名称和卷白名单见JSON；Qdrant和Neo4j当前数据在保留容器的文件系统中，不可把它们当无卷空壳删除。

## 唯一启动入口

在Agent仓库执行：

```bash
.venv/bin/python deployment/run_separated_local.py start
.venv/bin/python deployment/run_separated_local.py status
```

`run-local.sh`只包装同一入口；日常重启不运行全量compose、不重新seed或执行分库。启动器保留PG/Redis，只按需重建原生应用、读取真实私网IP、更新受限桥来源IP，并验证健康。两个正式PG容器的初始化库名和回环端口已与实际DSN统一；刷新容器时数据卷及集群标识不变。

宿主模型网关为127.0.0.1:7863/v1，保留配置模型名称；原生容器经受限19110桥访问。凭据只在Git忽略的本机配置中，文档和manifest不存口令。

## 账号与知识目录

独立IAM管理员凭据在Agent`.local/i4-live/credentials.md`；知识账号/机器凭据在RAG`.local/remote-iam-live/credentials.md`。root已于2026-10-19通过19100正常登录及四个有效企业的Agent权限读回；本轮核查未改口令，目标业务与查看权限已明确配置。root口令不写入本清单；早期“短口令无法登录”的记录不再代表当前已验证状态。

知识`.local/workspace-access/registry.json`仅保留技术目录，旧principals/grants及本地凭据清单已移除；正式权限每次由IAM裁决。记录仅写`.local/remote-iam-live/records`，旧local记录不是正式身份可读取的数据源。PDF、MinerU原文、PG public/rag/env_rag资料、向量和图不因环境清理而重建。

检索算法名`local`与身份模式`local`不是同一个配置；身份固定remote不意味着改写现有检索算法或重建其索引。

## 测试与历史资源

旧iam/air_agent源、各轮test/review/stage库、501xx–505xx评测容器、旧lightrag-server/Langfuse v2已删除。旧名称可能仍见于审计/迁移控制记录及原报告，那是历史事实，不能据此重建原环境或回退DSN。

IAM测试仅显式`bash scripts/test-db.sh create`创建空iam_test，按README跑独立测试后`drop`；日常基础设施启动不创建测试库。Agent/RAG数据库测试同样必须显式创建隔离临时资源，结束清理，不能使用正式库造数。旧在线验收、本地账号引导和初始化演练入口已标记退役并提前拒绝执行。

清理证据见[本次清理记录](reviews/runtime-retirement-20261019.md)。原评审/评分和离线证据保留为历史档案；其他项目的源码及bind目录不作为此正式环境的数据源，也不在本次文件删除范围。
