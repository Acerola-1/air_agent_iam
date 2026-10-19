# Air Agent IAM

## 正式运行态（始终适用）

- IAM19132/iam_identity为唯一正式身份库，旧iam与评测库已退役。唯一权威清单见[正式环境](docs/CURRENT-RUNTIME.md)；历史评审/评分/归档不得当作现用DSN或启动说明。
- 统一使用Agent的`deployment/run_separated_local.py start/status`；不重建已退役原库、评测容器或本地账号源。新测试只用空临时资源，完成后回收。

独立 IAM 服务：中文管理后台、人类会话、企业/成员/部门、角色权限、审计、服务账号与 SSO。技术栈见 [README.md](README.md)。

## 分支规范

- 本地开发与测试一律在 `dev` 分支进行，所有新功能、修复和验证性改动都先提交到 `dev`。
- 只有功能完好（已自测通过、构建与测试通过、密钥扫描 PASS）的代码才会合并并推送到 `main`；`main` 始终保持可交付状态。
- 不要直接在 `main` 上开发或向 `main` 推送未完成的代码；发布 `main` 前需先合并 `dev`。

## 提交前检查

- `cd server && ./mvnw test`；`cd web && npm test && npm run build`
- `bash scripts/verify-secret-scan.sh docs/reviews/evidence/run/<本次证据文件>`（真实秘密零命中才可提交；该目录已被 .gitignore 忽略）
- `.env.local`、`.venv/`、`node_modules/`、构建产物等已在 `.gitignore` 中排除，不得绕过。
