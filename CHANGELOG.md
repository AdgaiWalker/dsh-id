# Changelog

## 0.1.2 — 2026-11-16

**插件自带面板入口**
- 新工具 `account_vault_panel`：确保本机面板在跑（systemctl --user），返回地址 `http://127.0.0.1:8791`
- 只调 `/usr/bin/systemctl`（白名单常量），不在插件内发网络探测；服务没装时明确说怎么装
- 工具总数 12 → 13（9 只读 + 4 执行），测试同步

## 0.1.1 — 2026-11-16

**防封号：频率与熔断**
- `vault-guard check "<操作>" --scope <账号>`：按账号查限额（默认发帖 3 条/天、间隔 30 分钟）
- 超限 → `throttled` + exit 11，附原因与恢复办法
- `vault-guard record ... [--fail]`：记真实结果；连续失败 2 次自动熔断
- `vault-guard reset [--scope]`：查清原因后手动恢复
- 规则写在 `guard-rules.yaml` 的 `rate_limits`，可改
- 修：guardlib 支持 `VAULT_DIR_OVERRIDE`，测试不再碰生产状态

## 0.1.0 — 2026-11-16

首个公开版本。给 AI Agent 用的账号执行层：凭据值不进日志、不进对话、不进 argv。

**核心**
- `dsh-id exec`：按需注入凭据发一次请求，结束即失效（明文只存在于目标进程环境变量）
- `dsh-id session`：网页登录态加密保存与复用，2FA 只过一次
- `dsh-id creds`：增删查、改白名单、轮换、租约、`panic` 一键吊销、`restore` 恢复、审计哈希链校验
- `dsh-id guard`：不可逆操作闸门（关键词 + 待批准队列）
- `dsh-id panel`：本机 127.0.0.1 面板，看账号/会话/审计，增删改凭据

**维护通道**
- `dsh-id doctor`：自检依赖/权限/审计/版本，输出可粘贴的诊断报告
- 运行日志：按天落盘、保留 14 天、只记动作与结果，不记 URL 与值
- 面板「报告问题」一键生成脱敏 issue；`.github` 内置 bug / feature 模板
- `dsh-id creds revoke-list`：panic 后告诉你哪些 token/会话在平台上还没停

**安全边界（如实标注）**
- 同用户进程仍可读密钥：这是限制，不是隔离
- `guard` 是关键词闸门，不是强制审批
- 审计哈希链挡不住同权限整链重写
- `panic` 只隔离本地密文，不吊销上游 token、不终止已打开的网页会话

**已知未完成**
- 真正的短时签发（GitHub App 10 分钟令牌）尚未接入，只有长期凭据 + 租约
- 插件为只读状态 + 执行能力 MVP，不是登录执行器
