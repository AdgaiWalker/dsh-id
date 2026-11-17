# Changelog

> **本包取代 dsh-account-vault，dsh-account-vault 不再维护。** 两者是同一份代码的改名与扩展，不是竞争包。

## 0.3.0 — 2026-11-17

**B 组：本地轻量化（不破三条不变量）**

- 删 `vault-proxy`（318）、`accounts`（150）；`audit-report`、`mint`、`cmd_test` 一并移除。
- 入口 9 → 5：PATH 上只留 `dsh-id`、`dsh-id-panel`，其余三个（`vault-exec`/`vault-session`/`vault-login`）是转发壳，保证 `~/.dsh/AGENTS.md` 里「走 vault-exec」不断。
- 子命令 24 → 11（`add/list/rm/panic/restore/revoke-list/lease/rotate/audit/adopt/scope`）；主密码与恢复码 8 个收进 `dsh-id vault …`，代码保留（老板要求保留）。
- `revoke` 并成 `rm --revoke`；`audit-verify`/`audit-anchor` 并成 `audit verify|anchor`（旧名仍可调用）。
- 插件工具 13 → 8：删掉总览/账号列表/单账号/审批队列/审计链校验五个只读工具（对应 CLI 一条命令就能看）。
- 代码 8,346 → 7,061 行（−1,285）；`lib/index.js` 1,307 → 698。
- 测试：`test.sh` 13 步、`offline.mjs` 75、`npm test` 69，全过。

## 未发布

**A 组：账号本优先**

- 新增 `card` 类型：卡号/CVV 加密（JSON 两字段），有效期/持卡人/账单地址/尾号/品牌进 meta；
  不能 exec、没有租约；列表与面板只显示尾号。
- 面板能加 TOTP 种子：`types` 增加 `totp`/`card`，两类都不再要求域名白名单。
- 面板「出码」只限本机：Host 是回环 **且** 没有 `CF-Connecting-IP` / `X-Forwarded-For`；
  否则 403 + `panel_totp_denied` 审计。测试覆盖三条拒绝路径。

## 0.2.0 — 2026-11-17

**方案 v2 落地：账实一致 / 类别与作用域 / 短时凭据 / 可核对**

- **M0 账实一致**：新增 `creds adopt`，把 vault 根目录下未入索引的老格式密文（`<name>__<kind>.enc`）只补元数据、不重新加密、不移动。面板新增「第二因素」表：名字 / 站点 / 上次使用 / 状态。生产实测 6 个 TOTP 种子 + 1 个 MAIL_API_TOKEN 入册，凭据数 1 → 8。
- **M1 类别与作用域**：`totp` 单列一类——不能 `exec`（exit 6）、不发网络请求、没有租约；`creds scope <名字> --methods --paths` 把授权从「域名」下沉到「方法 + 路径前缀」，`vault-exec` 越界返回 exit 9。
- **2FA 失败熔断**：允许 1 次 ±1 时间步时钟补偿；被拒即停、记审计、熔断该账号（连错 2 次不再尝试），防止撞风控/锁号。
- **M2 短时凭据**：会话 TTL 默认 30 → 7 天；新增登录档案（`vault/login/<名字>.json`，只存 URL/选择器/用哪个凭据），会话过期后 `session use` 自动重登。
- **M3 可核对**：`creds audit-anchor` 导出链头到机外（默认 `~/.dsh/log/dsh-id-audit-anchor.json`），`creds audit-verify --anchor` 能识别截断与重写；面板显示「机外锚」状态；`doctor` 新增账实一致 / 第二因素 / 作用域 / 机外锚四项检查。
- **版本自检**：改按语义版本比较，403 限流时用上次缓存结果并明说是限流，不再把旧版本报成「已是最新」。
- **面板手机端**：窄屏改为卡片式（每行带字段标签），操作按钮不再被挤掉。

**如实说明**
- 2FA 种子与密码同库、同一把机器钥匙可解：这是「第二因素的托管」，不是「更安全」。任何把这件事说成「2FA 保护」的说法都是错的。
- 作用域对老凭据默认不收紧（向后兼容），`doctor` 会列出来；不收就一直是「未收紧」。

## 0.1.2 — 2026-11-16

**插件自带面板入口**
- 新工具 `account_vault_panel`：确保本机面板在跑（systemctl --user），返回地址 `http://127.0.0.1:8791`
- 只调 `/usr/bin/systemctl`（白名单常量），不在插件内发网络探测；服务没装时明确说怎么装
- 工具总数 12 → 13（9 只读 + 4 执行），测试同步
- 新增实测：用假 systemctl（`DSH_ID_SYSTEMCTL`）验证「识别在跑 / 不乱开实例」，不碰真实服务

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
