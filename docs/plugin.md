# dsh-account-vault

一个 DSH 插件：既能**只读查看**账号/凭据/会话的元数据状态，也能**真实干活**——带凭据发 HTTP 请求、用已保存会话开浏览器、操作浏览器。

> **定位：本地账号执行层，不是安全隔离产品。**
> 不提供零知识保证，未通过安全审计，不应被当作 1Password 等级。
> **执行类工具让 AI 能用真实凭据与登录态，能力真实、风险也真实。**
> 上线前必须经过独立安全评审。

## 它做什么

8 个只读工具：

| 工具 | 作用 |
|---|---|
| `account_vault_overview` | 总览：代理可达性、凭据数、会话数、待审批数、审计/账号文件是否存在 |
| `account_vault_accounts` | 账号/平台列表（id、类型、是否配 2FA、登录方式、依赖链），标识符**默认打码** |
| `account_vault_account` | **单账号**查询（有范围）；需要完整邮箱/手机号时传 `reveal_identifier: true` |
| `account_vault_credentials` | 凭据**名字**与元数据（类型、域名白名单、是否有密文），**不解密** |
| `account_vault_sessions` | 会话**元数据**（域名、时间、TTL），**不含 cookie/storage_state** |
| `account_vault_guard_status` | 审批队列（只读，**不能 approve**），动作只给截断预览 |
| `account_vault_audit_status` | 审计日志哈希链校验（**重算每条 hash**） |
| `account_vault_security_boundary` | 如实披露全部已知限制 |

### 执行类工具（会真实干活）

| 工具 | 作用 |
|---|---|
| `account_vault_exec_curl` | 用**已登记凭据**发一次 HTTP 请求（走 `vault-exec curl`）。响应体超 8KB 截断并标注；域名不在白名单直接报错 |
| `account_vault_session_open` | 用已保存会话开浏览器（走 `vault-session use`）。登录判断**标 heuristic**，不是证明 |
| `account_vault_browser` | 操作当前浏览器（走 `bctl`）：nav/text/click/clickText/fill/press/eval/shot/elements。**截图只返回本地路径** |
| `account_vault_browser_stop` | 关闭浏览器并检查 CDP 端口是否释放（走 `bstart --stop`） |

**执行类工具的错误分类**：`unknown_credential` / `host_not_allowed` / `vault_locked` / `timeout` / `cli_unavailable` / `browser_not_running` / `element_not_found` / `bad_args`

## 它明确不做

- 不返回密码、API token、TOTP 种子或验证码、cookie、恢复码
- 不调用任何解密路径（只读元数据 JSON、文件名、目录列表）
- 不包装 `account-secret get/login`
- 不提供批量授权、批量导出秘密的工具
- 不提供 approve / reject（审批必须由人在命令行执行）
- 不返回凭据值（凭据只走底层 `vault-exec`，不进参数/返回值/审计）
- 不提供 approve/reject（审批必须由人在命令行执行，避免 AI 自批）
- 截图不返回内容，只返回本地文件路径
- 不启动/停止/重启 DSH 或任何常驻服务（v0.3.0 起已无常驻代理；面板服务单独管理）
- 不修改 vault 内容、不改密钥、不动浏览器 profile

> 注：执行类工具**会** spawn 子进程（`vault-exec`/`vault-session`/`bstart`/`bctl`），
> 这是它们工作的必要条件。源码静态检查改为验证「只调用这四个白名单 CLI、不调用 account-secret」。

## 安全边界（必读）

以下均为**代码审查结论**，不是免责话术：

1. **凭据代理无调用者认证** — `127.0.0.1:48771` 上同一用户下的任何进程都能直接调用。**加共享 header 或改 Unix socket 都不构成**对同用户 AI/shell 的安全边界。
2. **`account-secret get/login` 会输出明文** — 本插件不调用，但命令仍在系统里。
3. **审批非强制** — `vault-guard` 是约定式关键词检查，AI 不调用就不触发。
4. **`--who` 可伪造** — 审计里的「批准人」不能作为真实审批证据。
5. **`panic` 不撤销上游** — 不吊销平台 token、不终止已有网页会话。
6. **哈希链有盲区** — 能发现**内容改动**与**中间行删除**（实测定位到具体行号）；但**不能**抵御同权限者重算整条链，**不能**发现**尾部截断**或整个文件被删除。
7. **会话 TTL ≠ 登录有效** — `vault-session check` 只是启发式探测（看是否跳回登录页），不能证明登录有效。
8. **`accounts.yaml` 未经验证** — 人工维护的笔记，含推断与可能过时的关联。
9. **元数据本身敏感** — 凭据名、域名、账号关系属敏感信息。
10. **不是完整登录执行器** — 不自动过 2FA、不自动填登录表单；`session_open` 依赖已保存会话。
11. **`exec_curl` 会产生真实对外请求** — GET 通常只读，但 POST/PUT/DELETE 可能有真实副作用。插件不判断业务语义，不会替你拦下危险请求。
12. **浏览器 CDP 端口开着时可被同机进程接管** — 默认 9222，用完必须 `browser_stop`。
13. **`browser` 的 `eval` 可执行任意 JS** — 等同于在该页面完全控制，慎用。
14. **`session_open` 与 `browser` 不能共用同一浏览器** — `vault-session use` 用 Playwright 起独立浏览器且不暴露 CDP 端口，`bctl` 接不上。需要浏览器操作请走 `bstart` 路径。

### 关于「不声明 subprocess」

`inject` 未包含 `subprocess` **只表示不依赖该 Cordis 服务，不是运行时安全沙箱**。
Node 插件仍以用户进程权限运行，理论上可自行 `import node:child_process` 或发起网络请求。
真正的约束来自**源码实际不执行子进程**（由测试做静态检查证明），以及只读、无写操作、输出白名单。
**这些是「实现约束」，不是安全隔离。**

### 输出限制（不是「永不泄露」保证）

- 账号/平台列表：**严格字段白名单**，不返回 `purpose`/`note`/`todo` 等自由文本
- 标识符：邮箱 → `t***@example.com`，手机号 → `138****00`；仅单账号查询可显式 `reveal_identifier`
- 审批动作：只返回**截断预览**（≤60 字符）+ 原长度
- 文本消毒：剔除控制字符、截断、长 hex/base64/token 形态替换为 `[REDACTED]`
- 深层对象：不递归回传，只取白名单标量

这**降低**了泄露风险，但**不构成**「永不泄露」的保证——输出仍含敏感元数据，且底层系统还有其它可输出明文的命令。

### 代理探测的副作用

`overview` / `credentials` 会向 `probeUrl`（默认 `http://127.0.0.1:48771/...`）发一次真实 HTTP 请求。
**若代理在跑，可能因此向代理自己的审计日志追加一条记录。** 本插件不写任何文件，但这次探测**不是完全无副作用**。
需要完全静默时，把 `probeUrl` 设为空字符串即可禁用探测。

## 配置

在 **DSH 设置 → 插件 → 插件配置**（命名空间 `account-vault`）：

| 字段 | 默认值 | 说明 |
|---|---|---|
| `vaultDir` | `~/.deepseekbot/vault` | 数据目录 |
| `accountsFile` | `~/.deepseekbot/accounts.yaml` | 账号笔记 |
| `probeUrl` | `http://127.0.0.1:48771/__probe__/example.com/` | 代理探测地址；**空字符串=禁用探测** |

> ⚠️ 关于「设置里能看到配置卡」：本包 `package.json` 只声明了 `dsh.bundle`，
> **没有 `dsh.client` 前端插件**，因此当前**可能不会**在设置界面渲染自定义配置卡。
> 设置命名空间仍会注册（`ctx.settings.register`），能通过 DSH 自身的设置机制读写，
> 但是否有可视化卡片**需以 DSH 实机隔离加载验证为准**，本文档不作承诺。

## 测试（干净环境一条命令）

```bash
cd dsh-id
npm run prepare:test-deps   # 链接 DSH 依赖（不联网）
npm test                    # 只读 + 执行，共 195 项
```

单独运行：

```bash
npm run test:readonly   # 只读工具，122 项
npm run test:exec       # 执行类工具，73 项（mock 底层 CLI）
```

测试**自己创建**唯一临时目录（`mkdtemp`）并**自己清理**，不触碰任何用户路径；
`fetch` 被 stub，绝不请求真实代理端口。

若缺少依赖，会明确报错并给出准备命令（见下）。依赖准备（指向已安装的 DSH profile，**不联网**）：

```bash
mkdir -p node_modules/@deepseek-ai
ln -sfn $DSH_PROFILE/node_modules/@deepseek-ai/dsh-tools    node_modules/@deepseek-ai/dsh-tools
ln -sfn $DSH_PROFILE/node_modules/@deepseek-ai/schemastery  node_modules/@deepseek-ai/schemastery
```

### 测试覆盖（195 项：122 只读 + 73 执行）

执行类工具测试（`test/exec.mjs`）用 **mock 底层 CLI**（假 `vault-exec`/`vault-session`/`bctl`/`bstart` 脚本）覆盖：

- `exec_curl`：成功 / 白名单拒绝 / 凭据不存在 / 保险库锁定 / 超时 / HTTP 404 / 响应体 >8KB 截断 / 参数校验
- `session_open`：成功 + heuristic 标注 / 会话过期 / 会话不存在
- `browser`：nav/text/elements/eval/shot 各 action / 截图只返回路径且文件确实落盘 / 浏览器未启动 / 选择器未命中 / 非法 action
- `browser_stop`：端口释放判定（已停 / 仍在跑）
- 无 approve/reject/get-secret 工具
- 审计写入且不含 canary 凭据值
- 所有 12 个工具都声明了 `timeoutMs`

只读测试覆盖：

1. 插件加载与依赖声明
2. **源码静态检查**：不含 child_process / exec / spawn / writeFile / unlink / mkdir / chmod / openssl / account-secret
3. 8 个工具注册与执行
4. **敏感 canary 检查**：往 note/purpose/todo/深层对象/action 注入 canary，验证不泄露
5. 标识符默认打码（邮箱、手机号）
6. 单账号查询的 reveal 行为
7. 审批动作只给截断预览
8. **审计链 10 个场景**：正常 / 改内容不改 hash / 删中间行 / 坏 JSON / 空 / 仅旧格式 / 旧行+链 / Unicode / 整数浮点混用 / 尾部截断
9. 只读：fetch 被 stub、probeUrl 为空时不发请求
10. 多实例隔离与卸载（cleanup 可重复调用）
11. 损坏 JSON / 权限问题 → 返回 unknown/unreadable 而非空
12. 安全边界披露完整性

## 安装（**需安全评审通过后执行，不要自行上线**）

```bash
cd ~/.dsh/profiles/web
pnpm add /path/to/dsh-id/plugin
# 再把 "dsh-account-vault" 加入 package.json 的 dsh.profile.bundles
# 重启 dsh-web 后生效
```

## 回滚

```bash
cd ~/.dsh/profiles/web
# 从 dsh.profile.bundles 删掉 "dsh-account-vault"
pnpm remove dsh-account-vault
# 重启 dsh-web
```

插件不写用户数据，卸载无残留。

## 后续未接的能力

本稿是**只读管理/状态 MVP**。以下能力**未实现**：

- 自动登录 / 填表 / 过 2FA
- 会话捕获（`vault-session save` 的插件化）
- 带凭据的请求代理调用（需先解决代理无认证问题）
- 审批的强制拦截（需内核级或独立进程配合）
- 批量凭据操作
- 任何写操作

## 版本兼容

- 目标：DSH `0.2.2-rc.1`（web profile）
- 依赖：`@deepseek-ai/dsh-tools`、`@deepseek-ai/schemastery`（peerDependencies）
- Node `>=20`

## 许可

MIT
