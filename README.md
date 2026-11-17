# dsh-id

给 AI Agent 用的账号执行层：**凭据值不落明文、不进日志、不进对话**，AI 却能自主用你的账号干活。

为 [DeepSeek Harness](https://github.com/deepseek-ai) 生态写的，纯本地、无服务端、无遥测。

![dsh-id](docs/screenshot.png)

---

## 解决什么问题

AI 要用你的账号，只有三种做法：

| 做法 | 问题 |
| --- | --- |
| 把 token 贴进对话 | 之后每一次请求的输入里都有它，永久泄露 |
| 把 token 写进 `.env` | 任何同机进程 `cat` 一下就有 |
| 让 AI 每次找你要密码 | 你变成人肉 2FA，一天被打断十次 |

`dsh-id` 走第四条：**凭据只在该用的那一瞬间、只在该用的那个进程里解开**，其余时间磁盘上只有密文。

```bash
dsh-id exec github-pat https://api.github.com/user
```

这条命令执行完，明文就消失了。它不在命令行参数里（`ps` 看不到）、不在日志里、不在对话里。

---

## 五个能力

| 命令 | 干什么 |
| --- | --- |
| `dsh-id exec` | 按需注入凭据，发一次 HTTP 请求或跑一条命令，结束即失效 |
| `dsh-id session` | 网页登录态：**登录一次**存下 cookie/localStorage，之后直接是登录态（2FA 只过一次） |
| `dsh-id creds` | 凭据增删查测、换值（轮换）、租约到期拦截、`panic` / `restore`、审计链校验 |
| `dsh-id guard` | 不可逆操作闸门：删除/转账/发布这类动作先记一条待批准 |
| `dsh-id panel` | 本机网页面板（127.0.0.1:8791）：看账号/会话/审计，增删改凭据 |
| `dsh-id` | 不带参数：一屏状态（凭据数、会话数、审计链、待审批） |

底层是五个独立可用的 CLI（`vault-cred` / `vault-session` / `vault-exec` / `vault-guard` / `vault-proxy`），`dsh-id` 只是统一入口，不改变它们的行为。

---

## 安装

### 方式一：当 DSH 插件装（推荐）

仓库根目录就是一个 DSH bundle（`package.json` + `cordis.patch.yml`）。在 DSH 里让 Agent 执行：

```text
plugin_manager install_bundle  github:AdgaiWalker/dsh-id
```

或手工装进 profile：

```bash
cd ~/.dsh/profiles/web
pnpm add github:AdgaiWalker/dsh-id
```

装好后在「设置 → 插件」里能看到 `dsh-id`。工具能力取决于机器上有没有装下面的 CLI。

### 方式二：只要命令行

需要：Linux / Python 3.10+ / `openssl`。

```bash
git clone https://github.com/AdgaiWalker/dsh-id ~/dsh-id
cd ~/dsh-id
./install.sh                 # 拷到 ~/.local/{bin,lib}，建数据目录
dsh-id                       # 看状态（首次会提示还没有凭据）
```

`install.sh` 只做三件事：拷文件、`chmod 755`、建数据目录。它不启动任何常驻服务。

### 目录结构

```text
package.json  cordis.patch.yml  lib/   ← DSH bundle 本体
cli/bin/  cli/lib/                     ← 五个命令行 + 两个 Python 库
docs/plugin.md                         ← 插件安装与工具清单细则
install.sh  test.sh                    ← 装 CLI / 冒烟测试
```

---

## 用法

### 存一个凭据

```bash
dsh-id creds add github-pat bearer --domains api.github.com
# bearer / basic / header / query 四种注入方式；totp 是另一类（见下）
# 交互输入值，不回显；写入后磁盘上是密文（0600）
```

### 用它发请求

```bash
dsh-id exec github-pat https://api.github.com/user
dsh-id exec github-pat https://api.github.com/repos/me/repo -X POST -d '{}'
# HTTP >= 400 默认退出码 22（便于判成败）；加 --allow-http-error 仍返回 0

# 也可以把明文注入子进程环境变量，跑任意命令
dsh-id exec run github-pat -- sh -c 'curl -H "Authorization: Bearer $VAULT_SECRET" https://api.github.com/user'
```

域名不在该凭据的白名单里 → 直接拒绝，退出码 4。

### 让 AI 自己登录（账号密码 + 2FA）

```bash
dsh-id login github --url https://github.com/login \
  --cred github-login --totp github-totp        # 有 COOKIE 就打，无则人工接手

# 凭据怎么存：
dsh-id creds add github-login basic  --domains github.com     # 值填 user:pass
dsh-id creds add github-totp  bearer --domains github.com --lease-days 0   # 值填 base32 种子
```

流程：打开登录页 → 填账号密码 → 提交 → 认出 2FA 框就用 TOTP 算码填入 → 启发式确认已登录 →
自动 `storage_state` 加密存成会话（`vault-session use <名字>` 复用）。每步截图落
`~/.deepseekbot/vault/shots/`，失败时看截图定位。

没有 TOTP 种子时加 `--manual-2fa`：窗口留给你手工过验证码，脚本等你。

### 存一个网页登录态

```bash
dsh-id session save github --url https://github.com/login --ttl-days 30
# 开可见窗口，你手动登录完回车；默认 7 天（到期有登录档案就自动重登）
dsh-id session list                                          # 域名、保存时间、过期时间
dsh-id session use github --headless                         # 打开就是登录态
dsh-id session check github                                  # 探一次，判断是否还有效
```

## 第二因素（totp）与它的边界

```bash
dsh-id creds add github-totp totp                    # 值填 base32 种子；不需要白名单
dsh-id login github --url https://github.com/login --cred github-login --totp github-totp
```

totp 是独立一类：**不能 exec、不发网络请求、没有租约**（作废一个种子等于把账号锁死）、
面板只显示「有没有、上次用过没有」，值永不回显。

**它不是「更安全」。** 种子和密码存在同一个库里，同一把机器钥匙都能解开——那是一个因素、
两种存法。它买到的是**自动化**（不用你在旁边报码），不是第二道防线。

登录有失败熔断：TOTP 允许 1 次 ±1 时间步的时钟补偿，被拒即停并熔断该账号（连错 2 次不再试），
避免撞平台风控或锁号。

## 作用域：域名之外，还管「能做什么」

域名白名单只回答「能发给谁」。拿到 `github-pat` 仍然可以 `-X DELETE /repos/...`：

```bash
dsh-id creds scope github-pat --methods GET,POST --paths /repos/,/user
# 越界：exit 9，并告你怎么开口子
```

没设作用域的老凭据保持向后兼容，`dsh-id doctor` 会把它们列成「未收紧」。

## 账实一致与机外锚

```bash
dsh-id creds adopt                          # 老格式裸密文入索引（只补元数据，不重新加密）
dsh-id creds audit-anchor --out ~/锚.json    # 导出链头，放到机外
dsh-id creds audit-verify --anchor ~/锚.json # 能识别「截断」与「重写」
```

审计链防误改，但同权限者可以整链重算。机外锚是唯一真正的见证：它记下行数与链头，
之后无论补写多少行，前 N 行都必须对得上。

### 出事的时候

```bash
dsh-id creds panic --dry-run    # 先看会做什么（顺带预览待吊销清单）
dsh-id creds panic              # 停服务 + 禁用自启 + 隔离密文 + 生成待吊销清单
dsh-id creds restore            # 一条命令回来（自动找最新隔离目录）
dsh-id creds revoke-list        # 随时重生成：哪些 token/会话在平台上还没停
```

`panic` 只隔离本地密文——**上游的 token、已经打开的网页会话都还活着**。
所以 panic 会同时问你一件更重要的事：**去哪吊销**。

```text
【上游还没停】
  ⚠ 1 个凭据 + 7 个会话在平台上依然有效，panic 管不到
  清单: ~/.deepseekbot/vault/.panic-<时间戳>/REVOKE.md
  - GitHub       github-pat  →  https://github.com/settings/tokens
  - ChatGPT 会话  chatgpt     →  https://chatgpt.com/#settings/Security
  - Google 会话   google      →  https://myaccount.google.com/deviceactivity
```

清单里只有名字和域名，没有任何凭据值；认识的平台直接给吊销/登出链接，
不认识的就写「去该平台后台删」。恢复后清单留档为 `REVOKE-<时间戳>.md`。

`panic` 不会删你的密钥文件——密文被挪进 `.panic-<时间戳>/`，随时可恢复。

### 短时令牌（GitHub App，1 小时自动过期）

不存长期 PAT：用 App 私钥现换一个 1 小时的安装令牌，过期了再换。

```bash
dsh-id creds mint gh-app --app-id 123456 --installation 7890 --key ~/.config/dsh-id/app.pem
dsh-id exec gh-app https://api.github.com/user        # 令牌已注入，不需要长令牌
```

- JWT 由 `openssl` 现签（RS256，exp ≤ 10 分钟），不引入额外依赖
- 换到的令牌写进保险库，GitHub 侧到期时间会记进元数据
- 测试用本地 mock（`DSH_ID_GITHUB_API`）跑通全流程，不碰真 GitHub

### 面板（不用记命令）

```bash
dsh-id panel            # → http://127.0.0.1:8791
dsh-id panel --port 9000
```

一页看完：凭据（名字/类型/白名单）、会话（域名/保存/有效期）、审计链状态、待审批、隔离目录。
能改：新增凭据、改白名单、删凭据、删会话、探会话、生成待吊销清单。

常驻方式（推荐，登录即起、只绑本机）：

```bash
cp cli/systemd/dsh-id-panel.service ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now dsh-id-panel
systemctl --user status dsh-id-panel --no-pager
```

只绑 `127.0.0.1`；写操作要求自定义头 + Origin 校验（挡浏览器跨站请求）；**页面永远不显示凭据值**，
新增时值只经一次 POST 交给 `vault-cred`（走 stdin），不落盘、不回显、不进日志。

### 租约：到期自动失效（对标 Vault 的短时凭据）

凭据不是永久有效的——默认 90 天租约，过期后 `exec` 直接拒绝（退出码 8），逼着轮换：

```bash
dsh-id creds add github-pat bearer --domains api.github.com --lease-days 30
dsh-id creds add locked-key  bearer --domains api.x.com    --lease-days 0   # 0=不设租约
dsh-id creds list                       # 多一列：剩 N 天 / 已过期 N 天 / 无租约
dsh-id creds rotate github-pat          # 只换值，类型/白名单不变，租约重新计时
dsh-id creds lease github-pat --days 30 --reset   # 给已有凭据补设租约（不换值）
dsh-id creds lease github-pat --days 0            # 取消租约
```

过期了不会静默失败：

```text
$ dsh-id exec github-pat https://api.github.com/user
vault-exec: 凭据已过期（租约 90 天，超期 10 天）——先轮换: vault-cred rotate github-pat
exit=8
```

现有凭据没有租约字段，行为不变（列表显示「无租约」），不会被追溯设成过期。

### 账目与审计

```bash
dsh-id creds audit-verify       # 逐行重算哈希链，指出第几行被动过
dsh-id creds audit-report       # 每件凭据的健康度（多久没换、白名单、过期）
dsh-id guard check "删除生产库" # → require_approval / allow
```

---

## DSH 插件

仓库根目录就是 bundle，把上面这些能力包成工具交给模型：

- 9 个只读工具（含 `account_vault_panel`：确保面板在跑并给出地址）：账号/凭据/会话**元数据**、审批队列、审计链校验、边界说明
- 4 个执行工具：带凭据发请求、用会话开浏览器、浏览器操作、关浏览器
- 全部工具都不返回凭据值；截图只返回文件路径，不返回 base64

细则见 [`docs/plugin.md`](docs/plugin.md)。它与 CLI 解耦，不装插件也能用命令行。

---

## 防封号：频率与熔断

Agent 用你的账号干活，最容易出事的是**节奏不像人**。guard 带一层按账号计的限额：

```bash
dsh-id guard check "发一条帖子" --scope x-main     # allow / throttled(exit 11)
dsh-id guard record "发一条帖子" --scope x-main     # 记一次成功（今日 +1，重置连续失败）
dsh-id guard record "发一条帖子" --scope x-main --fail   # 记一次失败
dsh-id guard reset --scope x-main                 # 查清原因后手动恢复正常时
```

默认（`guard-rules.yaml` 的 `rate_limits`，可改）：发帖 **3 条/天**、两次之间至少 **30 分钟**、连续失败 **2 次**自动熔断。

```text
$ dsh-id guard check "发一条帖子" --scope x-main
throttled
  原因:    距上次太近，还需等 30 分钟
  规则:    publish  {'max_per_day': 3, 'min_interval_minutes': 30, ...}
  ⚠ 先别做。等一会儿、或换账号、或查清失败原因后 vault-guard reset
exit=11
```

这只是降低概率，**不保证不封**。真封了：删会话重登、`creds panic` 吊销、换账号，系统照常。

## 维护通道（哪里错了能改）

| 通道 | 怎么用 |
| --- | --- |
| 自检 | `dsh-id doctor` / `dsh-id doctor --json`（把输出贴进 issue 即可，无凭据值） |
| 版本 | `dsh-id version`；面板顶部显示版本，「检查更新」读 GitHub 最新 release |
| 运行日志 | `<vault>/logs/dsh-id-YYYY-MM-DD.log`，按天保留 14 天，只记动作/名字/主机/结果 |
| 反馈 | 面板「报告问题」一键生成脱敏 issue，或直接开 [Issue](https://github.com/AdgaiWalker/dsh-id/issues/new/choose) |
| 仓库 | 面板「仓库」「文档」直达；`CHANGELOG.md` 记每次改了什么 |

日志长这样（不含 URL，不含值）：

```json
{"ts":"2026-11-16T18:10:06","action":"panel_check_update","ok":true,"msg":"已是最新 0.1.0"}
```

## 安全模型：它挡什么，挡不住什么

**设计上做到的**

- 磁盘上永远是密文（`openssl enc` / AES-256-CBC），密钥单独存放、权限 600
- 明文只在目标进程的环境变量里短暂存在，不进 argv、不进日志、不进对话
- 每次操作写审计（每行带 `prev_hash` + `hash`）
- 域名白名单：凭据只能用在登记过的主机上
- `panic` 一条命令让 AI 立刻失去全部凭据能力
- 会话文件加密存储，权限 600

**做不到的（请当它是「限制」，不是「隔离」）**

- **同用户的其他进程仍可读密钥文件**。这不是安全沙箱，是防手滑和防日志泄露的工程措施。真要隔离，得换用户/容器的边界。
- **审计哈希链防不住同权限重写整条链**，也发现不了尾部截断。它能让「改一行」这种篡改留下痕迹，仅此而已。机外锚（`audit-anchor`）能补上「截断/重写」这一块，但前提是那枚锚真的存到了机外。
- **`guard` 是关键词闸门，不是强制审批**。`approve --who` 由调用方填写，不能当作真实审批签名；模型也可以绕开它直接调用底层命令。
- **`panic` 只隔离本地密文**：它不会吊销上游已经发出的 token，也不会终止别人已经打开的网页会话。真要止血，还得去平台后台 revoke。
- **会话「过期时间」是本地 TTL**，不代表站点侧真的还有效。`session check` 是启发式探测，结果是参考不是保证。
- 机器绑定自动解锁意味着：**能在这台机器上以这个用户身份跑代码的人，就能解密**。这是刻意的取舍（AI 要自主干活），不是疏忽。
- **把 TOTP 种子存进同一个库，2FA 就不再是第二道防线**。它变成「一个因素、两种存法」，换来的是自动化。这不提高安全性，只提高便利性。
- **作用域对老凭据默认不收紧**，`doctor` 会列出来；不设就一直是用域名白名单兜着。

这些边界在 `dsh-id creds status` 和插件的 `*_security_boundary` 工具里也如实标着。

---

## 现状与未完成

- 主密码默认关闭，用机器绑定自动解锁（`creds passwd` 可开启，作为可选加强项）
- 插件是「只读状态 + 执行能力」MVP，不是登录执行器；设置卡片是否可视化取决于 DSH 版本
- 只做了 Linux；`vault-session` 依赖 Chromium/Playwright
- 没有做多用户、没有做远程同步、没有做团队共享

---

## 兼容性

- Python 3.10+（标准库 + `openssl` 命令行，无第三方依赖）
- 插件针对 DSH `0.2.2-rc.1` 开发，devDependencies 见根目录 `package.json`
- 在 Arch Linux / Omarchy 上实测

---

## License

MIT，见 [LICENSE](LICENSE)。安全问题怎么报见 [SECURITY.md](SECURITY.md)。
