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
| `dsh-id creds` | 凭据增删查测、改主密码、`panic` 一键吊销、`restore` 恢复、审计链校验 |
| `dsh-id guard` | 不可逆操作闸门：删除/转账/发布这类动作先记一条待批准 |
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
# bearer / basic / header / query 四种注入方式
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

### 存一个网页登录态

```bash
dsh-id session save github --url https://github.com/login --ttl-days 30
# 开可见窗口，你手动登录完回车；默认 30 天
dsh-id session list                                          # 域名、保存时间、过期时间
dsh-id session use github --headless                         # 打开就是登录态
dsh-id session check github                                  # 探一次，判断是否还有效
```

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

### 账目与审计

```bash
dsh-id creds audit-verify       # 逐行重算哈希链，指出第几行被动过
dsh-id creds audit-report       # 每件凭据的健康度（多久没换、白名单、过期）
dsh-id guard check "删除生产库" # → require_approval / allow
```

---

## DSH 插件

仓库根目录就是 bundle，把上面这些能力包成工具交给模型：

- 8 个只读工具：账号/凭据/会话**元数据**、审批队列、审计链校验、边界说明
- 4 个执行工具：带凭据发请求、用会话开浏览器、浏览器操作、关浏览器
- 全部工具都不返回凭据值；截图只返回文件路径，不返回 base64

细则见 [`docs/plugin.md`](docs/plugin.md)。它与 CLI 解耦，不装插件也能用命令行。

---

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
- **审计哈希链防不住同权限重写整条链**，也发现不了尾部截断。它能让「改一行」这种篡改留下痕迹，仅此而已。
- **`guard` 是关键词闸门，不是强制审批**。`approve --who` 由调用方填写，不能当作真实审批签名；模型也可以绕开它直接调用底层命令。
- **`panic` 只隔离本地密文**：它不会吊销上游已经发出的 token，也不会终止别人已经打开的网页会话。真要止血，还得去平台后台 revoke。
- **会话「过期时间」是本地 TTL**，不代表站点侧真的还有效。`session check` 是启发式探测，结果是参考不是保证。
- 机器绑定自动解锁意味着：**能在这台机器上以这个用户身份跑代码的人，就能解密**。这是刻意的取舍（AI 要自主干活），不是疏忽。

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
