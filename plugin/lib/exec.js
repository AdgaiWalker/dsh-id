/**
 * exec — 会真实「干活」的能力：带凭据发请求、开会话浏览器、操作浏览器。
 *
 * ⚠ 这部分**不是只读**，能力真实、风险也真实。安全边界见 SECURITY_LIMITATIONS。
 *
 * 设计原则：
 *   1. 一律调用现有底层 CLI（vault-exec / vault-session / bstart / bctl），不另造一套。
 *   2. 凭据值绝不进入返回值、日志、审计；底层已保证不进 argv。
 *   3. 所有子进程调用都有超时与明确的错误分类。
 *   4. 截图只落文件、只回路径，绝不回 base64。
 *   5. 不提供 approve/reject。
 */

import { defineTool } from "@deepseek-ai/dsh-tools";
import { spawn } from "node:child_process";
import { stat, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { homedir, tmpdir } from "node:os";

export const MAX_BODY_BYTES = 8192;
export const MAX_STDERR_BYTES = 2048;

/** 底层 CLI 路径（可用配置覆盖，便于测试指向 mock）。 */
const BIN_DIR = process.env.DSH_ID_BIN || join(homedir(), ".local", "bin");

export const DEFAULT_BIN = {
  vaultExec: join(BIN_DIR, "vault-exec"),
  vaultSession: join(BIN_DIR, "vault-session"),
  bstart: join(BIN_DIR, "bstart"),
  bctl: join(BIN_DIR, "bctl"),
};

/** vault-exec 退出码 → 语义化错误 */
const EXEC_EXIT = {
  2: { code: "usage_error", message: "参数用法错误" },
  3: { code: "unknown_credential", message: "凭据不存在" },
  4: { code: "host_not_allowed", message: "目标域名不在该凭据的 domains 白名单内" },
  5: { code: "vault_locked", message: "解密失败（保险库锁定或密钥不匹配）" },
  6: { code: "unsupported_type", message: "该凭据类型不支持 HTTP 注入" },
};

/**
 * 跑一个子进程，带超时与输出上限。
 * 返回 { ok, code, stdout, stderr, timedOut, spawnError }
 */
export function runProcess({ bin, args = [], env = {}, timeoutMs = 20_000,
  maxStdout = 1 << 20, maxStderr = MAX_STDERR_BYTES, stdin = null }) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(bin, args, {
        env: { ...process.env, ...env },
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (e) {
      resolve({ ok: false, spawnError: String(e && e.message || e), stdout: "", stderr: "" });
      return;
    }

    let stdout = "";
    let stderr = "";
    let outTruncated = false;
    let errTruncated = false;
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill("SIGKILL"); } catch { /* ignore */ }
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      if (stdout.length >= maxStdout) { outTruncated = true; return; }
      stdout += chunk.toString("utf8");
      if (stdout.length > maxStdout) {
        stdout = stdout.slice(0, maxStdout);
        outTruncated = true;
      }
    });
    child.stderr.on("data", (chunk) => {
      if (stderr.length >= maxStderr) { errTruncated = true; return; }
      stderr += chunk.toString("utf8");
      if (stderr.length > maxStderr) {
        stderr = stderr.slice(0, maxStderr);
        errTruncated = true;
      }
    });

    child.on("error", (e) => {
      clearTimeout(timer);
      resolve({ ok: false, spawnError: String(e && e.message || e), stdout, stderr });
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({
        ok: !timedOut && code === 0,
        code: typeof code === "number" ? code : null,
        signal: signal || null,
        stdout, stderr, outTruncated, errTruncated, timedOut,
      });
    });

    if (stdin !== null) {
      try { child.stdin.end(stdin); } catch { /* ignore */ }
    } else {
      try { child.stdin.end(); } catch { /* ignore */ }
    }
  });
}

/** 截断文本并标注 */
export function truncateText(text, maxBytes = MAX_BODY_BYTES) {
  if (typeof text !== "string") return { text: "", truncated: false, bytes: 0 };
  const buf = Buffer.from(text, "utf8");
  if (buf.length <= maxBytes) {
    return { text, truncated: false, bytes: buf.length };
  }
  // 按字节截断后可能切坏多字节字符，用 toString 的替换行为兜底
  let cut = buf.subarray(0, maxBytes).toString("utf8");
  // 去掉可能产生的替换字符尾巴
  cut = cut.replace(/\uFFFD+$/, "");
  return {
    text: cut,
    truncated: true,
    bytes: buf.length,
    note: `响应体 ${buf.length} 字节，已截断到前 ${maxBytes} 字节（按 UTF-8 字节）`,
  };
}

/**
 * 把 vault-exec 的退出码映射为语义化错误。
 * 注意：退出码 0 但 curl 失败（如 404/超时）时，状态码从 stdout 的 -w 输出里取。
 */
export function classifyExecFailure(res) {
  if (res.spawnError) {
    return {
      code: "cli_unavailable",
      message: "无法启动 vault-exec：" + res.spawnError,
      hint: "确认底层 CLI 存在且可执行。",
    };
  }
  if (res.timedOut) {
    return {
      code: "timeout",
      message: "请求超时（底层进程被强制终止）",
      hint: "目标站点无响应，或请求耗时超过超时限制。",
    };
  }
  if (typeof res.code === "number" && EXEC_EXIT[res.code]) {
    const m = EXEC_EXIT[res.code];
    return { code: m.code, message: m.message, exit_code: res.code, stderr: res.stderr || undefined };
  }
  return {
    code: "request_failed",
    message: "请求失败",
    exit_code: res.code,
    stderr: res.stderr || undefined,
  };
}

/** 生成截图落盘路径（只返回路径，不返回内容） */
export function shotPath(dir, prefix = "shot") {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const rand = Math.random().toString(36).slice(2, 8);
  return join(dir, `${prefix}-${stamp}-${rand}.png`);
}

/* ══════════════════════════════════════════════════════════════════════════
 * 注册执行类工具
 * ══════════════════════════════════════════════════════════════════════════ */

export function registerExecTools({ register, state, resolvePaths, textBlock, OUTPUT_SCHEMA, audit }) {
  const bins = () => ({ ...DEFAULT_BIN, ...(state.bins || {}) });

  /* ── 工具：带凭据发 HTTP 请求 ── */
  register(defineTool({
    name: "account_vault_exec_curl",
    description:
      "用**已登记的凭据**发一次 HTTP 请求（内部走 vault-exec curl）。" +
      "凭据值不会出现在参数、返回值或审计里——你只给凭据名。\n" +
      "响应体超过 8KB 会截断并标注。目标域名必须在该凭据的 domains 白名单内，否则直接报错。\n" +
      "错误分类：unknown_credential（凭据不存在）/ host_not_allowed（白名单拒绝）/" +
      "vault_locked（保险库锁定）/ timeout（超时）/ cli_unavailable（底层不可用）。\n" +
      "⚠ 风险：这会用真实凭据对外发起请求，可能产生真实副作用（取决于 method 与目标 API）。",
    parameters: {
      credential: { type: "string", description: "凭据名（如 github-pat），不是凭据值" },
      url: { type: "string", description: "完整目标 URL（含协议）" },
      method: { type: "string", description: "HTTP 方法，默认 GET" },
      headers: { type: "object", description: "附加请求头（键值对，字符串）", additionalProperties: true },
      body: { type: "string", description: "请求体（用于 POST/PUT 等）" },
      timeout_ms: { type: "number", description: "超时毫秒数，默认 20000，上限 60000" },
    },
    output: { schema: OUTPUT_SCHEMA, render: (_a, v) => textBlock(v) },
    timeoutMs: 70_000,
    async execute(args) {
      const cred = typeof args?.credential === "string" ? args.credential.trim() : "";
      const url = typeof args?.url === "string" ? args.url.trim() : "";
      if (!cred) return { ok: false, code: "bad_args", error: "必须提供 credential（凭据名）" };
      if (!url) return { ok: false, code: "bad_args", error: "必须提供 url" };
      if (!/^https?:\/\//i.test(url)) {
        return { ok: false, code: "bad_args", error: "url 必须以 http:// 或 https:// 开头" };
      }

      const method = (typeof args?.method === "string" && args.method.trim())
        ? args.method.trim().toUpperCase() : "GET";
      const timeoutMs = Math.min(Math.max(Number(args?.timeout_ms) || 20_000, 1000), 60_000);

      // 构造 curl 参数：-w 输出状态码，-o 输出体到 stdout 的独立标记
      // 用 -w '\n__VAULT_STATUS__:%{http_code}' 让状态码与体分离
      const curlArgs = [
        "curl", cred, url,
        "-sS",
        "-X", method,
        "-w", "\n__VAULT_STATUS__:%{http_code}",
        "--max-time", String(Math.max(1, Math.floor(timeoutMs / 1000))),
      ];

      if (args?.headers && typeof args.headers === "object") {
        for (const [k, v] of Object.entries(args.headers)) {
          if (typeof k !== "string" || typeof v !== "string") continue;
          if (!/^[A-Za-z0-9-]+$/.test(k)) continue;
          // 头值里不允许换行，避免 curl 配置注入
          curlArgs.push("-H", k + ": " + v.replace(/[\r\n]/g, " "));
        }
      }
      if (typeof args?.body === "string") {
        curlArgs.push("--data-binary", args.body);
      }

      const res = await runProcess({
        bin: bins().vaultExec,
        args: curlArgs,
        timeoutMs: timeoutMs + 5000,
        maxStdout: 1 << 20,
      });

      if (!res.ok && (res.spawnError || res.timedOut ||
        (typeof res.code === "number" && res.code !== 0))) {
        const f = classifyExecFailure(res);
        await audit("exec_curl_fail", cred, `code=${f.code}`);
        return {
          ok: false,
          credential: cred,
          code: f.code,
          error: f.message,
          hint: f.hint,
          exit_code: f.exit_code ?? null,
          stderr: f.stderr ? truncateText(f.stderr, 512).text : undefined,
        };
      }

      // 从 stdout 里剥离状态码标记
      let stdout = res.stdout;
      let httpStatus = null;
      const marker = "\n__VAULT_STATUS__:";
      const idx = stdout.lastIndexOf(marker);
      if (idx >= 0) {
        const tail = stdout.slice(idx + marker.length).trim();
        stdout = stdout.slice(0, idx);
        const n = parseInt(tail, 10);
        if (Number.isFinite(n)) httpStatus = n;
      }

      const bodyInfo = truncateText(stdout, MAX_BODY_BYTES);
      const result = {
        ok: true,
        credential: cred,
        http_status: httpStatus,
        method,
        url,
        body: bodyInfo.text,
        body_bytes: bodyInfo.bytes,
        body_truncated: bodyInfo.truncated,
      };
      if (bodyInfo.truncated) result.body_note = bodyInfo.note;
      if (res.outTruncated) result.stdout_truncated = true;

      await audit("exec_curl", cred, `status=${httpStatus} method=${method}`);
      return result;
    },
  }));

  /* ── 工具：用会话开浏览器 ── */
  register(defineTool({
    name: "account_vault_session_open",
    description:
      "用已保存的网页会话打开一个浏览器（内部走 vault-session use）。\n" +
      "返回是否成功、当前 URL、以及**启发式**的登录判断——注意 heuristic 不等于确认已登录，" +
      "它只是看有没有被跳回登录页/是否存在可见密码框。\n" +
      "⚠ 用完必须调用 account_vault_browser_stop 关闭，否则登录态会长期暴露。" +
      "⚠ 已知限制：vault-session use 当前用 Playwright 起独立浏览器且不暴露 CDP 端口，" +
      "因此它**不能**被 account_vault_browser 接管；需要浏览器操作时请改用 bstart 路径。",
    parameters: {
      session: { type: "string", description: "已保存的会话名（如 github）" },
      url: { type: "string", description: "打开哪个 URL（默认该会话域名首页）" },
      headless: { type: "boolean", description: "是否无头，默认 true" },
      timeout_ms: { type: "number", description: "超时毫秒，默认 90000" },
    },
    output: { schema: OUTPUT_SCHEMA, render: (_a, v) => textBlock(v) },
    timeoutMs: 120_000,
    async execute(args) {
      const session = typeof args?.session === "string" ? args.session.trim() : "";
      if (!session) return { ok: false, code: "bad_args", error: "必须提供 session（会话名）" };

      const headless = args?.headless !== false;
      const timeoutMs = Math.min(Math.max(Number(args?.timeout_ms) || 90_000, 5000), 110_000);

      const argv = ["use", session];
      if (headless) argv.push("--headless");
      if (typeof args?.url === "string" && args.url.trim()) {
        argv.push("--open", args.url.trim());
      }

      const res = await runProcess({
        bin: bins().vaultSession,
        args: argv,
        timeoutMs,
        maxStdout: 64 * 1024,
      });

      if (res.spawnError) {
        return {
          ok: false, code: "cli_unavailable",
          error: "无法启动 vault-session：" + res.spawnError,
          hint: "确认底层 CLI 存在，且 Playwright 环境已就绪。",
        };
      }
      if (res.timedOut) {
        return {
          ok: false, code: "timeout",
          error: "会话打开超时（已强制终止）",
          hint: "站点可能加载很慢，或需要人机交互。",
        };
      }

      const out = res.stdout || "";
      const mUrl = out.match(/当前页:\s*(\S+)/);
      const mSession = out.match(/会话:\s*(\S+)/);
      const loggedInHeuristic = /看起来已登录/.test(out);
      const looksLogin = /看起来未登录/.test(out);

      const okExit = res.code === 0;
      await audit("session_open", session,
        `exit=${res.code} heuristic=${loggedInHeuristic}`);

      if (!okExit && !mUrl) {
        const stderr = truncateText(res.stderr || "", 512).text;
        let code = "session_failed";
        if (/已过期/.test(out + stderr)) code = "session_expired";
        else if (/没有|不存在/.test(out + stderr)) code = "unknown_session";
        return {
          ok: false, code,
          error: "会话打开失败",
          detail: truncateText(out + stderr, 800).text,
          hint: "会话可能过期或不存在；需要时用 vault-session save 重新捕获。",
        };
      }

      return {
        ok: true,
        session,
        headless,
        current_url: mUrl ? mUrl[1] : null,
        session_meta_name: mSession ? mSession[1] : session,
        login_heuristic: {
          likely_logged_in: loggedInHeuristic,
          looks_like_login_page: looksLogin,
          heuristic: true,
          warning: "这是启发式判断（看是否跳回登录页/有可见密码框），不是登录有效的证明。",
        },
        must_stop: true,
        stop_hint: "用完请调用 account_vault_browser_stop 关闭浏览器，避免登录态长期暴露。",
        known_limitation:
          "vault-session use 用 Playwright 起独立浏览器且不暴露 CDP 端口，" +
          "因此不能被 account_vault_browser 接管。需要浏览器操作请用 bstart 路径。",
        exit_code: res.code,
      };
    },
  }));

  /* ── 工具：操作浏览器（bctl） ── */
  register(defineTool({
    name: "account_vault_browser",
    description:
      "操作**当前已启动的**浏览器（内部走 bctl，需要先由 bstart 启动并监听 CDP 端口）。\n" +
      "action: nav（导航）/ text（读可见文本）/ click（CSS 选择器点击）/" +
      "clickText（按文字点击）/ fill（填表）/ press（按键）/ eval（执行 JS）/" +
      "shot（截图，**只返回文件路径**）/ elements（列出可交互元素）。\n" +
      "⚠ eval 可执行任意 JS，能力等同于在该页面完全控制，慎用。\n" +
      "⚠ 浏览器 CDP 端口开着时可被同机其它进程接管，用完请 stop。",
    parameters: {
      action: {
        type: "string",
        description: "nav | text | click | clickText | fill | press | eval | shot | elements",
      },
      url: { type: "string", description: "action=nav 时的目标 URL" },
      selector: { type: "string", description: "action=click/fill 时的 CSS 选择器" },
      text: { type: "string", description: "action=clickText 时要匹配的文字" },
      value: { type: "string", description: "action=fill 时要填入的值；action=eval 时的 JS 代码" },
      key: { type: "string", description: "action=press 时的按键，如 Enter" },
      max_chars: { type: "number", description: "text/eval 返回的最大字符数，默认 4000" },
      timeout_ms: { type: "number", description: "超时毫秒，默认 20000" },
    },
    output: { schema: OUTPUT_SCHEMA, render: (_a, v) => textBlock(v) },
    timeoutMs: 40_000,
    async execute(args) {
      const action = typeof args?.action === "string" ? args.action.trim() : "";
      const allowed = ["nav", "text", "click", "clickText", "fill", "press", "eval", "shot", "elements"];
      if (!allowed.includes(action)) {
        return {
          ok: false, code: "bad_args",
          error: "action 必须是: " + allowed.join(" | "),
        };
      }
      const timeoutMs = Math.min(Math.max(Number(args?.timeout_ms) || 20_000, 1000), 35_000);
      const maxChars = Math.min(Math.max(Number(args?.max_chars) || 4000, 100), 20_000);

      const argv = [action];
      switch (action) {
        case "nav": {
          const url = typeof args?.url === "string" ? args.url.trim() : "";
          if (!url) return { ok: false, code: "bad_args", error: "action=nav 需要 url" };
          if (!/^https?:\/\//i.test(url)) {
            return { ok: false, code: "bad_args", error: "url 必须以 http(s):// 开头" };
          }
          argv.push(url);
          break;
        }
        case "click": {
          const sel = typeof args?.selector === "string" ? args.selector.trim() : "";
          if (!sel) return { ok: false, code: "bad_args", error: "action=click 需要 selector" };
          argv.push(sel);
          break;
        }
        case "clickText": {
          const t = typeof args?.text === "string" ? args.text : "";
          if (!t) return { ok: false, code: "bad_args", error: "action=clickText 需要 text" };
          argv.push(t);
          break;
        }
        case "fill": {
          const sel = typeof args?.selector === "string" ? args.selector.trim() : "";
          if (!sel) return { ok: false, code: "bad_args", error: "action=fill 需要 selector" };
          if (typeof args?.value !== "string") {
            return { ok: false, code: "bad_args", error: "action=fill 需要 value" };
          }
          argv.push(sel, args.value);
          break;
        }
        case "press": {
          const k = typeof args?.key === "string" ? args.key.trim() : "";
          if (!k) return { ok: false, code: "bad_args", error: "action=press 需要 key" };
          argv.push(k);
          break;
        }
        case "eval": {
          const js = typeof args?.value === "string" ? args.value : "";
          if (!js) return { ok: false, code: "bad_args", error: "action=eval 需要 value（JS 代码）" };
          argv.push(js);
          break;
        }
        case "shot": {
          // 截图落盘：路径由我们决定，绝不返回内容
          const dir = state.shotDir || join(tmpdir(), "dsh-account-vault-shots");
          try {
            await mkdir(dir, { recursive: true });
          } catch (e) {
            return { ok: false, code: "shot_dir_failed", error: "无法创建截图目录: " + String(e && e.message || e) };
          }
          const p = shotPath(dir);
          argv.push(p);
          break;
        }
        default:
          break;
      }

      const res = await runProcess({
        bin: bins().bctl,
        args: argv,
        timeoutMs,
        maxStdout: 256 * 1024,
      });

      if (res.spawnError) {
        return {
          ok: false, code: "cli_unavailable",
          error: "无法启动 bctl：" + res.spawnError,
          hint: "确认 bctl 存在且可执行。",
        };
      }
      if (res.timedOut) {
        return { ok: false, code: "timeout", error: "浏览器操作超时（已强制终止）" };
      }

      // bctl 在端口未监听/无页面时会失败
      const combined = (res.stdout || "") + (res.stderr || "");
      if (res.code !== 0) {
        let code = "browser_error";
        let hint;
        if (/ECONNREFUSED|未监听|connect/i.test(combined)) {
          code = "browser_not_running";
          hint = "浏览器未启动。请先由 bstart 启动（本插件不自动启动，避免长期暴露 CDP）。";
        } else if (/未找到|no such|not found/i.test(combined)) {
          code = "element_not_found";
          hint = "选择器没匹配到元素；可先 action=elements 查看可交互元素。";
        }
        await audit("browser_action_fail", "-", `action=${action} code=${code}`);
        return {
          ok: false, code,
          error: "浏览器操作失败",
          detail: truncateText(combined, 800).text,
          hint,
          exit_code: res.code,
        };
      }

      await audit("browser_action", "-", `action=${action}`);

      // shot：只返回路径 + 文件信息，不返回内容
      if (action === "shot") {
        const p = argv[argv.length - 1];
        let size = null;
        try {
          const st = await stat(p);
          size = st.size;
        } catch { /* 忽略 */ }
        return {
          ok: true,
          action,
          screenshot_path: p,
          screenshot_bytes: size,
          note: "截图已保存到本地文件，未把图像内容放进上下文。",
        };
      }

      const out = truncateText(res.stdout || "", maxChars);
      const result = {
        ok: true,
        action,
        output: out.text,
        output_truncated: out.truncated,
      };
      if (out.truncated) result.output_note = `输出超过 ${maxChars} 字符已截断`;
      if (action === "eval") {
        result.warning = "eval 执行了任意 JS，返回值可能包含页面上的敏感内容；请谨慎使用。";
      }
      return result;
    },
  }));

  /* ── 工具：关闭浏览器 ── */
  register(defineTool({
    name: "account_vault_browser_stop",
    description:
      "关闭当前浏览器（内部走 bstart --stop），并检查 CDP 端口是否已释放。" +
      "用完浏览器后应当立即调用，避免登录态长期暴露给同机其它进程。",
    parameters: {},
    output: { schema: OUTPUT_SCHEMA, render: (_a, v) => textBlock(v) },
    timeoutMs: 30_000,
    async execute() {
      const res = await runProcess({
        bin: bins().bstart,
        args: ["--stop"],
        timeoutMs: 20_000,
        maxStdout: 16 * 1024,
      });

      if (res.spawnError) {
        return {
          ok: false, code: "cli_unavailable",
          error: "无法启动 bstart：" + res.spawnError,
        };
      }
      if (res.timedOut) {
        return { ok: false, code: "timeout", error: "关闭浏览器超时" };
      }

      // 用 bstart --status 复查端口
      const st = await runProcess({
        bin: bins().bstart,
        args: ["--status"],
        timeoutMs: 10_000,
        maxStdout: 16 * 1024,
      });
      const statusText = (st.stdout || "") + (st.stderr || "");
      const stillRunning = /运行中/.test(statusText);
      const portReleased = !stillRunning;

      await audit("browser_stop", "-", `released=${portReleased}`);

      return {
        ok: portReleased,
        port_released: portReleased,
        stop_exit_code: res.code,
        status_after: truncateText(statusText, 400).text,
        note: portReleased
          ? "浏览器已关闭，CDP 端口已释放。"
          : "浏览器可能仍在运行，CDP 端口尚未释放，请手动确认。",
      };
    },
  }));
}
