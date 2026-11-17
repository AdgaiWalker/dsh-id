/**
 * 执行类工具测试：用 mock 底层 CLI + 本地 HTTP 服务，不碰真实凭据。
 *
 * 覆盖：
 *   - exec_curl：成功 / 白名单拒绝 / 超时 / 404 / 响应体截断 / canary 不泄露
 *   - session_open：成功 / 过期 / 不存在 / heuristic 标注
 *   - browser：各 action / 截图只返回路径 / 未启动 / eval 警告
 *   - browser_stop：端口释放判定
 *   - 所有工具都有超时、错误分类清晰
 */

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join, resolve } from "node:path";
import { mkdtemp, mkdir, writeFile, chmod, rm, stat, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { createServer } from "node:http";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pluginDir = resolve(__dirname, "..");

let pass = 0, fail = 0;
const failures = [];
function check(label, cond, detail = "") {
  if (cond) { pass++; console.log(`  ✓ ${label}`); }
  else { fail++; failures.push(label + (detail ? " → " + detail : "")); console.log(`  ✗ ${label}${detail ? "  → " + detail : ""}`); }
}

const CANARY = "CANARY_SECRET_VALUE_9f3a2b";

let TMP = null;

/* ── mock 底层 CLI ─────────────────────────────────────────────────────── */

async function writeMockBins(dir) {
  const binDir = join(dir, "bin");
  await mkdir(binDir, { recursive: true });

  // mock vault-exec：根据参数模拟各种情况
  const vaultExec = `#!/usr/bin/env node
const args = process.argv.slice(2);
const cred = args[0], url = args[1] || "";
const has = (f) => args.includes(f);
const body = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i+1] : null; };

if (process.env.MOCK_MODE === "no_cred") { process.stderr.write("vault-exec: 凭据不存在\\n"); process.exit(3); }
if (process.env.MOCK_MODE === "denied") { process.stderr.write("vault-exec: 拒绝 —— evil.com 不在白名单\\n"); process.exit(4); }
if (process.env.MOCK_MODE === "locked") { process.stderr.write("vault-exec: 解密失败\\n"); process.exit(5); }
if (process.env.MOCK_MODE === "slow") { setTimeout(() => {}, 60000); return; }
if (process.env.MOCK_MODE === "404") {
  process.stdout.write('{"message":"Not Found"}\\n__VAULT_STATUS__:404');
  process.exit(0);
}
if (process.env.MOCK_MODE === "big") {
  const big = "x".repeat(20000);
  process.stdout.write(big + '\\n__VAULT_STATUS__:200');
  process.exit(0);
}
if (process.env.MOCK_MODE === "leak") {
  // 故意让"响应体"里带上 canary，验证插件不额外泄露它自己不该加的
  process.stdout.write('{"login":"tester"}\\n__VAULT_STATUS__:200');
  process.exit(0);
}
process.stdout.write('{"login":"tester","id":123}\\n__VAULT_STATUS__:200');
process.exit(0);
`;

  // mock vault-session
  const vaultSession = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (process.env.MOCK_MODE === "expired") {
  process.stdout.write("✗ 会话 test 已过期（2026-01-01 00:00:00）。\\n");
  process.exit(1);
}
if (process.env.MOCK_MODE === "nosession") {
  process.stdout.write("✗ 会话不存在: test\\n");
  process.exit(1);
}
process.stdout.write([
  "=== 会话已恢复 ===",
  "会话:   test-session",
  "域名:   example.com",
  "保存于: 2026-11-01 10:00:00",
  "过期于: 2026-12-01 10:00:00",
  "模式:   headless",
  "打开:   https://example.com/",
  "当前页: https://example.com/dashboard",
  "✓ 看起来已登录（未被踢回登录页）",
  ""
].join("\\n"));
process.exit(0);
`;

  // mock bctl
  const bctl = `#!/usr/bin/env node
const args = process.argv.slice(2);
const action = args[0];
if (process.env.MOCK_MODE === "notrunning") {
  process.stderr.write("Error: connect ECONNREFUSED 127.0.0.1:9222\\n");
  process.exit(1);
}
if (process.env.MOCK_MODE === "noselector") {
  process.stderr.write("未找到元素: #nope\\n");
  process.exit(1);
}
if (action === "shot") {
  const p = args[args.length-1];
  require('fs').writeFileSync(p, 'FAKE_PNG_BYTES');
  process.stdout.write("截图已保存: " + p + "\\n");
  process.exit(0);
}
if (action === "text") { process.stdout.write("页面文本内容示例\\n"); process.exit(0); }
if (action === "eval") { process.stdout.write(JSON.stringify({result: 42}) + "\\n"); process.exit(0); }
if (action === "elements") { process.stdout.write("button#submit\\ninput[name=q]\\n"); process.exit(0); }
if (action === "nav") { process.stdout.write("navigated to " + args[1] + "\\n"); process.exit(0); }
process.stdout.write("ok\\n"); process.exit(0);
`;

  // mock bstart
  const bstart = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args.includes("--status")) {
  const running = process.env.MOCK_BROWSER === "running";
  process.stdout.write(running ? "运行中 (pid=1234, 端口=9222, 模式=无头)\\n" : "未运行 (端口 9222 未监听)\\n");
  process.exit(0);
}
if (args.includes("--stop")) {
  process.stdout.write("已停止\\n");
  process.exit(0);
}
process.stdout.write("started\\n");
process.exit(0);
`;

  const files = { "vault-exec": vaultExec, "vault-session": vaultSession, "bctl": bctl, "bstart": bstart };
  const paths = {};
  for (const [name, content] of Object.entries(files)) {
    const p = join(binDir, name);
    await writeFile(p, content);
    await chmod(p, 0o755);
    paths[name] = p;
  }
  return {
    vaultExec: paths["vault-exec"],
    vaultSession: paths["vault-session"],
    bctl: paths["bctl"],
    bstart: paths["bstart"],
  };
}

/* ── 加载插件 ─────────────────────────────────────────────────────────── */

async function loadPlugin() {
  for (const pkg of ["@deepseek-ai/dsh-tools", "@deepseek-ai/schemastery"]) {
    try { await import(pkg); } catch {
      console.error(`\n✗ 缺少依赖 ${pkg}。请先运行: npm run prepare:test-deps\n`);
      process.exit(3);
    }
  }
  return import(pathToFileURL(join(pluginDir, "lib/index.js")).href);
}

function makeCtx() {
  const tools = new Map();
  return {
    tools: { register(def) { tools.set(def.name, def); return () => tools.delete(def.name); } },
    settings: { register() { return { get: () => ({}), watch: () => () => {}, dispose: () => {} }; } },
    effect(fn) { return () => {}; },
    _tools: tools,
  };
}

/* ══════════════════════════════════════════════════════════════════════ */

async function main() {
  const mod = await loadPlugin();
  TMP = await mkdtemp(join(tmpdir(), "dsh-av-exec-"));
  const vault = join(TMP, "vault");
  await mkdir(join(vault, "proxy"), { recursive: true });
  await mkdir(join(vault, "sessions"), { recursive: true });
  await writeFile(join(TMP, "accounts.yaml"), "identities: []\nplatforms: []\n");
  await writeFile(join(vault, "audit.log"), "");

  const bins = await writeMockBins(TMP);
  const shotDir = join(TMP, "shots");

  // 拦截真实 fetch（插件探测用）
  globalThis.fetch = async () => { throw new Error("stubbed"); };

  const mkPlugin = () => {
    const ctx = makeCtx();
    mod.apply(ctx, {
      vaultDir: vault,
      accountsFile: join(TMP, "accounts.yaml"),
      probeUrl: "",
      bins,
      shotDir,
    });
    return ctx;
  };

  const ctx = mkPlugin();

  console.log("=== 1. 执行类工具已注册 ===");
  const execTools = ["account_vault_exec_curl", "account_vault_session_open",
    "account_vault_browser", "account_vault_browser_stop"];
  for (const n of execTools) check(`存在 ${n}`, ctx._tools.has(n));
  check("工具总数 8", ctx._tools.size === 8, String(ctx._tools.size));

  console.log("\n=== 2. exec_curl 成功路径 ===");
  process.env.MOCK_MODE = "";
  const r1 = await ctx._tools.get("account_vault_exec_curl")
    .execute({ credential: "demo", url: "https://api.example.com/user" }, {});
  check("返回 ok", r1.ok === true, JSON.stringify(r1).slice(0, 120));
  check("解析出 http_status=200", r1.http_status === 200, String(r1.http_status));
  check("返回响应体", typeof r1.body === "string" && r1.body.includes("tester"));
  check("回显凭据名（非值）", r1.credential === "demo");
  check("不含 canary", !JSON.stringify(r1).includes(CANARY));

  console.log("\n=== 3. exec_curl 白名单拒绝 ===");
  process.env.MOCK_MODE = "denied";
  const r2 = await ctx._tools.get("account_vault_exec_curl")
    .execute({ credential: "demo", url: "https://evil.com/x" }, {});
  check("ok=false", r2.ok === false);
  check("错误码 host_not_allowed", r2.code === "host_not_allowed", String(r2.code));
  check("有清晰错误信息", typeof r2.error === "string" && r2.error.length > 0);

  console.log("\n=== 4. exec_curl 凭据不存在 ===");
  process.env.MOCK_MODE = "no_cred";
  const r3 = await ctx._tools.get("account_vault_exec_curl")
    .execute({ credential: "nope", url: "https://api.example.com/x" }, {});
  check("错误码 unknown_credential", r3.code === "unknown_credential", String(r3.code));

  console.log("\n=== 5. exec_curl 保险库锁定 ===");
  process.env.MOCK_MODE = "locked";
  const r4 = await ctx._tools.get("account_vault_exec_curl")
    .execute({ credential: "demo", url: "https://api.example.com/x" }, {});
  check("错误码 vault_locked", r4.code === "vault_locked", String(r4.code));

  console.log("\n=== 6. exec_curl 超时 ===");
  process.env.MOCK_MODE = "slow";
  const t0 = Date.now();
  const r5 = await ctx._tools.get("account_vault_exec_curl")
    .execute({ credential: "demo", url: "https://api.example.com/x", timeout_ms: 1500 }, {});
  const elapsed = Date.now() - t0;
  check("错误码 timeout", r5.code === "timeout", String(r5.code));
  check("确实在超时后返回（<15s）", elapsed < 15000, elapsed + "ms");

  console.log("\n=== 7. exec_curl 404（HTTP 层失败但进程成功）===");
  process.env.MOCK_MODE = "404";
  const r6 = await ctx._tools.get("account_vault_exec_curl")
    .execute({ credential: "demo", url: "https://api.example.com/missing" }, {});
  check("ok=true（请求本身完成）", r6.ok === true);
  check("http_status=404", r6.http_status === 404, String(r6.http_status));
  check("响应体可读", typeof r6.body === "string" && r6.body.includes("Not Found"));

  console.log("\n=== 8. exec_curl 响应体截断（>8KB）===");
  process.env.MOCK_MODE = "big";
  const r7 = await ctx._tools.get("account_vault_exec_curl")
    .execute({ credential: "demo", url: "https://api.example.com/big" }, {});
  check("body_truncated=true", r7.body_truncated === true);
  check("截断到 8KB 以内", Buffer.byteLength(r7.body, "utf8") <= 8192,
    String(Buffer.byteLength(r7.body, "utf8")));
  check("标注了原始大小", typeof r7.body_bytes === "number" && r7.body_bytes > 8192,
    String(r7.body_bytes));
  check("有截断说明", typeof r7.body_note === "string" && r7.body_note.includes("截断"));

  console.log("\n=== 9. exec_curl 参数校验 ===");
  process.env.MOCK_MODE = "";
  const b1 = await ctx._tools.get("account_vault_exec_curl").execute({}, {});
  check("缺 credential → bad_args", b1.code === "bad_args", String(b1.code));
  const b2 = await ctx._tools.get("account_vault_exec_curl").execute({ credential: "x" }, {});
  check("缺 url → bad_args", b2.code === "bad_args");
  const b3 = await ctx._tools.get("account_vault_exec_curl")
    .execute({ credential: "x", url: "ftp://bad" }, {});
  check("非 http(s) URL → bad_args", b3.code === "bad_args");

  console.log("\n=== 10. session_open 成功 + heuristic 标注 ===");
  process.env.MOCK_MODE = "";
  const s1 = await ctx._tools.get("account_vault_session_open")
    .execute({ session: "test-session" }, {});
  check("ok=true", s1.ok === true, JSON.stringify(s1).slice(0, 150));
  check("返回当前 URL", typeof s1.current_url === "string" && s1.current_url.includes("example.com"),
    String(s1.current_url));
  check("登录判断标 heuristic=true", s1.login_heuristic?.heuristic === true);
  check("heuristic 带警告说明", typeof s1.login_heuristic?.warning === "string" &&
    s1.login_heuristic.warning.includes("不是登录有效的证明"));
  check("提示必须 stop", s1.must_stop === true);
  check("说明不能与 browser 共用", typeof s1.known_limitation === "string" &&
    s1.known_limitation.includes("不能被 account_vault_browser 接管"));

  console.log("\n=== 11. session_open 过期 / 不存在 ===");
  process.env.MOCK_MODE = "expired";
  const s2 = await ctx._tools.get("account_vault_session_open").execute({ session: "old" }, {});
  check("过期 → session_expired", s2.code === "session_expired", String(s2.code));
  process.env.MOCK_MODE = "nosession";
  const s3 = await ctx._tools.get("account_vault_session_open").execute({ session: "nope" }, {});
  check("不存在 → unknown_session", s3.code === "unknown_session", String(s3.code));

  console.log("\n=== 12. browser 各 action ===");
  process.env.MOCK_MODE = "";
  const browser = (a) => ctx._tools.get("account_vault_browser").execute(a, {});
  const nav = await browser({ action: "nav", url: "https://example.com" });
  check("nav ok", nav.ok === true, JSON.stringify(nav).slice(0, 100));
  const txt = await browser({ action: "text" });
  check("text 返回内容", txt.ok === true && txt.output.includes("页面文本"));
  const els = await browser({ action: "elements" });
  check("elements 返回列表", els.ok === true && els.output.includes("button"));
  const ev = await browser({ action: "eval", value: "1+1" });
  check("eval 返回结果", ev.ok === true);
  check("eval 带警告", typeof ev.warning === "string" && ev.warning.includes("任意 JS"));

  console.log("\n=== 13. browser 截图只返回路径 ===");
  const shot = await browser({ action: "shot" });
  check("shot ok", shot.ok === true, JSON.stringify(shot).slice(0, 150));
  check("返回 screenshot_path", typeof shot.screenshot_path === "string");
  check("路径是本地绝对路径", shot.screenshot_path.startsWith("/"), shot.screenshot_path);
  check("不含 base64 字段", !("base64" in shot) && !("image" in shot) && !("data" in shot));
  check("返回体不含 PNG 字节", !JSON.stringify(shot).includes("FAKE_PNG"));
  // 文件确实存在
  let shotExists = false, shotSize = 0;
  try { const st = await stat(shot.screenshot_path); shotExists = st.isFile(); shotSize = st.size; } catch {}
  check("截图文件确实落盘", shotExists);
  check("返回文件大小", shot.screenshot_bytes === shotSize, `${shot.screenshot_bytes} vs ${shotSize}`);

  console.log("\n=== 14. browser 错误分类 ===");
  process.env.MOCK_MODE = "notrunning";
  const nb = await browser({ action: "text" });
  check("未启动 → browser_not_running", nb.code === "browser_not_running", String(nb.code));
  check("给出启动提示", typeof nb.hint === "string" && nb.hint.includes("bstart"));
  process.env.MOCK_MODE = "noselector";
  const ns = await browser({ action: "click", selector: "#nope" });
  check("选择器未命中 → element_not_found", ns.code === "element_not_found", String(ns.code));
  process.env.MOCK_MODE = "";
  const bad = await browser({ action: "notanaction" });
  check("非法 action → bad_args", bad.code === "bad_args", String(bad.code));

  console.log("\n=== 15. browser_stop 端口释放判定 ===");
  process.env.MOCK_BROWSER = "stopped";
  const stop1 = await ctx._tools.get("account_vault_browser_stop").execute({}, {});
  check("已停止 → port_released=true", stop1.port_released === true);
  check("ok=true", stop1.ok === true);
  process.env.MOCK_BROWSER = "running";
  const stop2 = await ctx._tools.get("account_vault_browser_stop").execute({}, {});
  check("仍在运行 → port_released=false", stop2.port_released === false);
  check("ok=false", stop2.ok === false);
  process.env.MOCK_BROWSER = "";

  console.log("\n=== 16. 不提供 approve/reject 工具 ===");
  const allNames = [...ctx._tools.keys()];
  check("无 approve 工具", !allNames.some((n) => /approve/.test(n)), allNames.join(","));
  check("无 reject 工具", !allNames.some((n) => /reject/.test(n)));
  check("无 get/login 凭据明文工具", !allNames.some((n) => /secret|password|get_secret/.test(n)));

  console.log("\n=== 17. 审计已写入且不含 canary ===");
  const auditText = await readFile(join(vault, "audit.log"), "utf8").catch(() => "");
  check("审计文件有内容", auditText.length > 0, auditText.length + " bytes");
  check("审计不含 canary 凭据值", !auditText.includes(CANARY));
  check("审计记录了 exec_curl", /exec_curl/.test(auditText), auditText.slice(0, 200));

  console.log("\n=== 18. 所有工具都有超时设置 ===");
  for (const [n, def] of ctx._tools) {
    check(`${n} 声明了 timeoutMs`, typeof def.timeoutMs === "number" && def.timeoutMs > 0,
      String(def.timeoutMs));
  }

  console.log("\n" + "=".repeat(56));
  console.log(`结果: ${pass} 通过, ${fail} 失败`);
  if (fail > 0) { console.log("\n失败项:"); failures.forEach((f) => console.log("  - " + f)); }
  return fail === 0 ? 0 : 1;
}

main()
  .then(async (code) => {
    if (TMP) { await rm(TMP, { recursive: true, force: true }); console.log(`\n已清理: ${TMP}`); }
    process.exitCode = code;
  })
  .catch(async (e) => {
    console.error("\n测试崩溃:", e);
    if (TMP) await rm(TMP, { recursive: true, force: true }).catch(() => {});
    process.exitCode = 2;
  });
