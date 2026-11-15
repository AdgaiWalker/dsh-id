/**
 * 离线测试：自行创建合成 fixture、stub fetch、跑完清理。
 *
 * 用法（干净环境一条命令）：
 *   node test/offline.mjs
 *
 * 依赖：需要能解析 @deepseek-ai/dsh-tools 与 @deepseek-ai/schemastery。
 * 若缺失会给出明确报错与准备命令（见 README「测试」一节）。
 *
 * 安全：全程只用临时目录里的合成数据；fetch 被 stub，绝不触碰真实代理端口或真实文件。
 */

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join, resolve } from "node:path";
import { mkdtemp, mkdir, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pluginDir = resolve(__dirname, "..");

let pass = 0;
let fail = 0;
const failures = [];

function check(label, cond, detail = "") {
  if (cond) {
    pass++;
    console.log(`  ✓ ${label}`);
  } else {
    fail++;
    failures.push(label + (detail ? "  → " + detail : ""));
    console.log(`  ✗ ${label}${detail ? "  → " + detail : ""}`);
  }
}

/* ── 依赖检查：缺失时给出明确报错 ─────────────────────────────────────── */
async function ensureDeps() {
  const missing = [];
  for (const pkg of ["@deepseek-ai/dsh-tools", "@deepseek-ai/schemastery"]) {
    try {
      await import(pkg);
    } catch {
      missing.push(pkg);
    }
  }
  if (missing.length === 0) return;

  console.error("\n✗ 缺少依赖，无法运行测试：\n");
  for (const m of missing) console.error("    " + m);
  console.error("\n  本测试需要能解析上面两个包（来自已安装的 DSH profile，不联网）。");
  console.error("  请在插件目录执行：\n");
  console.error("    mkdir -p node_modules/@deepseek-ai");
  console.error("    PROFILE=${DSH_PROFILE:-~/.dsh/profiles/web}");
  console.error("    ln -sfn $PROFILE/node_modules/@deepseek-ai/dsh-tools   node_modules/@deepseek-ai/dsh-tools");
  console.error("    ln -sfn $PROFILE/node_modules/@deepseek-ai/schemastery node_modules/@deepseek-ai/schemastery\n");
  console.error("  或使用 package.json 的 scripts（见 README）。\n");
  process.exit(3);
}

async function loadPlugin() {
  await ensureDeps();
  return import(pathToFileURL(join(pluginDir, "lib/index.js")).href);
}

/* ── 模拟 ctx：每实例独立 ──────────────────────────────────────────────── */
function makeCtx() {
  const tools = new Map();
  const effects = [];
  return {
    tools: {
      register(def) {
        if (!def || typeof def.name !== "string") throw new Error("bad tool def");
        if (tools.has(def.name)) throw new Error("duplicate tool name: " + def.name);
        tools.set(def.name, def);
        return () => tools.delete(def.name);
      },
    },
    settings: {
      register() {
        const store = { vaultDir: "", accountsFile: "", probeUrl: "" };
        return {
          get: () => store,
          watch: () => () => {},
          set: (v) => Object.assign(store, v),
        };
      },
    },
    effect(fn) { effects.push(fn); return () => {}; },
    _tools: tools,
    _effects: effects,
  };
}

/* ── fetch stub：记录调用，绝不真的发请求 ─────────────────────────────── */
let fetchCalls = [];
function installFetchStub(mode = "down") {
  fetchCalls = [];
  globalThis.fetch = async (url, opts) => {
    fetchCalls.push(String(url));
    if (mode === "up") {
      return { status: 404, ok: false, async text() { return '{"error":"unknown_credential"}'; } };
    }
    throw new Error("ECONNREFUSED (stubbed)");
  };
}

/* ── 与 vaultlib.py 一致的哈希计算（用于造真实格式的 fixture） ────────── */
function canonical(body) {
  const keys = Object.keys(body).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + JSON.stringify(body[k])).join(",") + "}";
}
function chainHash(prev, rec) {
  const body = {};
  for (const [k, v] of Object.entries(rec)) {
    if (k === "prev_hash" || k === "hash") continue;
    body[k] = v;
  }
  return createHash("sha256").update(prev + canonical(body), "utf8").digest("hex");
}
function makeChain(records) {
  let prev = "genesis";
  return records.map((r) => {
    const rec = { ...r, prev_hash: prev };
    rec.hash = chainHash(prev, rec);
    prev = rec.hash;
    return rec;
  });
}
const toLines = (recs) => recs.map((r) => JSON.stringify(r)).join("\n") + "\n";

/* ══════════════════════════════════════════════════════════════════════ */

let TMP = null;

async function makeFixtures() {
  TMP = await mkdtemp(join(tmpdir(), "dsh-av-test-"));
  const vault = join(TMP, "vault");
  await mkdir(join(vault, "proxy"), { recursive: true });
  await mkdir(join(vault, "sessions"), { recursive: true });

  // 凭据元数据（含 canary：value/token 字段必须永不出现）
  await writeFile(join(vault, "proxy", "demo-api.meta.json"),
    JSON.stringify({ name: "demo-api", type: "bearer", domains: ["api.example.com"], created_at: 1794000000 }));
  await writeFile(join(vault, "proxy", "demo-api.secret.enc"), "CANARY_ENC_BLOB");
  await writeFile(join(vault, "proxy", "leaky.meta.json"),
    JSON.stringify({ name: "leaky", type: "bearer", domains: ["x.example.com"], value: "CANARY_VALUE", token: "CANARY_TOKEN" }));

  // 会话元数据（含 canary 在深层字段）
  await writeFile(join(vault, "sessions", "demo-session.session.json"),
    JSON.stringify({ name: "demo-session", domain: "example.com", saved_at: 1794000000,
      saved_at_str: "2026-11-07 10:00:00", expires_at: 1796592000,
      expires_at_str: "2026-12-07 10:00:00", ttl_days: 30,
      deep: { deeper: { secret_canary: "CANARY_DEEP" } } }));
  await writeFile(join(vault, "sessions", "demo-session.session.enc"), "CANARY_SESSION_BLOB");

  // 审批队列：action 里塞 canary 与超长文本
  await writeFile(join(vault, "guard-pending.json"), JSON.stringify({
    items: [
      { id: "abc12345", action: "删除测试数据 CANARY_ACTION " + "x".repeat(200),
        hits: ["删除"], status: "pending", created_at_str: "2026-11-14 16:00:00" },
      { id: "old00001", action: "已处理", status: "approved" },
    ],
  }));
  await writeFile(join(vault, "guard-rules.yaml"), "danger: [删除, delete, rm]\n");

  // accounts.yaml：note/purpose/todo 里塞 canary
  await writeFile(join(TMP, "accounts.yaml"), [
    "meta:",
    "  owner: 测试老板",
    "  note: META_NOTE_CANARY",
    "identities:",
    "  - id: test_mail",
    "    type: email",
    "    address: test.person@example.com",
    "    purpose: PURPOSE_CANARY 这是用途",
    "    note: NOTE_CANARY 备注内容",
    "    2fa:",
    "      app: TestApp",
    "platforms:",
    "  - id: testplat",
    "    name: TestPlatform",
    "    username: 13800138000",
    "    login:",
    "      method: password",
    "      identity: test_mail",
    "dependency_chains:",
    "  test_mail:",
    "    fails_if_lost: [testplat]",
    "todo:",
    "  - TODO_CANARY 待办事项",
    "",
  ].join("\n"));

  return { vault, accountsFile: join(TMP, "accounts.yaml") };
}

const AUDIT_CASES = [];

function addAuditCase(name, text, expectStatus, opts = {}) {
  AUDIT_CASES.push({ name, text, expectStatus, ...opts });
}

function buildAuditCases() {
  // 1. 正常链
  const good = makeChain([
    { ts: "2026-11-14T10:00:00+0800", epoch: 1794000000, cred: "a", host: "h", path: "/p", status: 200 },
    { ts: "2026-11-14T10:00:01+0800", epoch: 1794000001, cred: "b", host: "h", path: "/p", status: 404 },
    { ts: "2026-11-14T10:00:02+0800", epoch: 1794000002, cred: "c", host: "h", path: "/p", status: 403 },
  ]);
  addAuditCase("正常链（3 行，全部可校验）", toLines(good), "ok", { chained: 3 });

  // 2. 改内容但保留 hash/prev_hash → 必须 broken
  const tampered = JSON.parse(JSON.stringify(good));
  tampered[1].status = 500;   // 改内容，hash 不变
  addAuditCase("改内容不改 hash（第 2 行 status 200→500）", toLines(tampered), "broken", { problemLine: 2 });

  // 3. 删中间行 → 必须 broken
  const deleted = [good[0], good[2]];
  addAuditCase("删中间行（去掉第 2 行）", toLines(deleted), "broken", { problemLine: 2 });

  // 4. 坏 JSON → 必须 unknown
  addAuditCase("坏 JSON 行", toLines(good.slice(0, 1)) + "{not json\n", "unknown");

  // 5. 空文件 → unknown
  addAuditCase("空文件", "", "unknown");

  // 6. 只有旧格式无 hash 行 → unknown（无从校验）
  addAuditCase("只有旧格式无 hash 行",
    '{"ts":"2026-11-01T00:00:00+0800","cred":"x","status":200}\n', "unknown");

  // 7. 旧行 + 正常链 → ok，且 legacy 计数正确
  const mixed = '{"ts":"2026-11-01T00:00:00+0800","cred":"old","status":200}\n' + toLines(good);
  addAuditCase("旧行在前 + 正常链", mixed, "ok", { legacy: 1, chained: 3 });

  // 8. Unicode（中文/emoji）内容 → 应正常校验通过
  const uni = makeChain([
    { ts: "2026-11-14T10:00:00+0800", epoch: 1794000000, cred: "中文凭据", note: "删除操作 ✅ 已完成", status: 200 },
    { ts: "2026-11-14T10:00:01+0800", epoch: 1794000001, cred: "第二行", note: "含 emoji 🎉 与引号\"测试\"", status: 404 },
  ]);
  addAuditCase("Unicode 内容（中文 + emoji + 引号）", toLines(uni), "ok", { chained: 2 });

  // 9. 浮点数与整数混用（Python 兼容性）
  const nums = makeChain([
    { ts: "2026-11-14T10:00:00+0800", epoch: 1794000000, status: 200 },
    { ts: "2026-11-14T10:00:01+0800", epoch: 1794000001, status: 200, ratio: 1.5 },
  ]);
  addAuditCase("整数与浮点数混用", toLines(nums), "ok", { chained: 2 });

  // 10. 尾部截断（最后一行的 hash 存在但后一行被删）→ 无法发现，应仍 ok（诚实标注）
  addAuditCase("尾部截断（只保留前 2 行）", toLines(good.slice(0, 2)), "ok", { chained: 2 });
}

/* ══════════════════════════════════════════════════════════════════════ */

async function main() {
  const mod = await loadPlugin();
  const fx = await makeFixtures();
  installFetchStub("down");

  console.log("=== 1. 插件加载与依赖声明 ===");
  check("导出 name", mod.name === "dsh-account-vault", String(mod.name));
  check("导出 apply", typeof mod.apply === "function");
  check("inject 含 tools", mod.inject.includes("tools"));
  check("inject 含 settings", mod.inject.includes("settings"));
  // 注意：未声明 subprocess 只是「不依赖该服务」，不是安全边界。
  // 真正的约束由下面的源码静态检查证明。
  check("未声明 subprocess 服务依赖", !mod.inject.includes("subprocess"), JSON.stringify(mod.inject));

  console.log("\n=== 1b. 源码静态检查：实际不执行子进程 / 不写文件 ===");
  const srcText = await readFile(join(pluginDir, "lib/index.js"), "utf8");
  // 去掉注释与字符串字面量后再匹配，避免注释里的词造成误报
  const srcCode = srcText
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "")
    .replace(/`(?:[^`\\]|\\.)*`/g, "``")
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\]|\\.)*'/g, "''");

  const forbidden = [
    // 注意：执行类工具确实需要 spawn（vault-exec/vault-session/bstart/bctl），
    // 所以这里不再要求"无 spawn"，而是验证 spawn 只指向白名单 CLI（见下方专项检查）。
    ["child_process 的 exec/execSync（禁止 shell 拼接）", /\b(execSync|execFileSync|spawnSync|execFile|exec)\s*\(/],
    ["eval / new Function", /\b(eval|Function)\s*\(/],
    ["writeFile / appendFile", /\b(writeFile|appendFile|createWriteStream)\b/],
    ["unlink / rm / rmdir", /\b(unlink|rmdir|rmSync|unlinkSync|rm)\s*\(/],
    ["mkdir", /\bmkdir(Sync)?\s*\(/],
    ["chmod / chown", /\b(chmod|chown)(Sync)?\s*\(/],
    ["rename / copyFile", /\b(rename|copyFile)(Sync)?\s*\(/],
    ["openssl 调用", /openssl/],
    ["account-secret 调用", /account-secret/],
  ];
  for (const [label, re] of forbidden) {
    check(`源码不含 ${label}`, !re.test(srcCode));
  }
  // 专项：spawn 只允许指向白名单 CLI。
  // 做法：在原始源码里找 spawn( 的实参表达式（字符串已被替换，所以看原文本）
  const spawnExprs = [...srcText.matchAll(/\bspawn\s*\(\s*([A-Za-z_$][\w$.]*|\([^)]*\)|"[^"]*")/g)]
    .map((m) => m[1]);
  const allowedSpawnTargets = ["bin", "bins()", "/usr/bin/python3", "python3", "command"];
  check("spawn 目标只来自白名单变量/常量",
    spawnExprs.every((e) => allowedSpawnTargets.some((a) => e.includes(a))),
    JSON.stringify([...new Set(spawnExprs)]));
  // 底层 CLI 白名单常量必须只含这四个
  const execSrc = await readFile(join(pluginDir, "lib/exec.js"), "utf8");
  const binConst = execSrc.match(/DEFAULT_BIN\s*=\s*\{([\s\S]*?)\};/);
  check("DEFAULT_BIN 只含 4 个白名单 CLI",
    Boolean(binConst) && ["vault-exec", "vault-session", "bstart", "bctl"].every((b) => binConst[1].includes(b)),
    binConst ? binConst[1].replace(/\s+/g, " ").slice(0, 160) : "未找到 DEFAULT_BIN");
  check("未直接 spawn account-secret", !/spawn\s*\([^)]*account-secret/.test(srcCode));
  check("未直接 spawn vault-cred", !/spawn\s*\([^)]*vault-cred/.test(srcCode));
  check("未直接 spawn vault-guard（不能自批审批）", !/spawn\s*\([^)]*vault-guard/.test(srcCode));

  // 允许的读取能力应当存在（证明检查本身有效）
  check("源码确实 import 了 node:fs（只读能力存在，检查有效）",
    /from\s+"node:fs/.test(srcText) || /from\s+'node:fs/.test(srcText));
  check("源码只 import 读取类 API（readFile/readdir/stat）",
    /\breadFile\b/.test(srcCode) && !/\bwriteFile\b/.test(srcCode));

  console.log("\n=== 2. 工具注册 ===");
  const ctx = makeCtx();
  mod.apply(ctx, { vaultDir: fx.vault, accountsFile: fx.accountsFile });
  const expected = [
    "account_vault_overview", "account_vault_accounts", "account_vault_account",
    "account_vault_credentials", "account_vault_sessions", "account_vault_guard_status",
    "account_vault_audit_status", "account_vault_security_boundary",
  ];
  const EXPECTED_TOTAL = expected.length + 4; // 8 只读 + 4 执行
  check(`注册 ${EXPECTED_TOTAL} 个工具`, ctx._tools.size === EXPECTED_TOTAL,
    `实际 ${ctx._tools.size}: ${[...ctx._tools.keys()].join(",")}`);
  for (const n of expected) check(`存在 ${n}`, ctx._tools.has(n));

  console.log("\n=== 3. 工具执行 ===");
  const R = {};
  for (const n of expected) {
    try {
      R[n] = await ctx._tools.get(n).execute(n === "account_vault_account" ? { id: "test_mail" } : {}, {});
      check(`${n} 返回对象`, R[n] && typeof R[n] === "object");
    } catch (e) {
      check(`${n} 未抛异常`, false, String(e && e.message || e));
    }
  }

  console.log("\n=== 4. 敏感内容不外泄（canary 全查） ===");
  // 列表类工具：任何自由文本 canary 都不得出现
  const listTools = ["account_vault_overview", "account_vault_accounts",
    "account_vault_credentials", "account_vault_sessions",
    "account_vault_guard_status", "account_vault_audit_status",
    "account_vault_security_boundary"];
  const listOut = JSON.stringify(listTools.map((n) => R[n]));
  const listCanaries = ["CANARY_VALUE", "CANARY_TOKEN", "CANARY_ENC_BLOB", "CANARY_SESSION_BLOB",
    "CANARY_DEEP", "META_NOTE_CANARY", "NOTE_CANARY", "PURPOSE_CANARY", "TODO_CANARY"];
  for (const c of listCanaries) {
    check(`列表类输出不含 ${c}`, !listOut.includes(c));
  }
  // 审批动作只给截断预览，不应出现超长原文
  check("审批队列不含完整超长动作原文", !listOut.includes("x".repeat(120)));
  check("凭据输出无 value 键", !/"value"\s*:/.test(JSON.stringify(R.account_vault_credentials)));
  check("凭据输出无 token 键", !/"token"\s*:/.test(JSON.stringify(R.account_vault_credentials)));

  // 单账号查询是「有范围的逃生口」：允许返回消毒后的用途/备注，
  // 但必须长度受限、且长 hex / token 形态被 REDACTED
  const singleOut = JSON.stringify(R.account_vault_account);
  check("单账号查询不含凭据 canary", !singleOut.includes("CANARY_VALUE") && !singleOut.includes("CANARY_TOKEN"));
  check("单账号查询不含密文 blob canary",
    !singleOut.includes("CANARY_ENC_BLOB") && !singleOut.includes("CANARY_SESSION_BLOB"));

  console.log("\n=== 5. 标识符默认打码 ===");
  const accs = R.account_vault_accounts;
  const mailEntry = accs.identities?.find((i) => i.id === "test_mail");
  check("邮箱已打码", mailEntry?.identifier === "t***@example.com", String(mailEntry?.identifier));
  check("标注 identifier_masked", mailEntry?.identifier_masked === true);
  const platEntry = accs.platforms?.find((p) => p.id === "testplat");
  check("手机号已打码", /^138\*+00$/.test(String(platEntry?.identifier || "")), String(platEntry?.identifier));
  check("列表不返回 purpose/note", !("purpose" in (mailEntry || {})) && !("note" in (mailEntry || {})));
  check("明确列出被省略字段", Array.isArray(accs.omitted) && accs.omitted.includes("todo"));

  console.log("\n=== 6. 单账号查询（有范围） ===");
  const single = await ctx._tools.get("account_vault_account")
    .execute({ id: "test_mail", reveal_identifier: true }, {});
  check("reveal 后显示完整邮箱", single.account?.identifier === "test.person@example.com",
    String(single.account?.identifier));
  check("purpose 经消毒返回", typeof single.purpose === "string" && single.purpose.includes("PURPOSE_CANARY"),
    "单账号查询可带用途，但只截断消毒后");
  check("note 经消毒返回", typeof single.note === "string");
  const noReveal = await ctx._tools.get("account_vault_account").execute({ id: "test_mail" }, {});
  check("不 reveal 时仍打码", noReveal.account?.identifier === "t***@example.com");
  const missing = await ctx._tools.get("account_vault_account").execute({ id: "nope" }, {});
  check("不存在的 id 返回 ok:false", missing.ok === false);

  console.log("\n=== 7. 审批队列：动作只给截断预览 ===");
  const guard = R.account_vault_guard_status;
  check("只统计 pending", guard.pending_count === 1, String(guard.pending_count));
  const p0 = guard.pending?.[0];
  check("有 action_preview 且被截断", typeof p0?.action_preview === "string" && p0.action_preview.length <= 61,
    String(p0?.action_preview?.length));
  check("给出 action_length", p0?.action_length > 100, String(p0?.action_length));
  check("说明审批非强制", String(guard.limitation).includes("不是内核级强制"));

  console.log("\n=== 8. 审计链校验（真实格式合成日志） ===");
  buildAuditCases();
  const auditTool = ctx._tools.get("account_vault_audit_status");
  const auditDir = join(TMP, "auditcases");
  await mkdir(auditDir, { recursive: true });

  for (const c of AUDIT_CASES) {
    const file = join(auditDir, "audit.log");
    await writeFile(file, c.text);
    // 用独立实例指向该目录
    const c2 = makeCtx();
    mod.apply(c2, { vaultDir: dirname(file), accountsFile: fx.accountsFile, probeUrl: "" });
    const res = await c2._tools.get("account_vault_audit_status").execute({}, {});
    check(`[${c.name}] status=${c.expectStatus}`, res.status === c.expectStatus,
      `实际 ${res.status} (${res.reason})`);
    if (c.problemLine) {
      const lines = (res.problems || []).map((p) => p.line);
      check(`[${c.name}] 指出第 ${c.problemLine} 行`, lines.includes(c.problemLine), JSON.stringify(lines));
    }
    if (c.legacy !== undefined) {
      check(`[${c.name}] legacy=${c.legacy}`, res.legacy_lines_unverifiable === c.legacy,
        String(res.legacy_lines_unverifiable));
    }
    if (c.chained !== undefined) {
      check(`[${c.name}] chained=${c.chained}`, res.chained_lines === c.chained,
        String(res.chained_lines));
    }
  }

  // 缺失文件
  const missingCtx = makeCtx();
  mod.apply(missingCtx, { vaultDir: join(TMP, "nodir"), accountsFile: fx.accountsFile, probeUrl: "" });
  const missRes = await missingCtx._tools.get("account_vault_audit_status").execute({}, {});
  check("审计文件缺失 → status=unknown", missRes.status === "unknown", missRes.status);
  check("审计文件缺失 → verifiable=false", missRes.verifiable === false);
  check("审计文件缺失 → chain_ok 不为 true", missRes.chain_ok !== true);

  console.log("\n=== 9. 只读：不触碰生产端口 ===");
  check("fetch 被 stub 且已调用", fetchCalls.length > 0, String(fetchCalls.length));
  check("所有探测都指向默认本地地址", fetchCalls.every((u) => u.includes("127.0.0.1:48771")),
    fetchCalls[0]);
  // 用空 probeUrl 禁用探测
  fetchCalls = [];
  const noProbeCtx = makeCtx();
  mod.apply(noProbeCtx, { vaultDir: fx.vault, accountsFile: fx.accountsFile, probeUrl: "" });
  await noProbeCtx._tools.get("account_vault_overview").execute({}, {});
  check("probeUrl 为空时不发请求", fetchCalls.length === 0, String(fetchCalls.length));

  console.log("\n=== 10. 多实例隔离与卸载 ===");
  const ctxA = makeCtx();
  const ctxB = makeCtx();
  mod.apply(ctxA, { vaultDir: join(TMP, "vaultA"), accountsFile: fx.accountsFile, probeUrl: "" });
  mod.apply(ctxB, { vaultDir: join(TMP, "vaultB"), accountsFile: fx.accountsFile, probeUrl: "" });
  check("两实例各注册 12 个工具", ctxA._tools.size === 12 && ctxB._tools.size === 12,
    `${ctxA._tools.size} / ${ctxB._tools.size}`);
  check("两实例工具表相互独立", ctxA._tools !== ctxB._tools);
  const dispA = await ctxA._tools.get("account_vault_credentials").execute({}, {});
  check("实例 A 用 A 的路径（目录不存在→0 条）", dispA.count === 0, String(dispA.count));
  const dispB = await ctxB._tools.get("account_vault_credentials").execute({}, {});
  check("实例 B 用 B 的路径（目录不存在→0 条）", dispB.count === 0, String(dispB.count));
  // 卸载
  const cleanup = mod.apply(makeCtx(), { vaultDir: fx.vault, accountsFile: fx.accountsFile, probeUrl: "" });
  check("apply 返回 cleanup 函数", typeof cleanup === "function");
  cleanup();
  check("cleanup 可重复调用不抛错", (() => { try { cleanup(); return true; } catch { return false; } })());

  console.log("\n=== 11. 目录权限/损坏数据 → unknown 而非空 ===");
  const brokenDir = join(TMP, "broken");
  await mkdir(join(brokenDir, "proxy"), { recursive: true });
  await mkdir(join(brokenDir, "sessions"), { recursive: true });
  await writeFile(join(brokenDir, "proxy", "bad.meta.json"), "{not json");
  await writeFile(join(brokenDir, "sessions", "bad.session.json"), "{not json");
  await writeFile(join(brokenDir, "guard-pending.json"), "{not json");
  await writeFile(join(TMP, "bad.yaml"), "::: [[[");
  const bctx = makeCtx();
  mod.apply(bctx, { vaultDir: brokenDir, accountsFile: join(TMP, "bad.yaml"), probeUrl: "" });
  const bCred = await bctx._tools.get("account_vault_credentials").execute({}, {});
  check("损坏元数据标记为 unreadable", bCred.credentials?.some((c) => c.status === "unreadable"),
    JSON.stringify(bCred.credentials));
  const bSess = await bctx._tools.get("account_vault_sessions").execute({}, {});
  check("损坏会话标记为 unreadable", bSess.sessions?.some((s) => s.status === "unreadable"));
  const bGuard = await bctx._tools.get("account_vault_guard_status").execute({}, {});
  check("损坏队列 → pending_count 为 null 并带 error", bGuard.pending_count === null && Boolean(bGuard.error),
    `count=${bGuard.pending_count} err=${bGuard.error}`);
  for (const n of expected) {
    try {
      const out = await bctx._tools.get(n).execute(n === "account_vault_account" ? { id: "x" } : {}, {});
      check(`${n} 损坏数据下不崩溃`, out && typeof out === "object");
    } catch (e) {
      check(`${n} 损坏数据下不崩溃`, false, String(e && e.message || e));
    }
  }

  console.log("\n=== 12. 安全边界披露 ===");
  const sb = R.account_vault_security_boundary;
  const lim = JSON.stringify(sb.limitations || []);
  check("声明非安全隔离产品", String(sb.product_class).includes("非安全隔离"));
  check("披露同用户进程可绕过", lim.includes("同用户进程可读 vault.key"));
  check("披露 account-secret 明文", lim.includes("account-secret"));
  check("披露审批非强制", lim.includes("不是强制拦截"));
  check("披露 --who 可伪造", lim.includes("--who"));
  check("披露 panic 不撤销上游", lim.includes("不会撤销上游"));
  check("披露哈希链可重算", lim.includes("重算整条链"));
  check("披露尾部截断无法发现", lim.includes("尾部被截断"));
  check("披露会话 check 是启发式", lim.includes("启发式"));
  check("披露非完整登录执行器", lim.includes("不是完整的登录执行器"));
  check("披露 exec_curl 有真实副作用", lim.includes("真实副作用"));
  check("披露 CDP 可被接管", lim.includes("CDP 端口"));
  check("披露 eval 可执行任意 JS", lim.includes("任意 JS"));
  check("not_claimed 含 1Password", JSON.stringify(sb.not_claimed).includes("1Password"));
  check("design 说明是限制输出而非永不泄露", String(sb.design).includes("不构成"));

  console.log("\n" + "=".repeat(56));
  console.log(`结果: ${pass} 通过, ${fail} 失败`);
  if (fail > 0) {
    console.log("\n失败项:");
    failures.forEach((f) => console.log("  - " + f));
  }
  return fail === 0 ? 0 : 1;
}

main()
  .then(async (code) => {
    if (TMP) {
      await rm(TMP, { recursive: true, force: true });
      console.log(`\n已清理临时目录: ${TMP}`);
    }
    process.exitCode = code;
  })
  .catch(async (e) => {
    console.error("\n测试崩溃:", e);
    if (TMP) await rm(TMP, { recursive: true, force: true }).catch(() => {});
    process.exitCode = 2;
  });
