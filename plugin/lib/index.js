/**
 * dsh-account-vault — 只读的账号与凭据「状态」插件
 *
 * 设计目标：让 AI 在不读取任何密文的前提下，了解账号/凭据/会话的**元数据状态**。
 *
 * 诚实定位（不要升级成更强的说法）：
 *   - 本插件**设计为不读取密文**：它只读元数据 JSON、文件名与目录列表，
 *     从不调用解密路径，也不执行任何外部命令（未申请 subprocess 权限）。
 *   - 它**限制输出**：字段走严格白名单，自由文本默认不回传，标识符默认打码。
 *   - 但这**不是**「永不泄露」的保证：输出仍可能包含敏感元数据（账号关系、域名），
 *     底层系统还有其它可输出明文的命令，本插件管不到。
 *
 * 明确不做：
 *   - 不返回密码、token、TOTP 种子/验证码、cookie、恢复码
 *   - 不提供 approve/reject，不提供批量授权，不提供 get/login 包装
 *   - 不修改任何文件（无 write/unlink/mkdir 调用）
 */

import { defineTool } from "@deepseek-ai/dsh-tools";
import z from "@deepseek-ai/schemastery";
import { readFile, readdir, stat, mkdtemp } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { homedir, tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { registerExecTools } from "./exec.js";

/**
 * 写审计：委托给底层 vaultlib（复用哈希链），只写元信息。
 * 用子进程调 python 是因为审计链格式由 vaultlib 定义，重复实现会漂移。
 * 失败不阻断主流程；调用方必须保证 note 不含凭据值。
 */
/**
 * 写审计：复用底层 vaultlib 的哈希链实现，只写元信息。
 *
 * 关键：必须写到**当前实例配置的 vault 目录**（通过 VAULT_DIR_OVERRIDE 传进去），
 * 否则测试会污染生产审计日志，且审计会记到错误的位置。
 * 用同步等待（await）保证写入落盘，避免 unref 导致进程退出时丢失。
 * 调用方必须保证 note 不含凭据值。
 */
function V_auditEvent(fields, vaultDir) {
  const py = [
    "import sys, json",
    `sys.path.insert(0, ${JSON.stringify(process.env.DSH_ID_LIB || join(homedir(), ".local", "lib"))})`,
    "import vaultlib as V",
    "f = json.loads(sys.stdin.read())",
    "V.audit_event(**f)",
  ].join("\n");
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn("/usr/bin/python3", ["-c", py], {
        stdio: ["pipe", "ignore", "ignore"],
        env: vaultDir
          ? { ...process.env, VAULT_DIR_OVERRIDE: vaultDir }
          : process.env,
      });
    } catch {
      resolve(false);
      return;
    }
    const timer = setTimeout(() => {
      try { child.kill("SIGKILL"); } catch { /* ignore */ }
      resolve(false);
    }, 5000);
    child.on("close", () => { clearTimeout(timer); resolve(true); });
    child.on("error", () => { clearTimeout(timer); resolve(false); });
    try { child.stdin.end(JSON.stringify(fields)); } catch { /* ignore */ }
  });
}

export const name = "dsh-account-vault";
// 依赖声明：本插件只用 tools 与 settings 两个 Cordis 服务。
//
// ⚠ 这不是安全边界。未声明 subprocess 只表示「不依赖该服务」，
// Node 插件仍以用户进程权限运行，可以自行 import node:fs / node:child_process / 发起网络请求。
// 本插件确实会 spawn 子进程（vault-exec / vault-session / bstart / bctl），
// 这是执行类工具的必要条件，不是安全隔离。
export const inject = ["tools", "settings"];

const SETTINGS_NAMESPACE = "account-vault";

const SETTINGS_SCHEMA = z.object({
  vaultDir: z.string().default(""),
  accountsFile: z.string().default(""),
  probeUrl: z.string().default(""),
});

const NO_PARAMS = {};
const OUTPUT_SCHEMA = { type: "object", additionalProperties: true };

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_PROBE_URL = "http://127.0.0.1:48771/__probe__/example.com/";

/** 审计链的链起点（与 vaultlib.py 的 GENESIS 一致）。 */
const GENESIS = "genesis";

/**
 * 真实安全边界（如实披露）。每一条都对应一次代码审查结论，不是免责话术。
 */
const SECURITY_LIMITATIONS = [
  "这些工具让 AI 能用真实凭据与真实登录态，能力真实、风险也真实。它不构成安全隔离。",
  "同用户进程可读 vault.key 与解密路径：同一用户下的任何进程（含任意 shell）都能绕过本插件直接拿到凭据，本插件的白名单与审计都不阻止这一点。",
  "account-secret 的 get / login 子命令会把明文打到 stdout：一旦被调用就进入调用方上下文。本插件不调用它们，但它们在系统里仍然存在。",
  "guard 审批是约定式关键词检查，不是强制拦截：AI 若不调用 vault-guard 直接执行危险操作，不会被阻止。本插件也不提供 approve/reject，避免 AI 自批。",
  "guard approve 的 --who 可由调用方任意填写，因此审计里的『批准人』不能作为老板真实审批的证据。",
  "panic 只隔离本地 proxy 密文：不会撤销上游平台已签发的 token，也不会终止已经打开的网页会话。上游凭据必须到各平台自行吊销。",
  "审计日志哈希链能发现内容改动与中间行删除，但不能抵御拥有同等级文件权限者重算整条链，也不能发现文件尾部被截断或整个文件被删除。",
  "会话的 expires_at 只是保存时写入的元数据 TTL，不代表站点侧登录仍然有效。vault-session check 与 session_open 返回的登录判断都是启发式（看是否跳回登录页/有可见密码框），不能证明登录有效。",
  "accounts.yaml 是人工维护的笔记，含推断与可能过时的关联，未经核实，不能作为权威事实来源。",
  "本插件不返回密码、令牌、TOTP 种子/验证码、cookie 或恢复码；但 exec_curl 会用真实凭据对外发起请求，响应体可能包含敏感数据（属于目标服务的返回值，不是凭据本身）。",
  "exec_curl 会产生真实的对外请求：GET 通常是只读的，但 POST/PUT/DELETE 等可能造成真实副作用。本插件不判断业务语义，也不会替你拦下危险请求。",
  "浏览器 CDP 端口（默认 9222）开着时可被同机任意进程接管该 profile 的全部登录态。用完必须 browser_stop。",
  "browser 的 eval 动作可执行任意 JS，等同于在该页面完全控制；截图只落文件返回路径，但页面文本可能含敏感信息。",
  "本插件不是完整的登录执行器：不实现自动过 2FA、不自动填登录表单；session_open 依赖已保存会话，且已知不能与 browser 工具共用同一浏览器实例。",
];

/* ══════════════════════════════════════════════════════════════════════════
 * Python 兼容的 JSON 规范化 + 哈希链校验
 *
 * 必须与 ~/.local/lib/vaultlib.py 完全一致：
 *   canonical = json.dumps(body, ensure_ascii=False, separators=(",", ":"),
 *                          sort_keys=True)   # body 去掉 prev_hash / hash
 *   hash      = sha256(prev_hash + canonical)
 *
 * 关键难点：Python 的 int 与 float 序列化不同（200 vs 200.0），而
 * JSON.parse 会丢掉「原始字面量」。所以这里用一个保留数字原文的小解析器，
 * 保证重算时数字按文件里的字面量拼回去，避免把格式差异误判成篡改。
 * ══════════════════════════════════════════════════════════════════════════ */

class UnsupportedJson extends Error {}

/** 保留数字字面量的极简 JSON 解析器。 */
function parseJsonPreservingNumbers(text) {
  let i = 0;
  const n = text.length;

  function skipWs() {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  }

  function parseString() {
    if (text[i] !== '"') throw new UnsupportedJson("expected string");
    const start = i;
    i++;
    while (i < n) {
      const ch = text[i];
      if (ch === "\\") { i += 2; continue; }
      if (ch === '"') { i++; break; }
      i++;
    }
    const raw = text.slice(start, i);
    try {
      return JSON.parse(raw);
    } catch {
      throw new UnsupportedJson("bad string literal");
    }
  }

  function parseNumber() {
    const start = i;
    if (text[i] === "-") i++;
    while (i < n && /[0-9]/.test(text[i])) i++;
    if (text[i] === ".") { i++; while (i < n && /[0-9]/.test(text[i])) i++; }
    if (text[i] === "e" || text[i] === "E") {
      i++;
      if (text[i] === "+" || text[i] === "-") i++;
      while (i < n && /[0-9]/.test(text[i])) i++;
    }
    const raw = text.slice(start, i);
    if (!/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(raw)) throw new UnsupportedJson("bad number");
    return { __num: raw };
  }

  function parseValue() {
    skipWs();
    const c = text[i];
    if (c === "{") {
      i++;
      const obj = {};
      skipWs();
      if (text[i] === "}") { i++; return obj; }
      for (;;) {
        skipWs();
        const key = parseString();
        skipWs();
        if (text[i] !== ":") throw new UnsupportedJson("expected colon");
        i++;
        obj[key] = parseValue();
        skipWs();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "}") { i++; break; }
        throw new UnsupportedJson("expected , or }");
      }
      return obj;
    }
    if (c === "[") {
      i++;
      const arr = [];
      skipWs();
      if (text[i] === "]") { i++; return arr; }
      for (;;) {
        arr.push(parseValue());
        skipWs();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "]") { i++; break; }
        throw new UnsupportedJson("expected , or ]");
      }
      return arr;
    }
    if (c === '"') return parseString();
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    if (text.startsWith("null", i)) { i += 4; return null; }
    if (c === "-" || (c >= "0" && c <= "9")) return parseNumber();
    throw new UnsupportedJson("unexpected token");
  }

  const v = parseValue();
  skipWs();
  if (i !== n) throw new UnsupportedJson("trailing garbage");
  return v;
}

/** 按 Python sort_keys + separators 的规则序列化（数字用原始字面量）。 */
function canonicalize(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") return JSON.stringify(value);
  if (value && typeof value === "object" && "__num" in value) return value.__num;
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  if (value && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(value[k])).join(",") + "}";
  }
  throw new UnsupportedJson("unserializable value");
}

/** 与 vaultlib._chain_hash 等价。 */
function chainHash(prevHash, record) {
  const body = {};
  for (const [k, v] of Object.entries(record)) {
    if (k === "prev_hash" || k === "hash") continue;
    body[k] = v;
  }
  const canonical = canonicalize(body);
  return createHash("sha256").update(prevHash + canonical, "utf8").digest("hex");
}

/**
 * 校验审计日志哈希链。
 *
 * 返回：
 *   status      "ok" | "broken" | "unknown"
 *   verifiable  是否真的做过校验（unknown 时为 false）
 *   problems    [{ line, reason }]
 *   legacyLines 链起点之前没有 hash 的旧格式行数（不可验证）
 *
 * 注意：即使 status=ok，也不能抵御同权限整链重算与尾部截断（见 SECURITY_LIMITATIONS）。
 */
function verifyAuditChain(text) {
  const rawLines = text.split(/\r?\n/).filter((l) => l.trim() !== "");

  if (rawLines.length === 0) {
    return {
      status: "unknown",
      verifiable: false,
      problems: [],
      legacyLines: 0,
      totalLines: 0,
      chainedLines: 0,
      reason: "审计日志为空，没有可校验的链",
    };
  }

  const problems = [];
  let legacyLines = 0;
  let chainedLines = 0;
  let expectedPrev = GENESIS;
  let chainStarted = false;
  let unsupported = null;

  for (let idx = 0; idx < rawLines.length; idx++) {
    const lineNo = idx + 1;
    const raw = rawLines[idx];

    let rec;
    try {
      rec = parseJsonPreservingNumbers(raw);
    } catch (e) {
      if (e instanceof UnsupportedJson) {
        // 该行既不是合法 JSON，也不是本校验器能理解的格式 → 整体不可验证
        unsupported = { line: lineNo, reason: "不是合法 JSON 或格式不受支持: " + e.message };
        break;
      }
      throw e;
    }
    if (!rec || typeof rec !== "object" || Array.isArray(rec)) {
      unsupported = { line: lineNo, reason: "该行不是 JSON 对象" };
      break;
    }

    const hasHash = typeof rec.hash === "string" && rec.hash !== "";
    if (!hasHash) {
      if (!chainStarted) {
        legacyLines++;      // 链起点之前的旧格式行：不可验证，但不算错误
        continue;
      }
      problems.push({ line: lineNo, reason: "缺少 hash 字段（链在此中断，可能被删改）" });
      continue;
    }

    chainStarted = true;
    chainedLines++;

    const prev = typeof rec.prev_hash === "string" ? rec.prev_hash : "";
    if (prev !== expectedPrev) {
      problems.push({
        line: lineNo,
        reason: "prev_hash 与上一行 hash 不一致（该行之前可能有行被删除或篡改）",
      });
    }

    let recomputed;
    try {
      recomputed = chainHash(prev, rec);
    } catch (e) {
      unsupported = { line: lineNo, reason: "无法规范化该行内容: " + String(e.message || e) };
      break;
    }
    if (recomputed !== rec.hash) {
      problems.push({ line: lineNo, reason: "内容与自身 hash 不符（该行被篡改）" });
    }
    expectedPrev = rec.hash;
  }

  if (unsupported) {
    return {
      status: "unknown",
      verifiable: false,
      problems,
      legacyLines,
      totalLines: rawLines.length,
      chainedLines,
      reason: `第 ${unsupported.line} 行无法校验（${unsupported.reason}）`,
    };
  }

  if (problems.length > 0) {
    return {
      status: "broken",
      verifiable: true,
      problems,
      legacyLines,
      totalLines: rawLines.length,
      chainedLines,
      reason: "哈希链存在问题",
    };
  }

  // 全部是旧格式行（没有任何 hash）→ 无从校验
  if (chainedLines === 0) {
    return {
      status: "unknown",
      verifiable: false,
      problems: [],
      legacyLines,
      totalLines: rawLines.length,
      chainedLines: 0,
      reason: "所有记录都是无 hash 的旧格式，无法校验完整性",
    };
  }

  return {
    status: "ok",
    verifiable: true,
    problems: [],
    legacyLines,
    totalLines: rawLines.length,
    chainedLines,
    reason: "已校验的链行全部通过（旧格式行不可验证，尾部截断无法发现）",
  };
}

/* ══════════════════════════════════════════════════════════════════════════
 * 极简 YAML 读取（只支持 accounts.yaml 用到的子集）
 * ══════════════════════════════════════════════════════════════════════════ */

function stripComment(line) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === "#" && !inSingle && !inDouble) {
      if (i === 0 || /\s/.test(line[i - 1])) return line.slice(0, i);
    }
  }
  return line;
}

function parseScalar(raw) {
  const s = raw.trim();
  if (s === "") return null;
  if (s === "null" || s === "~") return null;
  if (s === "true") return true;
  if (s === "false") return false;
  if (/^-?\d+$/.test(s)) return Number(s);
  if (s.startsWith("[") && s.endsWith("]")) {
    const inner = s.slice(1, -1).trim();
    if (!inner) return [];
    return inner.split(",").map((x) => parseScalar(x));
  }
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  return s;
}

function parseYaml(text) {
  const rawLines = text.split(/\r?\n/);
  const lines = [];
  for (const rawLine of rawLines) {
    const line = stripComment(rawLine);
    if (!line.trim()) continue;
    lines.push({ indent: line.match(/^ */)[0].length, content: line.trim() });
  }

  function nextIsListItem(idx, indent) {
    for (let i = idx + 1; i < lines.length; i++) {
      const l = lines[i];
      if (l.indent <= indent) return false;
      return l.content.startsWith("- ");
    }
    return false;
  }

  const root = {};
  const stack = [{ indent: -1, node: root }];

  for (let i = 0; i < lines.length; i++) {
    const { indent, content } = lines[i];

    if (content.startsWith("- ")) {
      const itemText = content.slice(2).trim();
      while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
      const frame = stack[stack.length - 1];
      const container = frame.pendingArray || frame.node;
      if (!Array.isArray(container)) continue;
      const kv = itemText.match(/^([A-Za-z0-9_]+):\s*(.*)$/);
      if (kv) {
        const obj = {};
        obj[kv[1]] = parseScalar(kv[2]);
        container.push(obj);
        stack.push({ indent, node: obj });
      } else {
        container.push(parseScalar(itemText));
      }
      continue;
    }

    const kv = content.match(/^([^:]+):\s*(.*)$/);
    if (!kv) continue;
    const key = kv[1].trim();
    const rest = kv[2];

    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
    const frame = stack[stack.length - 1];
    const parent = frame.node;

    if (Array.isArray(parent)) {
      const last = parent[parent.length - 1];
      if (last && typeof last === "object") {
        if (rest.trim() === "") {
          last[key] = {};
          stack.push({ indent, node: last[key] });
        } else {
          last[key] = parseScalar(rest);
        }
      }
      continue;
    }

    if (rest.trim() === "") {
      if (nextIsListItem(i, indent)) {
        const arr = [];
        parent[key] = arr;
        stack.push({ indent, node: arr, pendingArray: arr });
      } else {
        const obj = {};
        parent[key] = obj;
        stack.push({ indent, node: obj });
      }
    } else {
      parent[key] = parseScalar(rest);
    }
  }
  return root;
}

/* ══════════════════════════════════════════════════════════════════════════
 * 输出脱敏：严格白名单 + 文本消毒
 * ══════════════════════════════════════════════════════════════════════════ */

/** 标识符打码：邮箱保留首字母与域名，手机号保留前 3 后 2。 */
function maskIdentifier(raw) {
  if (typeof raw !== "string") return null;
  const t = raw.trim();
  if (!t) return null;
  const at = t.indexOf("@");
  if (at > 0) {
    const local = t.slice(0, at);
    const domain = t.slice(at + 1);
    return (local.slice(0, 1) || "*") + "***@" + domain;
  }
  const digits = t.replace(/\D/g, "");
  if (digits.length >= 6 && /^[+()\d\s-]+$/.test(t)) {
    return digits.slice(0, 3) + "****" + digits.slice(-2);
  }
  if (t.length <= 4) return "***";
  return t.slice(0, 2) + "***" + t.slice(-1);
}

/**
 * 文本消毒：控制字符剔除、长度截断、疑似秘密（长 hex / base64 / 常见前缀）打码。
 * 只用于可展示的短文本；默认根本不回传自由文本。
 */
function sanitizeText(raw, maxLen = 60) {
  if (typeof raw !== "string") return null;
  let t = raw.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();
  if (!t) return null;
  // 疑似秘密：长 hex、长 base64、常见 token 前缀
  t = t.replace(/\b[0-9a-fA-F]{32,}\b/g, "[REDACTED]");
  t = t.replace(/\b[A-Za-z0-9+/_-]{40,}={0,2}\b/g, "[REDACTED]");
  t = t.replace(/\b(ghp_|gho_|ghs_|sk-|xoxb-|AKIA)[A-Za-z0-9_-]{8,}/g, "[REDACTED]");
  if (t.length > maxLen) t = t.slice(0, maxLen) + "…";
  return t;
}

function strField(v, maxLen = 120) {
  if (typeof v !== "string") return null;
  const t = v.trim();
  if (!t) return null;
  return t.length > maxLen ? t.slice(0, maxLen) + "…" : t;
}

function idList(v, maxItems = 20) {
  if (!Array.isArray(v)) return [];
  return v
    .filter((x) => typeof x === "string" && /^[A-Za-z0-9_.-]{1,64}$/.test(x))
    .slice(0, maxItems);
}

/**
 * 账号条目：**严格白名单**。不返回 note/purpose 等自由文本，
 * 标识符默认打码（reveal 为 true 时才给原文）。
 */
function safeAccountEntry(e, { reveal = false } = {}) {
  if (!e || typeof e !== "object") return null;
  const out = {};
  const id = strField(e.id, 64);
  if (id) out.id = id;
  const type = strField(e.type, 32);
  if (type) out.type = type;
  const nm = strField(e.name, 64);
  if (nm) out.name = nm;

  // 标识符：默认打码。username 可能是 YAML 解析出的数字（如手机号），一并处理
  const identRaw = typeof e.address === "string" && e.address.trim()
    ? e.address.trim()
    : (typeof e.username === "string" || typeof e.username === "number")
      ? String(e.username).trim()
      : null;
  if (identRaw) {
    out.identifier = reveal ? identRaw : maskIdentifier(identRaw);
    out.identifier_masked = !reveal;
  }

  if (e["2fa"] && typeof e["2fa"] === "object") {
    out.has_2fa = Boolean(e["2fa"].app);
    const app = strField(e["2fa"].app, 40);
    if (app) out.twofa_app = app;
  }

  if (e.login && typeof e.login === "object") {
    const login = {};
    const method = strField(e.login.method, 24);
    if (method) login.method = method;
    const identity = strField(e.login.identity, 64);
    if (identity) login.identity = identity;
    const via = strField(e.login.via, 64);
    if (via) login.via = via;
    if (Object.keys(login).length) out.login = login;
  }

  const grants = idList(e.grants);
  if (grants.length) out.grants = grants;
  const services = idList(e.services);
  if (services.length) out.services = services;

  return Object.keys(out).length ? out : null;
}

/* ══════════════════════════════════════════════════════════════════════════
 * 插件主体：**每实例独立状态**，无模块级可变变量
 * ══════════════════════════════════════════════════════════════════════════ */

export function apply(ctx, config = {}) {
  const has = (o, k) => o && Object.prototype.hasOwnProperty.call(o, k);

  // 每实例一份状态，避免多实例/热重载互相覆盖。
  // 分层：bundle config（部署时）< settings（运行时用户改的，非空才覆盖）。
  const configState = {
    vaultDir: has(config, "vaultDir") && typeof config.vaultDir === "string" ? config.vaultDir : undefined,
    accountsFile: has(config, "accountsFile") && typeof config.accountsFile === "string" ? config.accountsFile : undefined,
    // 显式传空字符串 = 关闭探测；未传 = 用默认地址
    probeUrl: has(config, "probeUrl") && typeof config.probeUrl === "string" ? config.probeUrl : undefined,
    // 执行类：底层 CLI 路径与截图目录（测试可覆盖为 mock）
    bins: (config && typeof config.bins === "object" && config.bins) || {},
    shotDir: has(config, "shotDir") && typeof config.shotDir === "string" ? config.shotDir : undefined,
  };
  const state = {
    vaultDir: "",
    accountsFile: "",
    probeUrl: "",
    // 执行类工具：底层 CLI 路径可覆盖（测试时指向 mock），截图目录可覆盖
    bins: configState.bins,
    shotDir: configState.shotDir || "",
  };

  const disposers = [];

  function resolvePaths() {
    const home = homedir();
    const pick = (live, cfg, fallback) => {
      if (typeof live === "string" && live.trim()) return live;
      if (typeof cfg === "string") return cfg;   // 可能是 ""（显式关闭）
      return fallback;
    };
    const probe = pick(state.probeUrl, configState.probeUrl, DEFAULT_PROBE_URL);
    return {
      vaultDir: pick(state.vaultDir, configState.vaultDir, join(home, ".deepseekbot", "vault")),
      accountsFile: pick(state.accountsFile, configState.accountsFile, join(home, ".deepseekbot", "accounts.yaml")),
      // 空字符串表示禁用探测
      probeUrl: probe === "" ? "" : probe,
    };
  }

  function textBlock(value) {
    return [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }];
  }

  function register(def) {
    const d = ctx.tools.register(def);
    if (typeof d === "function") disposers.push(d);
    return d;
  }

  async function listDirSafe(dir) {
    try {
      const entries = await readdir(dir);
      return { ok: true, entries };
    } catch (e) {
      const code = e && e.code;
      if (code === "ENOENT") return { ok: true, entries: [], missing: true };
      // 权限不足等：明确报 unknown，不能当成空结果
      return { ok: false, error: code || String(e && e.message || e) };
    }
  }

  async function readJsonSafe(path) {
    try {
      const raw = await readFile(path, "utf8");
      return { ok: true, value: JSON.parse(raw) };
    } catch (e) {
      const code = e && e.code;
      if (code === "ENOENT") return { ok: true, missing: true };
      return { ok: false, error: code === "EACCES" ? "权限不足" : "读取或解析失败" };
    }
  }

  /**
   * 探测本地凭据代理是否在跑。
   *
   * 副作用说明：这是一次真实 HTTP 请求，会命中代理端口；若代理在跑，
   * 它可能因此向**代理自己的**审计日志追加一条记录。本插件不写任何文件，
   * 但这次探测不是「完全无副作用」。测试中必须 stub fetch 或改 probeUrl。
   */
  async function probeProxy() {
    const { probeUrl } = resolvePaths();
    if (!probeUrl) {
      return { attempted: false, listening: null, note: "探测已禁用（probeUrl 为空）" };
    }
    if (typeof fetch !== "function") {
      return { attempted: false, listening: null, note: "运行环境没有 fetch" };
    }
    try {
      const res = await fetch(probeUrl, { signal: AbortSignal.timeout(1500) });
      return {
        attempted: true,
        listening: true,
        http_status: res.status,
        note: "探测会命中代理端口；若代理在跑，可能追加一条代理审计记录。",
      };
    } catch {
      return {
        attempted: true,
        listening: false,
        note: "无法连接（代理可能未运行）。",
      };
    }
  }

  /* ── 工具 1：总览 ── */
  register(defineTool({
    name: "account_vault_overview",
    description:
      "只读总览：凭据代理是否可达、凭据数量、会话数量、待审批数量、审计日志是否存在、accounts.yaml 是否存在。" +
      "不返回任何密码/令牌/验证码/cookie。注意：代理探测会命中本地端口，可能有代理侧审计副作用。",
    parameters: NO_PARAMS,
    output: { schema: OUTPUT_SCHEMA, render: (_a, v) => textBlock(v) },
    timeoutMs: DEFAULT_TIMEOUT_MS * 2,
    async execute() {
      const { vaultDir, accountsFile } = resolvePaths();

      const credDir = await listDirSafe(join(vaultDir, "proxy"));
      const sessDir = await listDirSafe(join(vaultDir, "sessions"));
      const unknown = [];
      if (!credDir.ok) unknown.push("凭据目录不可读: " + credDir.error);
      if (!sessDir.ok) unknown.push("会话目录不可读: " + sessDir.error);

      const credCount = credDir.ok
        ? credDir.entries.filter((f) => f.endsWith(".meta.json")).length : null;
      const sessCount = sessDir.ok
        ? sessDir.entries.filter((f) => f.endsWith(".session.json")).length : null;

      let pendingCount = null;
      const pendingRead = await readJsonSafe(join(vaultDir, "guard-pending.json"));
      if (pendingRead.ok) {
        if (pendingRead.missing) pendingCount = 0;
        else {
          const items = Array.isArray(pendingRead.value?.items) ? pendingRead.value.items : [];
          pendingCount = items.filter((i) => i && i.status === "pending").length;
        }
      } else {
        unknown.push("审批队列不可读: " + pendingRead.error);
      }

      let auditExists = false;
      try {
        await stat(join(vaultDir, "audit.log"));
        auditExists = true;
      } catch { /* 不存在 */ }

      const probe = await probeProxy();

      const warnings = [];
      if (probe.listening === false) warnings.push("凭据代理不可达：无法发起带凭据的请求。");
      if (probe.listening === null) warnings.push("代理状态未知：" + probe.note);
      if (!existsSync(accountsFile)) warnings.push("accounts.yaml 不存在：账号笔记不可用。");
      if (!auditExists) warnings.push("审计日志不存在。");

      return {
        ok: true,
        read_only: true,
        proxy: probe,
        credentials: { count: credCount },
        sessions: { count: sessCount },
        guard: { pending: pendingCount },
        audit: { exists: auditExists },
        accounts_file: { exists: existsSync(accountsFile) },
        unknown,
        warnings,
        limitations: SECURITY_LIMITATIONS,
      };
    },
  }));

  /* ── 工具 2：账号列表（默认打码，无自由文本） ── */
  register(defineTool({
    name: "account_vault_accounts",
    description:
      "列出账号/平台的**标识信息**（id、类型、平台名、是否配 2FA、登录方式与依赖），" +
      "邮箱/手机号默认打码。不返回 note/purpose 等自由文本，也不返回任何秘密。" +
      "数据来自人工维护的 accounts.yaml，含推断，标 verified=false。" +
      "需要看某个账号的完整标识时，用 account_vault_account 单账号查询。",
    parameters: NO_PARAMS,
    output: { schema: OUTPUT_SCHEMA, render: (_a, v) => textBlock(v) },
    timeoutMs: DEFAULT_TIMEOUT_MS,
    async execute() {
      const { accountsFile } = resolvePaths();
      if (!existsSync(accountsFile)) {
        return {
          ok: false,
          verified: false,
          error: "accounts.yaml 不存在",
          note: "该文件是可选的账号笔记；不存在不影响凭据代理与会话功能。",
        };
      }
      let text;
      try {
        text = await readFile(accountsFile, "utf8");
      } catch (e) {
        const code = e && e.code;
        return { ok: false, verified: false, error: code === "EACCES" ? "accounts.yaml 权限不足" : "读取失败" };
      }
      let doc;
      try {
        doc = parseYaml(text);
      } catch (e) {
        return { ok: false, verified: false, error: "accounts.yaml 解析失败" };
      }
      if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
        return { ok: false, verified: false, error: "accounts.yaml 结构异常（顶层不是映射）" };
      }

      const identities = (Array.isArray(doc.identities) ? doc.identities : [])
        .map((e) => safeAccountEntry(e, { reveal: false })).filter(Boolean);
      const platforms = (Array.isArray(doc.platforms) ? doc.platforms : [])
        .map((e) => safeAccountEntry(e, { reveal: false })).filter(Boolean);

      const chains = {};
      if (doc.dependency_chains && typeof doc.dependency_chains === "object") {
        for (const [k, v] of Object.entries(doc.dependency_chains)) {
          if (!v || typeof v !== "object") continue;
          chains[strField(k, 64) || k] = {
            fails_if_lost: idList(v.fails_if_lost),
            affects: idList(v.affects),
          };
        }
      }

      return {
        ok: true,
        read_only: true,
        verified: false,
        source: accountsFile,
        disclaimer:
          "数据来自人工维护的 accounts.yaml，含推断与可能过时的关联；未经验证，不应作为权威事实来源。",
        counts: { identities: identities.length, platforms: platforms.length },
        identities,
        platforms,
        dependency_chains: chains,
        // 刻意不返回 todo 与 meta.note：它们是自由文本，可能含敏感内容
        omitted: ["todo", "meta.note", "purpose", "note"],
        identifiers_masked: true,
        limitations: SECURITY_LIMITATIONS,
      };
    },
  }));

  /* ── 工具 3：单账号查询（有范围，可选显示完整标识） ── */
  register(defineTool({
    name: "account_vault_account",
    description:
      "按 id 查询**单个**账号/平台的详细信息（有范围，不是批量导出）。" +
      "默认仍打码标识符；当具体任务确实需要完整邮箱/手机号时，把 reveal_identifier 设为 true。" +
      "仍不返回密码、令牌、TOTP 种子、cookie。数据来自 accounts.yaml，标 verified=false。",
    parameters: {
      id: { type: "string", description: "账号或平台的 id（如 github、gmail_main）" },
      reveal_identifier: {
        type: "boolean",
        description: "是否显示完整邮箱/手机号（默认 false，仅打码）",
      },
    },
    output: { schema: OUTPUT_SCHEMA, render: (_a, v) => textBlock(v) },
    timeoutMs: DEFAULT_TIMEOUT_MS,
    async execute(args) {
      const wanted = typeof args?.id === "string" ? args.id.trim() : "";
      if (!wanted) {
        return { ok: false, error: "必须提供 id" };
      }
      const reveal = args?.reveal_identifier === true;

      const { accountsFile } = resolvePaths();
      if (!existsSync(accountsFile)) {
        return { ok: false, error: "accounts.yaml 不存在" };
      }
      let doc;
      try {
        doc = parseYaml(await readFile(accountsFile, "utf8"));
      } catch {
        return { ok: false, error: "accounts.yaml 读取或解析失败" };
      }
      if (!doc || typeof doc !== "object") {
        return { ok: false, error: "accounts.yaml 结构异常" };
      }

      const pool = [
        ...(Array.isArray(doc.identities) ? doc.identities : []),
        ...(Array.isArray(doc.platforms) ? doc.platforms : []),
      ];
      const hit = pool.find((e) => e && typeof e === "object" && e.id === wanted);
      if (!hit) {
        return { ok: false, error: "找不到该 id", id: wanted };
      }

      const entry = safeAccountEntry(hit, { reveal }) || {};
      // 单账号查询可以带一小段用途说明，但仍做消毒与截断
      const purpose = sanitizeText(hit.purpose, 160);
      const note = sanitizeText(hit.note, 160);

      return {
        ok: true,
        read_only: true,
        verified: false,
        id: wanted,
        account: entry,
        purpose,
        note,
        identifiers_masked: !reveal,
        disclaimer: "数据来自人工维护的 accounts.yaml，未经验证。",
        limitations: SECURITY_LIMITATIONS,
      };
    },
  }));

  /* ── 工具 4：凭据元数据（不解密） ── */
  register(defineTool({
    name: "account_vault_credentials",
    description:
      "列出凭据代理里已登记的**凭据名**及其元数据（类型、域名白名单、是否有密文文件），" +
      "并探测代理是否可达。只读元数据，绝不触发解密、绝不返回凭据值。" +
      "注意：代理探测会命中本地端口，可能有代理侧审计副作用。",
    parameters: NO_PARAMS,
    output: { schema: OUTPUT_SCHEMA, render: (_a, v) => textBlock(v) },
    timeoutMs: DEFAULT_TIMEOUT_MS,
    async execute() {
      const { vaultDir } = resolvePaths();
      const proxyDir = join(vaultDir, "proxy");
      const dir = await listDirSafe(proxyDir);
      const probe = await probeProxy();

      if (!dir.ok) {
        return {
          ok: false,
          read_only: true,
          proxy: probe,
          error: "凭据目录不可读: " + dir.error,
        };
      }

      const metas = [];
      for (const fn of dir.entries) {
        if (!fn.endsWith(".meta.json")) continue;
        const nameFromFile = fn.slice(0, -".meta.json".length);
        const r = await readJsonSafe(join(proxyDir, fn));
        if (!r.ok) {
          metas.push({ name: nameFromFile, status: "unreadable", error: r.error });
          continue;
        }
        if (r.missing) continue;
        const m = r.value && typeof r.value === "object" ? r.value : {};
        metas.push({
          name: strField(m.name, 64) || nameFromFile,
          type: strField(m.type, 24),
          domains: Array.isArray(m.domains)
            ? m.domains.filter((d) => typeof d === "string").slice(0, 20)
            : [],
          created_at: typeof m.created_at === "number" ? m.created_at : null,
          has_secret: existsSync(join(proxyDir, (strField(m.name, 64) || nameFromFile) + ".secret.enc")),
          status: "ok",
        });
      }

      return {
        ok: true,
        read_only: true,
        proxy: probe,
        count: metas.length,
        credentials: metas,
        note: "只列出凭据名与元数据；凭据值不在此接口范围内，也不会被解密。",
        limitations: SECURITY_LIMITATIONS,
      };
    },
  }));

  /* ── 工具 5：会话元数据 ── */
  register(defineTool({
    name: "account_vault_sessions",
    description:
      "列出已保存网页会话的**元数据**（会话名、域名、保存时间、TTL），不含 cookie/localStorage。" +
      "重要：metadata_expired 只是保存时写入的 TTL 判断，不代表站点侧登录仍然有效；" +
      "login_verified 恒为 false —— vault-session check 也只是启发式探测。",
    parameters: NO_PARAMS,
    output: { schema: OUTPUT_SCHEMA, render: (_a, v) => textBlock(v) },
    timeoutMs: DEFAULT_TIMEOUT_MS,
    async execute() {
      const { vaultDir } = resolvePaths();
      const sessDir = join(vaultDir, "sessions");
      const dir = await listDirSafe(sessDir);
      if (!dir.ok) {
        return { ok: false, read_only: true, error: "会话目录不可读: " + dir.error };
      }

      const out = [];
      const now = Math.floor(Date.now() / 1000);
      for (const fn of dir.entries) {
        if (!fn.endsWith(".session.json")) continue;
        const name = fn.slice(0, -".session.json".length);
        const r = await readJsonSafe(join(sessDir, fn));
        if (!r.ok) {
          out.push({ name, status: "unreadable", error: r.error });
          continue;
        }
        if (r.missing) continue;
        const m = r.value && typeof r.value === "object" ? r.value : {};
        const exp = typeof m.expires_at === "number" ? m.expires_at : null;
        out.push({
          name: strField(m.name, 64) || name,
          domain: strField(m.domain, 128),
          saved_at_str: strField(m.saved_at_str, 32),
          expires_at_str: strField(m.expires_at_str, 32),
          ttl_days: typeof m.ttl_days === "number" ? m.ttl_days : null,
          metadata_expired: exp === null ? null : now > exp,
          encrypted_blob_present: existsSync(join(sessDir, name + ".session.enc")),
          login_verified: false,
          status: "ok",
        });
      }

      return {
        ok: true,
        read_only: true,
        count: out.length,
        sessions: out,
        note:
          "metadata_expired 仅基于保存时写入的 TTL；不代表站点侧登录有效。" +
          "login_verified 恒为 false，vault-session check 也只是启发式。",
        limitations: SECURITY_LIMITATIONS,
      };
    },
  }));

  /* ── 工具 6：审批队列（只读，无 approve） ── */
  register(defineTool({
    name: "account_vault_guard_status",
    description:
      "查看不可逆操作审批队列状态（待批准数量、每项的 id、命中词与**截断的**操作预览）。" +
      "只读：本工具不能批准或拒绝。注意审批是约定式的关键词检查，不是强制拦截。",
    parameters: NO_PARAMS,
    output: { schema: OUTPUT_SCHEMA, render: (_a, v) => textBlock(v) },
    timeoutMs: DEFAULT_TIMEOUT_MS,
    async execute() {
      const { vaultDir } = resolvePaths();
      const r = await readJsonSafe(join(vaultDir, "guard-pending.json"));

      let pending = [];
      let pendingError = null;
      if (!r.ok) {
        pendingError = r.error;
      } else if (!r.missing) {
        const items = Array.isArray(r.value?.items) ? r.value.items : [];
        pending = items
          .filter((i) => i && i.status === "pending")
          .slice(0, 50)
          .map((i) => ({
            id: strField(i.id, 32),
            // 不返回完整操作文本：只给消毒并截断的预览
            action_preview: sanitizeText(i.action, 60),
            action_length: typeof i.action === "string" ? i.action.length : null,
            hits: Array.isArray(i.hits)
              ? i.hits.filter((h) => typeof h === "string").slice(0, 10) : [],
            created_at_str: strField(i.created_at_str, 32),
          }));
      }

      return {
        ok: r.ok,
        read_only: true,
        pending_count: r.ok ? pending.length : null,
        pending,
        error: pendingError,
        limitation:
          "审批是约定式的关键词检查，不是内核级强制：AI 若不调用 guard 直接执行危险操作不会被拦截。" +
          "本插件不提供 approve，避免 AI 自行批准自己；且 --who 可伪造，不能作为真实审批证据。",
        limitations: SECURITY_LIMITATIONS,
      };
    },
  }));

  /* ── 工具 7：审计链校验（重算每条 hash） ── */
  register(defineTool({
    name: "account_vault_audit_status",
    description:
      "校验审计日志哈希链：逐行重算每条记录的 sha256 并核对 prev_hash 引用。" +
      "返回 status = ok / broken / unknown；unknown 表示无法校验（文件缺失、空、或含不支持的格式），" +
      "不能当成健康。旧格式无 hash 行不可验证会单独计数。" +
      "限制：不能抵御同权限者整链重算，也不能发现尾部截断或整个文件被删除。",
    parameters: NO_PARAMS,
    output: { schema: OUTPUT_SCHEMA, render: (_a, v) => textBlock(v) },
    timeoutMs: DEFAULT_TIMEOUT_MS,
    async execute() {
      const { vaultDir } = resolvePaths();
      const auditFile = join(vaultDir, "audit.log");

      let text;
      try {
        text = await readFile(auditFile, "utf8");
      } catch (e) {
        const code = e && e.code;
        if (code === "ENOENT") {
          return {
            ok: true,
            read_only: true,
            exists: false,
            status: "unknown",
            verifiable: false,
            reason: "审计日志不存在，无法校验",
            limitations: SECURITY_LIMITATIONS,
          };
        }
        return {
          ok: false,
          read_only: true,
          exists: true,
          status: "unknown",
          verifiable: false,
          error: code === "EACCES" ? "审计日志权限不足，无法校验" : "读取审计日志失败",
          limitations: SECURITY_LIMITATIONS,
        };
      }

      const v = verifyAuditChain(text);
      return {
        ok: true,
        read_only: true,
        exists: true,
        status: v.status,
        verifiable: v.verifiable,
        chain_ok: v.status === "ok",      // 兼容旧字段名；unknown 时为 false
        reason: v.reason,
        total_lines: v.totalLines,
        chained_lines: v.chainedLines,
        legacy_lines_unverifiable: v.legacyLines,
        problems: v.problems,
        limitations: SECURITY_LIMITATIONS,
      };
    },
  }));

  /* ── 工具 8：安全边界 ── */
  register(defineTool({
    name: "account_vault_security_boundary",
    description:
      "如实返回这套账号执行层的安全边界与已知限制。在依赖它做安全判断前应先读一次。" +
      "它不是安全隔离产品，不应被当作 1Password 等级。",
    parameters: NO_PARAMS,
    output: { schema: OUTPUT_SCHEMA, render: (_a, v) => textBlock(v) },
    timeoutMs: DEFAULT_TIMEOUT_MS,
    async execute() {
      return {
        ok: true,
        read_only: true,
        product_class: "本地只读管理/状态工具（非安全隔离产品）",
        not_claimed: [
          "不是 1Password 等级：没有零知识保证，未通过安全审计。",
          "不是强制审批：guard 是约定式关键词检查，可被绕过。",
          "不是内核级隔离：同一用户下的任何进程都能读到相同文件。",
          "不是登录执行器：不实现自动登录、填表、过 2FA 或业务操作。",
          "执行类工具（exec_curl / session_open / browser）让 AI 能用真实凭据与登录态，能力真实、风险也真实。",
        ],
        design: "只读工具设计为不读取密文、限制输出字段；执行类工具会真实调用底层能力。两者都不构成『永不泄露』的保证。",
        limitations: SECURITY_LIMITATIONS,
      };
    },
  }));

  /* ── 执行类工具（会真实干活） ── */
  try {
    registerExecTools({
      register,
      state,
      resolvePaths,
      textBlock,
      OUTPUT_SCHEMA,
      audit: (action, cred, note) => {
        // 审计复用 vaultlib 哈希链；只写元信息，绝不写凭据值。
        // 写入当前实例配置的 vault 目录，避免污染生产审计。
        const { vaultDir } = resolvePaths();
        return V_auditEvent(
          { action, cred: cred || "-", host: "-", path: "-", status: 0,
            note: String(note || "").slice(0, 200) },
          vaultDir,
        ).catch(() => false);
      },
    });
  } catch (e) {
    console.log(`[dsh-account-vault] exec 工具注册跳过: ${String(e && e.message || e)}`);
  }

  /* ── settings 命名空间 ── */
  const settings = ctx.settings;
  if (settings && typeof settings.register === "function") {
    try {
      const scope = settings.register(SETTINGS_NAMESPACE, SETTINGS_SCHEMA, {
        validate: (value) => {
          if (value && typeof value.vaultDir === "string" && value.vaultDir.trim()
            && !value.vaultDir.startsWith("/")) {
            throw new Error("vaultDir 必须是绝对路径");
          }
          if (value && typeof value.accountsFile === "string" && value.accountsFile.trim()
            && !value.accountsFile.startsWith("/")) {
            throw new Error("accountsFile 必须是绝对路径");
          }
          if (value && typeof value.probeUrl === "string" && value.probeUrl.trim()
            && !/^https?:\/\//.test(value.probeUrl)) {
            throw new Error("probeUrl 必须是 http(s) URL");
          }
        },
      });
      const read = () => {
        const r = scope.get() || {};
        state.vaultDir = typeof r.vaultDir === "string" ? r.vaultDir : "";
        state.accountsFile = typeof r.accountsFile === "string" ? r.accountsFile : "";
        state.probeUrl = typeof r.probeUrl === "string" ? r.probeUrl : "";
      };
      read();
      const stop = scope.watch(() => read());
      if (typeof stop === "function") disposers.push(stop);
      if (typeof scope.dispose === "function") disposers.push(() => scope.dispose());
    } catch (e) {
      console.log(`[dsh-account-vault] settings 注册跳过: ${String(e && e.message || e)}`);
    }
  }

  const cleanup = () => {
    while (disposers.length) {
      const d = disposers.pop();
      try { d(); } catch { /* 卸载时忽略单个失败 */ }
    }
  };

  // Cordis 规范：优先用 ctx.effect 注册资源释放；否则由 apply 返回 disposer
  if (typeof ctx.effect === "function") {
    ctx.effect(() => cleanup);
  }

  console.log(`[dsh-account-vault] registered ${disposers.length} disposers, read-only tools`);
  return cleanup;
}
