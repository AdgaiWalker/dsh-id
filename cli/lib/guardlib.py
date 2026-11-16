#!/usr/bin/env python3
"""guardlib — 不可逆操作审批（步5）

设计原则：简单可用优先，不过度设计。

数据流：
    AI 执行危险操作前 → vault-guard check "<描述>"
        ├─ allow            → 直接执行
        └─ require_approval → 拿到 id，停下等老板
    老板 → vault-guard pending / approve <id> / reject <id>

存储：
    待批准队列  ~/.deepseekbot/vault/guard-pending.json
    规则        ~/.deepseekbot/vault/guard-rules.yaml
    审计        ~/.deepseekbot/vault/audit.log（复用哈希链）

安全：队列里只存操作描述，绝不存凭据值。
"""

import json
import os
import re
import sys
import time
import uuid

def _vault_dir():
    """与 vaultlib 一致：测试用 VAULT_DIR_OVERRIDE / VAULT_DIR 隔离，别碰生产。"""
    return (os.environ.get("VAULT_DIR_OVERRIDE") or os.environ.get("VAULT_DIR")
            or os.path.expanduser("~/.deepseekbot/vault"))


VAULT_DIR = _vault_dir()
RULES_FILE = os.path.join(VAULT_DIR, "guard-rules.yaml")
PENDING_FILE = os.path.join(VAULT_DIR, "guard-pending.json")
STATE_FILE = os.path.join(VAULT_DIR, "guard-state.json")

# 频率/熔断默认值：规则文件没写 rate_limits 时用这套
RATE_DEFAULTS = {
    "publish": {
        "match": ["发布", "发帖", "发一条", "post", "publish", "tweet"],
        "max_per_day": 3,
        "min_interval_minutes": 30,
        "max_consecutive_failures": 2,
    },
}

# 英文词边界匹配：避免 "form" 里的 "rm"、"display" 里的 "play" 误判
_WORD_RE_CACHE = {}


def _word_pattern(word):
    """英文/数字组成的词用词边界；含空格或非 ASCII 的用子串。"""
    if word in _WORD_RE_CACHE:
        return _WORD_RE_CACHE[word]
    w = word.strip()
    if not w:
        return None
    # 纯 ASCII 字母数字（可含空格、连字符）→ 词边界
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _\-]*", w):
        parts = [re.escape(p) for p in w.split()]
        pat = re.compile(r"(?<![A-Za-z0-9])" + r"\s+".join(parts) + r"(?![A-Za-z0-9])",
                         re.IGNORECASE)
    else:
        # 中文等：子串匹配
        pat = re.compile(re.escape(w), re.IGNORECASE)
    _WORD_RE_CACHE[word] = pat
    return pat


def load_rules():
    """读规则文件。缺失或损坏时退回内置最小规则（保守：宁可多问）。"""
    default = {
        "version": 1,
        "danger": ["删除", "delete", "rm", "drop", "付款", "pay", "转账",
                   "改密码", "password", "发布", "publish", "deploy",
                   "生产环境", "production"],
        "allow_override": [],
        "readonly_hints": ["查询", "查看", "list", "show", "get", "status"],
    }
    if not os.path.exists(RULES_FILE):
        return default
    try:
        import yaml
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            return default
        data.setdefault("danger", default["danger"])
        data.setdefault("allow_override", [])
        data.setdefault("readonly_hints", default["readonly_hints"])
        return data
    except Exception:
        return default


def _matches(text, words):
    """返回命中的词列表。"""
    hits = []
    for w in words or []:
        pat = _word_pattern(str(w))
        if pat and pat.search(text):
            hits.append(str(w))
    return hits


def check(text):
    """判断一个操作是否需要批准。

    返回 dict：
        decision   "allow" | "require_approval"
        hits       命中的危险词
        overrides  命中的放行词
        readonly   是否像只读操作
        id         需要批准时生成的待批 id
    """
    rules = load_rules()
    text = (text or "").strip()
    danger_hits = _matches(text, rules.get("danger"))
    override_hits = _matches(text, rules.get("allow_override"))
    readonly_hits = _matches(text, rules.get("readonly_hints"))

    # allow_override 优先（更具体的词可放行）
    if danger_hits and override_hits:
        decision = "allow"
    elif danger_hits:
        decision = "require_approval"
    else:
        decision = "allow"

    result = {
        "decision": decision,
        "hits": danger_hits,
        "overrides": override_hits,
        "readonly": bool(readonly_hits) and not danger_hits,
        "readonly_hits": readonly_hits,
        "id": None,
    }
    if decision == "require_approval":
        result["id"] = _enqueue(text, danger_hits)
    return result


# ── 待批准队列 ──────────────────────────────────────────────────────────────

def load_rate_rules():
    rules = load_rules().get("rate_limits") or {}
    return rules if rules else RATE_DEFAULTS


def _today():
    return time.strftime("%Y-%m-%d", time.localtime())


def _load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            return json.load(fh) or {}
    except (OSError, ValueError):
        return {}


def _save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_FILE)


def _bucket(state, scope, key):
    sc = state.setdefault("scopes", {}).setdefault(scope or "-", {"actions": {}})
    b = sc["actions"].setdefault(key, {"day": _today(), "count": 0, "last_ts": 0, "fails": 0})
    if b.get("day") != _today():          # 跨天自动清零
        b.update({"day": _today(), "count": 0})
    return b


def _rule_for(text):
    """命中哪条限速规则（返回 (key, rule) 或 (None, None)）。"""
    rules = load_rate_rules()
    for key, rule in rules.items():
        words = rule.get("match") or []
        if _matches(text, words):
            return key, rule
    return None, None


def rate_check(text, scope=None):
    """频率/熔断检查。返回 dict(decision=allow|throttled, reason, key, rule)。"""
    key, rule = _rule_for(text)
    if not key:
        return {"decision": "allow", "reason": "不在限速范围", "key": None, "rule": None}
    b = _bucket(_load_state(), scope, key)
    cap = int(rule.get("max_per_day", 0) or 0)
    gap = int(rule.get("min_interval_minutes", 0) or 0) * 60
    breaker = int(rule.get("max_consecutive_failures", 0) or 0)

    if breaker and b.get("fails", 0) >= breaker:
        return {"decision": "throttled",
                "reason": f"断路器已打开（连续失败 {b['fails']} 次）；先查原因再 vault-guard reset",
                "key": key, "rule": rule}
    if cap and b.get("count", 0) >= cap:
        return {"decision": "throttled",
                "reason": f"今日已达上限（{b['count']}/{cap} 条）", "key": key, "rule": rule}
    if gap and b.get("last_ts"):
        left = gap - (int(time.time()) - int(b["last_ts"]))
        if left > 0:
            return {"decision": "throttled",
                    "reason": f"距上次太近，还需等 {left // 60} 分钟", "key": key, "rule": rule}
    return {"decision": "allow", "reason": f"限速通过（今日 {b.get('count', 0)}/{cap or '∞'}）",
            "key": key, "rule": rule}


def record(text, ok=True, scope=None):
    """记一次实际操作结果，供上限/间隔/熔断使用。"""
    key, rule = _rule_for(text)
    if not key:
        return None
    state = _load_state()
    b = _bucket(state, scope, key)
    if ok:
        b["count"] = int(b.get("count", 0)) + 1
        b["fails"] = 0
    else:
        b["fails"] = int(b.get("fails", 0)) + 1
    b["last_ts"] = int(time.time())
    _save_state(state)
    return {"key": key, "count": b["count"], "fails": b["fails"]}


def reset(scope=None):
    state = _load_state()
    if scope is None:
        state = {"scopes": {}}
    else:
        state.get("scopes", {}).pop(scope, None)
    _save_state(state)
    return True


def _load_pending():
    if not os.path.exists(PENDING_FILE):
        return {"items": []}
    try:
        with open(PENDING_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        if not isinstance(d, dict) or "items" not in d:
            return {"items": []}
        return d
    except (OSError, ValueError):
        return {"items": []}


def _save_pending(data):
    os.makedirs(VAULT_DIR, mode=0o700, exist_ok=True)
    tmp = PENDING_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, PENDING_FILE)
    os.chmod(PENDING_FILE, 0o600)


def _enqueue(text, hits):
    """加入待批准队列，返回短 id。"""
    data = _load_pending()
    pid = uuid.uuid4().hex[:8]
    now = int(time.time())
    data["items"].append({
        "id": pid,
        "action": text,
        "hits": hits,
        "status": "pending",
        "created_at": now,
        "created_at_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
    })
    _save_pending(data)
    return pid


def pending_items():
    data = _load_pending()
    return [i for i in data.get("items", []) if i.get("status") == "pending"]


def get_item(pid):
    for i in _load_pending().get("items", []):
        if i.get("id") == pid:
            return i
    return None


def decide(pid, approve, who="老板", note=""):
    """批准或拒绝。返回 (ok, item, message)。"""
    data = _load_pending()
    target = None
    for i in data.get("items", []):
        if i.get("id") == pid:
            target = i
            break
    if not target:
        return False, None, "找不到该待批准项: " + pid
    if target.get("status") != "pending":
        return False, target, "该项已处理过（状态: %s）" % target.get("status")

    now = int(time.time())
    target["status"] = "approved" if approve else "rejected"
    target["decided_at"] = now
    target["decided_at_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    target["decided_by"] = who
    if note:
        target["note"] = note
    _save_pending(data)
    return True, target, ("已批准" if approve else "已拒绝")


def is_approved(pid):
    """供 AI 在执行前二次确认：该 id 是否已被批准。"""
    item = get_item(pid)
    return bool(item and item.get("status") == "approved")


def _audit(**fields):
    """写审计（复用 vaultlib 的哈希链）。失败不阻断主流程。"""
    try:
        sys.path.insert(0, os.path.expanduser("~/.local/lib"))
        import vaultlib as V
        V.audit_event(**fields)
    except Exception:
        pass
