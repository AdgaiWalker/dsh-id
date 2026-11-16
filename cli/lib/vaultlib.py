#!/usr/bin/env python3
"""vaultlib — 账号执行层公共库（凭据存储 / 白名单 / 审计）

设计要点
--------
1. **元数据与密文分离**：凭据的「名字 / 类型 / domains 白名单」存明文
   `<name>.meta.json`，凭据「值」单独加密存 `<name>.secret.enc`。
   这样代理可以在**解密之前**完成白名单校验（安全红线 3）。
2. **复用现有加密**：openssl aes-256-cbc + pbkdf2，key 取 `~/.deepseekbot/vault/vault.key`。
   用 `-pass file:` 让 openssl 自己读 key 文件，**key 不进 argv**（argv 全局可见）。
3. **子目录隔离**：新凭据放 `~/.deepseekbot/vault/proxy/`，
   不污染 `account-secret list` 的 `*__*.enc` 通配。
4. **审计只记元信息**：时间 / 凭据名 / host / 路径 / 状态码，绝不记凭据值。

参考实现：
- agent-id `plugins/agent-id-vault/lib/access.mjs` → hostMatchesAllowlist（精确 + `*.suffix` 通配）
- agent-id `plugins/agent-id-proxy/lib/rewrite.mjs` → URL 契约解析、按类型注入
- coral `coral/audit.py` → append-only 审计的"单一写入口 + 无密钥纪律"
"""

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

# ── 路径解析：运行时读取，不再在 import 时固化 ─────────────────────────────
# 历史问题：原来 VAULT_DIR 是模块级常量，在 import 时就展开 ~，
# 导致测试时用 `HOME=/tmp/xxx python ...` 隔离完全不生效，会误触真实 vault。
# 现在改成函数，每次调用重新读环境变量；并支持 VAULT_DIR_OVERRIDE 显式注入。
#
# 优先级：
#   1. VAULT_DIR_OVERRIDE（显式注入，测试/工具用）
#   2. VAULT_DIR 环境变量
#   3. ~/.deepseekbot/vault（默认）

def _vault_dir():
    """返回当前 vault 目录（每次调用都重新解析，支持运行时切换）。"""
    override = os.environ.get("VAULT_DIR_OVERRIDE")
    if override:
        return os.path.expanduser(override)
    env = os.environ.get("VAULT_DIR")
    if env:
        return os.path.expanduser(env)
    return os.path.expanduser("~/.deepseekbot/vault")


def _path(*parts):
    return os.path.join(_vault_dir(), *parts)


def keyfile_path():
    return _path("vault.key")


def proxy_dir():
    return _path("proxy")


def session_dir():
    return _path("sessions")


def audit_log_path():
    return _path("audit.log")


# 兼容旧引用：这些是“快照”属性，只在 import 时求值一次。
# 新代码请用上面的函数。为兼容外部脚本（vault-proxy/vault-cred）保留。
VAULT_DIR = _vault_dir()
KEYFILE = keyfile_path()
PROXY_DIR = proxy_dir()
SESSION_DIR = session_dir()
AUDIT_LOG = audit_log_path()


def refresh_paths():
    """重新解析全局路径常量（改了环境变量后调用）。"""
    global VAULT_DIR, KEYFILE, PROXY_DIR, SESSION_DIR, AUDIT_LOG
    VAULT_DIR = _vault_dir()
    KEYFILE = keyfile_path()
    PROXY_DIR = proxy_dir()
    SESSION_DIR = session_dir()
    AUDIT_LOG = audit_log_path()
    return VAULT_DIR

# systemd 用户服务名与代理端口（panic / restore 共用）
SERVICE = "vault-proxy.service"
PROXY_PORT = 48771

# 凭据名：与 agent-id 一致，URL 安全
CREDNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")

# 本步支持的类型（方案 §3 的前四种）
SUPPORTED_TYPES = ("bearer", "basic", "header", "query")


class VaultError(Exception):
    """带机器可读 code 的错误，供代理映射成 HTTP 状态码。"""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ── 密钥与加解密（1Password 级：主密码解锁 + 自动锁定）─────────────────────
#
# 模型：
#   DEK（data encryption key）—— 真正加密凭据的密钥，就是原来的 vault.key 内容
#   KEK（key encryption key）  —— 由主密码经 PBKDF2 派生
#   vault.key.enc              —— 用 KEK 加密包裹后的 DEK（磁盘上只有这个）
#
# 关键点：
#   - **DEK 在磁盘上不再以明文存在**（启用主密码后删除 vault.key 明文）
#   - 解锁时把 DEK 写进 tmpfs（/run/user/<uid>/vault-session/），不落真实磁盘
#   - 解锁有效期到期 → 自动删除 tmpfs 里的 DEK → 解密直接 401 vault_locked
#   - 主密码本身从不存储，只存「用主密码能否解开 DEK」这一事实

def master_meta_path():
    return _path("master.json")     # 配置（超时等），无秘密

def key_enc_path():
    return _path("vault.key.enc")   # 包裹后的 DEK

def recovery_file_path():
    return _path("recovery.json")   # 恢复码包裹的 DEK 副本

# 兼容快照（新代码请用上面的函数）
MASTER_META = master_meta_path()
KEY_ENC = key_enc_path()
RECOVERY_FILE = recovery_file_path()

DEFAULT_TIMEOUT_MIN = 30

# ── 机器绑定自动解锁（默认模式，AI 自理）──────────────────────────────────
#
# 老板原则：「AI 自理优先——在保证数据与财产安全的前提下，让 AI 尽量发挥
# 自主能动性，不让他反复输密码或做确认。」
#
# 所以默认不要求主密码：
#   - 机器密钥 = PBKDF2(machine-id + 本机绑定密钥文件) 派生
#   - 该密钥用「机器绑定 KEK」包裹 DEK，存在 vault.key.machine
#   - 代理启动时自动解开，人不用参与
#   - 拷贝 vault 到别的机器 → machine-id 不同 → 解不开（这是保护）
#
# 主密码是**可选加强项**（vault-cred passwd --enable），默认关闭。

def machine_key_path():
    return _path("vault.key.machine")   # 机器绑定包裹的 DEK

def machine_salt_path():
    return _path("machine.salt")        # 绑定盐（本机）

# 兼容快照
MACHINE_KEY = machine_key_path()
MACHINE_SALT_FILE = machine_salt_path()


def _machine_id():
    """取本机唯一标识。取不到就退回 hostname + 用户（弱一些但仍绑定本机）。"""
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(p, "r", encoding="utf-8") as f:
                v = f.read().strip()
            if v:
                return v
        except OSError:
            continue
    import socket
    return "%s-%s" % (socket.gethostname(), os.getuid())


def _machine_salt():
    """本机绑定盐：首次创建后固定，权限 600。"""
    if os.path.exists(machine_salt_path()):
        try:
            with open(machine_salt_path(), "rb") as f:
                s = f.read().strip()
            if s:
                return s
        except OSError:
            pass
    os.makedirs(_vault_dir(), mode=0o700, exist_ok=True)
    s = os.urandom(16).hex().encode()
    fd = os.open(machine_salt_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(s)
    os.chmod(machine_salt_path(), 0o600)
    return s


def _machine_kek():
    """由 machine-id + 本机盐派生 KEK。换机器就变，所以拷走 vault 也解不开。"""
    salt = _machine_salt()
    material = (_machine_id() + "|" + salt.decode()).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", material, salt,
                               200000, dklen=32).hex().encode()


def machine_enabled():
    """是否已启用机器绑定（存在 vault.key.machine）。"""
    return os.path.exists(machine_key_path())


def init_machine_binding(dek_bytes=None):
    """建立机器绑定：用机器 KEK 包裹 DEK。

    dek_bytes 为空时从现有 vault.key 读取（迁移场景）。
    """
    if dek_bytes is None:
        if not os.path.exists(keyfile_path()):
            raise VaultError("vault_locked", "没有可绑定的 DEK（vault.key 不存在）")
        with open(keyfile_path(), "rb") as f:
            dek_bytes = f.read().strip()
    if not dek_bytes:
        raise VaultError("vault_locked", "DEK 为空")

    kek = _machine_kek()
    p = _openssl(dek_bytes, kek)
    if p.returncode != 0:
        raise VaultError("vault_locked", "机器绑定包裹失败")

    rec = {
        "version": 1,
        "kdf": "pbkdf2-hmac-sha256",
        "iterations": 200000,
        "ct": base64.b64encode(p.stdout).decode(),
        "created_at": int(time.time()),
        "machine_id_hint": _machine_id()[:8],
    }
    tmp = machine_key_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rec, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, machine_key_path())
    return rec


def unwrap_machine_dek():
    """用机器绑定解出 DEK。失败返回 None（换了机器/文件被改）。"""
    if not machine_enabled():
        return None
    try:
        with open(machine_key_path(), "r", encoding="utf-8") as f:
            rec = json.load(f)
        ct = base64.b64decode(rec["ct"])
    except (OSError, ValueError, KeyError):
        return None
    kek = _machine_kek()
    p = _openssl(ct, kek, decrypt=True)
    if p.returncode != 0:
        return None
    return p.stdout
PBKDF2_ITER = 600000


def _runtime_dir():
    """解锁态存放目录：优先 XDG_RUNTIME_DIR（tmpfs，重启即失）。"""
    base = os.environ.get("XDG_RUNTIME_DIR")
    if not base or not os.path.isdir(base):
        base = "/run/user/%d" % os.getuid()
    d = os.path.join(base, "vault-session")
    return d


def _session_key_path():
    return os.path.join(_runtime_dir(), "dek")


def _session_expiry_path():
    return os.path.join(_runtime_dir(), "expires_at")


def _openssl(data, pass_bytes, decrypt=False):
    """用 openssl 加解密。密码通过**临时文件**（-pass file:）传入。

    为什么不用 fd:3：
      连续快速调用时 dup2(r,3) 会与父进程其它 fd 冲突，
      openssl 报 "Error reading password from BIO"。
    为什么不用 argv：argv 全局可见（ps 就能看到）。
    临时文件方案：权限 600、用完立即删除、不进 argv / 不进环境变量。
    """
    tmpdir = None
    try:
        tmpdir = tempfile.mkdtemp(prefix=".vk-", dir=None)
        os.chmod(tmpdir, 0o700)
        pwfile = os.path.join(tmpdir, "p")
        fd = os.open(pwfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pass_bytes + b"\n")
        os.chmod(pwfile, 0o600)

        cmd = ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt",
               "-pass", "file:" + pwfile]
        if decrypt:
            cmd.insert(2, "-d")
        return subprocess.run(cmd, input=data, capture_output=True)
    finally:
        if tmpdir:
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass


def master_enabled():
    """是否已启用主密码（存在包裹后的 DEK）。"""
    return os.path.exists(key_enc_path())


def load_master_meta():
    if not os.path.exists(master_meta_path()):
        return {"timeout_minutes": DEFAULT_TIMEOUT_MIN, "version": 1}
    try:
        with open(master_meta_path(), "r", encoding="utf-8") as f:
            m = json.load(f)
    except (OSError, ValueError):
        return {"timeout_minutes": DEFAULT_TIMEOUT_MIN, "version": 1}
    m.setdefault("timeout_minutes", DEFAULT_TIMEOUT_MIN)
    return m


def save_master_meta(meta):
    os.makedirs(_vault_dir(), mode=0o700, exist_ok=True)
    tmp = master_meta_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, master_meta_path())


def _derive_kek(password, salt, iterations):
    """PBKDF2-HMAC-SHA256 派生 KEK（64 位十六进制字符串，交给 openssl 当口令）。"""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt,
        iterations, dklen=32).hex().encode()


def _wrap_dek(dek_bytes, password):
    """用主密码把 DEK 包起来，返回可落盘的 JSON dict。"""
    salt = os.urandom(16)
    kek = _derive_kek(password, salt, PBKDF2_ITER)
    p = _openssl(dek_bytes, kek)
    if p.returncode != 0:
        raise VaultError("vault_locked", "包裹 DEK 失败")
    return {
        "version": 1,
        "kdf": "pbkdf2-hmac-sha256",
        "iterations": PBKDF2_ITER,
        "salt": base64.b64encode(salt).decode(),
        "ct": base64.b64encode(p.stdout).decode(),
        "created_at": int(time.time()),
    }


def _unwrap_dek(rec, password):
    """用主密码解出 DEK。密码错 → 返回 None（不抛异常，便于校验）。"""
    try:
        salt = base64.b64decode(rec["salt"])
        ct = base64.b64decode(rec["ct"])
        iterations = int(rec.get("iterations", PBKDF2_ITER))
    except (KeyError, ValueError, TypeError):
        return None
    kek = _derive_kek(password, salt, iterations)
    p = _openssl(ct, kek, decrypt=True)
    if p.returncode != 0:
        return None
    return p.stdout


def current_dek():
    """取当前可用于加解密的 DEK。

    优先级：
      1. 机器绑定（默认）——自动解锁，人不用参与
      2. 主密码解锁态（可选加强项）——tmpfs 里的 DEK
      3. 旧版明文 vault.key（向后兼容）

    返回 (dek_bytes, source)，source ∈ {"machine","session","legacy"}
    """
    # ① 机器绑定：自动解锁（老板原则：AI 自理）
    if machine_enabled():
        dek = unwrap_machine_dek()
        if dek:
            return dek.strip(), "machine"
        # 机器绑定坏了，再看是否有人工解锁态兜底
        if master_enabled() and not is_locked():
            try:
                with open(_session_key_path(), "rb") as f:
                    dek = f.read().strip()
                if dek:
                    return dek, "session"
            except OSError:
                pass
        raise VaultError(
            "vault_locked",
            "机器绑定解不开（可能换了机器或被改动）。"
            "请用 vault-cred unlock 人工解锁，或重新建立机器绑定")

    # ② 主密码模式
    if master_enabled():
        if is_locked():
            raise VaultError("vault_locked",
                             "保险库已锁定，请先 vault-cred unlock")
        try:
            with open(_session_key_path(), "rb") as f:
                dek = f.read().strip()
        except OSError:
            raise VaultError("vault_locked", "解锁态丢失，请重新 unlock")
        if not dek:
            raise VaultError("vault_locked", "解锁态为空，请重新 unlock")
        return dek, "session"

    # ③ 旧版明文 key
    ensure_key()
    with open(keyfile_path(), "rb") as f:
        return f.read().strip(), "legacy"


def ensure_key():
    """确保旧版 vault.key 存在且权限 600。

    ⚠ 安全关键：一旦启用了主密码（vault.key.enc 存在），**绝不能重建明文 vault.key**。
    否则会生成一把新 key，与所有旧密文不匹配，等于把保险库锁死。
    """
    if master_enabled():
        # 已启用主密码：明文 key 不该存在，存在也只是遗留物，不碰不建
        if os.path.exists(keyfile_path()):
            raise VaultError(
                "vault_locked",
                "已启用主密码，但明文 vault.key 仍存在——请用 vault-cred 检查，"
                "不要依赖明文 key")
        return None

    if not os.path.exists(keyfile_path()):
        os.makedirs(_vault_dir(), mode=0o700, exist_ok=True)
        k = subprocess.run(["openssl", "rand", "-hex", "32"],
                           capture_output=True, text=True).stdout.strip()
        fd = os.open(keyfile_path(), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(k)
    os.chmod(keyfile_path(), 0o600)
    return keyfile_path()


def encrypt(plaintext: str) -> bytes:
    """加密。用当前 DEK（解锁态或旧 key），DEK 通过 fd:3 传给 openssl。"""
    dek, _ = current_dek()
    p = _openssl(plaintext.encode(), dek)
    if p.returncode != 0:
        raise VaultError("vault_locked", "加密失败")
    return p.stdout


def decrypt(blob: bytes) -> str:
    """解密。锁定时抛 vault_locked。"""
    dek, _ = current_dek()
    p = _openssl(blob, dek, decrypt=True)
    if p.returncode != 0:
        raise VaultError("vault_locked", "解密失败（密钥不对或文件损坏）")
    return p.stdout.decode()


# ── 解锁 / 锁定 / 状态 ──────────────────────────────────────────────────────

def init_master(password, timeout_minutes=None):
    """首次设置主密码：把当前 DEK 用主密码包裹，然后删掉明文 vault.key。"""
    if master_enabled():
        raise VaultError("vault_locked", "主密码已设置过；改密码请用 vault-cred passwd")

    ensure_key()
    with open(keyfile_path(), "rb") as f:
        dek = f.read().strip()
    if not dek:
        raise VaultError("vault_locked", "vault.key 为空，无法初始化")

    rec = _wrap_dek(dek, password)
    tmp = key_enc_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rec, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, key_enc_path())

    meta = load_master_meta()
    if timeout_minutes:
        meta["timeout_minutes"] = int(timeout_minutes)
    meta["enabled_at"] = int(time.time())
    save_master_meta(meta)

    # 关键：删掉明文 DEK，磁盘上只留被包裹的版本
    try:
        os.remove(keyfile_path())
    except OSError:
        pass

    # 初始化后立即解锁一次，省得老板马上要再输一遍
    unlock(password)
    return meta


def unlock(password, timeout_minutes=None):
    """校验主密码 → 把 DEK 写进 tmpfs → 记过期时间。"""
    if not master_enabled():
        raise VaultError("vault_locked", "尚未设置主密码，请先 vault-cred init")
    try:
        with open(key_enc_path(), "r", encoding="utf-8") as f:
            rec = json.load(f)
    except (OSError, ValueError):
        raise VaultError("vault_locked", "vault.key.enc 损坏或不可读")

    dek = _unwrap_dek(rec, password)
    if not dek:
        return False

    meta = load_master_meta()
    mins = int(timeout_minutes or meta.get("timeout_minutes") or DEFAULT_TIMEOUT_MIN)
    rdir = _runtime_dir()
    os.makedirs(rdir, mode=0o700, exist_ok=True)
    os.chmod(rdir, 0o700)

    kp = _session_key_path()
    fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(dek)
    os.chmod(kp, 0o600)

    exp = int(time.time()) + mins * 60
    with open(_session_expiry_path(), "w", encoding="utf-8") as f:
        f.write(str(exp))
    os.chmod(_session_expiry_path(), 0o600)
    return True


def lock():
    """立即锁定：删掉 tmpfs 里的 DEK。"""
    removed = False
    for p in (_session_key_path(), _session_expiry_path()):
        if os.path.exists(p):
            try:
                os.remove(p)
                removed = True
            except OSError:
                pass
    return removed


def is_locked():
    """是否处于锁定态（未启用主密码时永远不算锁）。"""
    if not master_enabled():
        return False
    kp = _session_key_path()
    if not os.path.exists(kp):
        return True
    try:
        with open(_session_expiry_path(), "r", encoding="utf-8") as f:
            exp = int(f.read().strip())
    except (OSError, ValueError):
        lock()
        return True
    if int(time.time()) >= exp:
        lock()          # 过期即自动锁
        return True
    return False


def unlock_status():
    """返回 (unlocked, remaining_seconds, expires_at, timeout_minutes)。"""
    meta = load_master_meta()
    timeout = int(meta.get("timeout_minutes") or DEFAULT_TIMEOUT_MIN)
    if not master_enabled():
        return True, None, None, timeout
    if is_locked():
        return False, 0, None, timeout
    try:
        with open(_session_expiry_path(), "r", encoding="utf-8") as f:
            exp = int(f.read().strip())
    except (OSError, ValueError):
        return False, 0, None, timeout
    return True, max(0, exp - int(time.time())), exp, timeout


def change_password(old_password, new_password):
    """改主密码：先验旧的解出 DEK，再用新密码重新包裹。"""
    if not master_enabled():
        raise VaultError("vault_locked", "尚未设置主密码，请先 vault-cred init")
    try:
        with open(key_enc_path(), "r", encoding="utf-8") as f:
            rec = json.load(f)
    except (OSError, ValueError):
        raise VaultError("vault_locked", "vault.key.enc 损坏")
    dek = _unwrap_dek(rec, old_password)
    if not dek:
        return False

    newrec = _wrap_dek(dek, new_password)
    tmp = key_enc_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(newrec, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, key_enc_path())

    # 恢复码是用旧密码体系包的 DEK 副本，改密码不影响它们（它们各自独立包裹 DEK）
    unlock(new_password)
    return True


# ── 恢复码（紧急恢复）──────────────────────────────────────────────────────
#
# 思路：生成 N 个一次性恢复码，每个都能独立解出 DEK（各用自己的 PBKDF2 盐包裹）。
# 磁盘上只存「被恢复码包裹的 DEK」若干份，**不存恢复码明文**。
# 老板抄在纸上/存密码管理器；码丢了 + 主密码忘了 = 数据打不开（这是设计取舍）。

RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_WORDS = (
    "amber", "basil", "cedar", "delta", "ember", "fjord", "glide", "hazel",
    "ivory", "jade", "karma", "lumen", "maple", "nectar", "onyx", "pearl",
    "quartz", "raven", "sable", "topaz", "umber", "vivid", "willow", "xenon",
    "yarrow", "zephyr", "birch", "cobalt", "dune", "flint", "grove", "heron",
)


def _gen_recovery_code():
    """生成形如 xxxx-xxxx-xxxx-xxxx 的恢复码（用词表，便于手抄）。"""
    import secrets
    words = [secrets.choice(RECOVERY_CODE_WORDS) for _ in range(4)]
    return "-".join(words)


def generate_recovery_codes(count=None):
    """生成恢复码并落盘（只存包裹后的 DEK，不存码本身）。

    返回明文码列表 —— **调用方必须只打印一次给老板，不要写日志。**
    """
    if not master_enabled():
        raise VaultError("vault_locked", "请先设置主密码再生成恢复码")
    # 需要解锁态才能拿到 DEK
    dek, _ = current_dek()

    n = int(count or RECOVERY_CODE_COUNT)
    codes = []
    wrapped = []
    for _ in range(n):
        code = _gen_recovery_code()
        # 避免重复
        while code in codes:
            code = _gen_recovery_code()
        codes.append(code)
        wrapped.append(_wrap_dek(dek, code))

    payload = {
        "version": 1,
        "created_at": int(time.time()),
        "created_at_str": time.strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(wrapped),
        "slots": wrapped,
    }
    tmp = recovery_file_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, recovery_file_path())

    return codes


def recovery_available():
    if not os.path.exists(recovery_file_path()):
        return False
    try:
        with open(recovery_file_path(), "r", encoding="utf-8") as f:
            d = json.load(f)
        return bool(d.get("slots"))
    except (OSError, ValueError):
        return False


def recovery_info():
    """返回恢复码信息（不含码本身）。"""
    if not recovery_available():
        return None
    try:
        with open(recovery_file_path(), "r", encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return None
    return {
        "count": len(d.get("slots") or []),
        "created_at": d.get("created_at"),
        "created_at_str": d.get("created_at_str"),
    }


def reset_with_recovery_code(code, new_password):
    """用恢复码重置主密码。

    返回 True/False。成功后该恢复码作废（重新生成一整套）。
    """
    if not recovery_available():
        return False, "没有可用的恢复码文件"
    try:
        with open(recovery_file_path(), "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, ValueError):
        return False, "恢复码文件损坏"

    code = (code or "").strip().lower()
    dek = None
    for rec in payload.get("slots") or []:
        d = _unwrap_dek(rec, code)
        if d:
            dek = d
            break
    if not dek:
        return False, "恢复码无效"

    # 用新主密码重新包裹 DEK
    newrec = _wrap_dek(dek, new_password)
    tmp = key_enc_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(newrec, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, key_enc_path())

    # 旧恢复码全部作废（它们还能解出同一个 DEK，留着等于多把钥匙）
    try:
        os.remove(recovery_file_path())
    except OSError:
        pass

    unlock(new_password)
    return True, "主密码已重置；旧恢复码已全部作废，请重新生成"


# ── 安全审计报告（Watchtower 式）───────────────────────────────────────────

def audit_report():
    """扫描所有凭据与会话，给出风险清单和健康分。

    检查项：
      - 长期未更新（>90 天）
      - 域名白名单为空 / 过宽（*）
      - 凭据类型（basic 弱于 bearer）
      - 会话已过期
      - 是否有恢复码（没有 = 高风险）
      - 是否启用主密码（没有 = 高风险）
    """
    now = int(time.time())
    findings = []          # (severity, 类别, 名字, 说明)
    score = 100

    # ① 保险库整体
    if not master_enabled():
        findings.append(("high", "保险库", "-",
                         "未启用主密码：有 vault.key 就能解密，等同钥匙插在锁上"))
        score -= 30
    if not recovery_available():
        findings.append(("high", "保险库", "-",
                         "没有恢复码：主密码遗忘将无法恢复数据"))
        score -= 15

    meta = load_master_meta()
    timeout = int(meta.get("timeout_minutes") or DEFAULT_TIMEOUT_MIN)
    if timeout > 120:
        findings.append(("low", "保险库", "-",
                         f"自动锁定超时过长（{timeout} 分钟），建议 ≤120"))
        score -= 3

    # ② 凭据
    creds = list_credentials()
    for c in creds:
        name = c.get("name", "?")
        ctype = c.get("type", "?")
        domains = c.get("domains") or []
        created = c.get("created_at") or 0

        if not domains:
            findings.append(("high", "凭据", name, "域名白名单为空（默认拒绝，无法使用）"))
            score -= 8
        elif any(d == "*" or d.startswith("*.") and d.count("*") > 0 and
                 d in ("*", "*.*") for d in domains):
            findings.append(("medium", "凭据", name, "域名白名单过宽"))
            score -= 4

        if ctype == "basic":
            findings.append(("medium", "凭据", name,
                             "basic 类型存的是用户名+密码，风险高于 token"))
            score -= 3

        if created and (now - created) > 90 * 86400:
            days = (now - created) // 86400
            findings.append(("medium", "凭据", name,
                             f"已 {days} 天未更新，建议轮换"))
            score -= 5

        if not os.path.exists(_secret_path(name)):
            findings.append(("high", "凭据", name, "元数据存在但密文缺失"))
            score -= 10

    # ③ 会话
    sessions = list_sessions()
    for s in sessions:
        name = s.get("name", "?")
        if session_expired(s):
            findings.append(("medium", "会话", name,
                             f"会话已于 {s.get('expires_at_str','?')} 过期，需重新捕获"))
            score -= 4
        saved = s.get("saved_at") or 0
        if saved and (now - saved) > 30 * 86400:
            findings.append(("low", "会话", name, "会话已超过 30 天，建议重新登录"))
            score -= 2

    score = max(0, min(100, score))
    if score >= 90:
        grade = "优秀"
    elif score >= 75:
        grade = "良好"
    elif score >= 60:
        grade = "一般"
    else:
        grade = "需改进"

    return {
        "score": score,
        "grade": grade,
        "findings": findings,
        "counts": {
            "credentials": len(creds),
            "sessions": len(sessions),
            "high": sum(1 for f in findings if f[0] == "high"),
            "medium": sum(1 for f in findings if f[0] == "medium"),
            "low": sum(1 for f in findings if f[0] == "low"),
        },
        "master_enabled": master_enabled(),
        "recovery_available": recovery_available(),
        "timeout_minutes": timeout,
    }


# ── 域名白名单 ──────────────────────────────────────────────────────────────

def host_matches_allowlist(host: str, allowlist) -> bool:
    """移植自 agent-id access.mjs hostMatchesAllowlist。

    - 精确匹配：`api.github.com`
    - 通配：`*.github.com` 匹配 `api.github.com` 和裸 `github.com`
    - 空名单 / 非列表 → 一律 False（默认拒绝）
    """
    if not host or not isinstance(allowlist, (list, tuple)):
        return False
    host_l = host.lower()
    for entry in allowlist:
        if not isinstance(entry, str) or not entry:
            continue
        e = entry.lower()
        if e.startswith("*."):
            bare = e[2:]
            if host_l == bare or host_l.endswith("." + bare):
                return True
        elif host_l == e:
            return True
    return False


# ── 凭据元数据 ──────────────────────────────────────────────────────────────

def _meta_path(name):
    return os.path.join(proxy_dir(), name + ".meta.json")


def _secret_path(name):
    return os.path.join(proxy_dir(), name + ".secret.enc")


def meta_exists(name) -> bool:
    return os.path.exists(_meta_path(name))


LEASE_DEFAULT_DAYS = 90


def lease_expiry(meta):
    """租约到期时间戳；没设租约返回 None（老凭据不受影响）。"""
    days = meta.get("lease_days")
    if not days:
        return None
    try:
        return int(meta.get("created_at") or 0) + int(days) * 86400
    except (TypeError, ValueError):
        return None


def lease_state(meta, now_ts=None):
    """(state, days_left)；state ∈ ok / expired / none。"""
    exp = lease_expiry(meta)
    if exp is None:
        return "none", None
    now_ts = int(now_ts if now_ts is not None else __import__("time").time())
    left = (exp - now_ts) // 86400
    return ("expired", -(-(exp - now_ts) // 86400)) if now_ts >= exp else ("ok", left)


def load_meta(name):
    """只读明文元数据（不解密）。不存在 → unknown_credential。"""
    if not CREDNAME_RE.match(name or ""):
        raise VaultError("unknown_credential", "凭据名非法")
    path = _meta_path(name)
    if not os.path.exists(path):
        raise VaultError("unknown_credential", "凭据不存在: " + name)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_meta(meta):
    os.makedirs(proxy_dir(), mode=0o700, exist_ok=True)
    path = _meta_path(meta["name"])
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path


def load_secret(name) -> str:
    """解密取凭据值。**调用方必须已先过白名单校验。**"""
    path = _secret_path(name)
    if not os.path.exists(path):
        raise VaultError("vault_locked", "凭据密文缺失: " + name)
    with open(path, "rb") as f:
        return decrypt(f.read())


def save_secret(name, value: str):
    os.makedirs(proxy_dir(), mode=0o700, exist_ok=True)
    path = _secret_path(name)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(encrypt(value))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def list_credentials():
    """列出凭据元数据（永不读密文）。"""
    if not os.path.isdir(proxy_dir()):
        return []
    out = []
    for fn in sorted(os.listdir(proxy_dir())):
        if not fn.endswith(".meta.json"):
            continue
        try:
            with open(os.path.join(proxy_dir(), fn), "r", encoding="utf-8") as f:
                out.append(json.load(f))
        except (OSError, ValueError):
            continue
    return out


def remove_credential(name):
    removed = []
    for p in (_meta_path(name), _secret_path(name)):
        if os.path.exists(p):
            os.remove(p)
            removed.append(p)
    return removed


# ── 吊销 / 一键 panic ───────────────────────────────────────────────────────
#
# 关键：**只挪走密文，绝不动 vault.key**。key 留着才有恢复的余地
# （把 .panic-<ts>/ 里的密文挪回来 + 重启服务即可原样恢复）。

def _quarantine_dir(tag=None):
    stamp = tag or time.strftime("%Y%m%d-%H%M%S")
    return os.path.join(_vault_dir(), ".panic-" + stamp)


def _secret_files():
    """所有凭据密文文件（proxy 子目录下的 *.secret.enc）。"""
    if not os.path.isdir(proxy_dir()):
        return []
    return [os.path.join(proxy_dir(), fn) for fn in sorted(os.listdir(proxy_dir()))
            if fn.endswith(".secret.enc")]


def _move_aside(paths, dest_dir):
    """把文件挪进隔离目录，保持文件名。返回 (已挪走列表, 失败列表)。"""
    os.makedirs(dest_dir, mode=0o700, exist_ok=True)
    os.chmod(dest_dir, 0o700)
    moved, failed = [], []
    for p in paths:
        try:
            shutil.move(p, os.path.join(dest_dir, os.path.basename(p)))
            moved.append(os.path.basename(p))
        except OSError as e:
            failed.append((p, str(e)))
    return moved, failed


def _systemctl(*args, timeout=25):
    """跑 systemctl --user。返回 (returncode, stdout, stderr)。"""
    try:
        p = subprocess.run(["systemctl", "--user"] + list(args),
                           capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except (OSError, subprocess.SubprocessError) as e:
        return 1, "", str(e)[:200]


def panic(dry_run=False):
    """一键吊销。

    顺序很重要：先 stop（立刻断能力）→ disable（重启也不自愈）→ 挪密文。
    返回一个结果 dict 供 CLI 打印。
    """
    result = {
        "dry_run": dry_run,
        "service_stopped": None,
        "service_disabled": None,
        "secrets": [],
        "moved": [],
        "failed": [],
        "quarantine_dir": None,
    }

    secrets = _secret_files()
    result["secrets"] = [os.path.basename(p) for p in secrets]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    qdir = _quarantine_dir(stamp)
    result["quarantine_dir"] = qdir

    if dry_run:
        return result

    # ① 先停服务 —— 立刻切断 AI 的登录能力
    rc, _, err = _systemctl("stop", SERVICE)
    result["service_stopped"] = (rc == 0)
    if rc != 0:
        result["service_error"] = err[:200]

    # ② 再 disable —— 重启机器也不会自愈，必须人工恢复（安全优先）
    rc2, _, err2 = _systemctl("disable", SERVICE)
    result["service_disabled"] = (rc2 == 0)
    if rc2 != 0:
        result["disable_error"] = err2[:200]

    # ③ 再把密文挪到隔离目录（不 rm，留证据/可恢复）
    if secrets:
        moved, failed = _move_aside(secrets, qdir)
        result["moved"] = moved
        result["failed"] = failed
    else:
        os.makedirs(qdir, mode=0o700, exist_ok=True)
        os.chmod(qdir, 0o700)

    # ④ 审计一条 panic 记录（不含任何凭据值）
    try:
        audit_event(
            action="panic",
            cred="-",
            host="-",
            path="-",
            status=0,
            note="revoked %d credential(s); stopped=%s; disabled=%s; quarantine=%s"
                 % (len(result["moved"]), result["service_stopped"],
                    result["service_disabled"], os.path.basename(qdir)),
        )
    except Exception:
        pass

    return result


def list_quarantines():
    """列出所有可恢复的隔离目录，最新的在前。

    返回 [{"dir": 路径, "stamp": 时间戳串, "files": [密文文件名], "count": n}]
    """
    if not os.path.isdir(_vault_dir()):
        return []
    out = []
    for name in os.listdir(_vault_dir()):
        if not name.startswith(".panic-"):
            continue
        full = os.path.join(_vault_dir(), name)
        if not os.path.isdir(full):
            continue
        try:
            files = sorted(fn for fn in os.listdir(full)
                           if fn.endswith(".secret.enc"))
        except OSError:
            files = []
        out.append({
            "dir": full,
            "stamp": name[len(".panic-"):],
            "files": files,
            "count": len(files),
        })
    # 时间戳是 YYYYmmdd-HHMMSS，字典序即时间序；倒序取最新
    out.sort(key=lambda x: x["stamp"], reverse=True)
    return out


def restore(stamp=None):
    """一条命令恢复：找隔离目录 → 挪回密文 → enable --now → 实测一次调用。

    stamp 为 None 时恢复最新的隔离目录。
    返回结果 dict 供 CLI 打印。
    """
    result = {
        "ok": False,
        "quarantine_dir": None,
        "restored": [],
        "failed": [],
        "service_enabled": None,
        "service_active": None,
        "verify_code": None,
        "verify_cred": None,
        "error": None,
    }

    dirs = list_quarantines()
    if not dirs:
        result["error"] = "没有找到任何 .panic-* 隔离目录，无可恢复内容"
        return result

    target = None
    if stamp is None:
        # 优先挑真正有密文的最新目录（可能存在只放了 REVOKE.md 的目录）
        target = next((d for d in dirs if d.get("count")), dirs[0])
    else:
        for d in dirs:
            if d["stamp"] == stamp or d["dir"] == stamp:
                target = d
                break
        if target is None:
            result["error"] = ("找不到隔离目录: %s（可用 vault-cred restore --list 查看）"
                               % stamp)
            return result

    result["quarantine_dir"] = target["dir"]

    # ① 密文挪回原位
    os.makedirs(proxy_dir(), mode=0o700, exist_ok=True)
    for fn in target["files"]:
        src = os.path.join(target["dir"], fn)
        dst = os.path.join(proxy_dir(), fn)
        try:
            shutil.move(src, dst)
            os.chmod(dst, 0o600)
            result["restored"].append(fn)
        except OSError as e:
            result["failed"].append((fn, str(e)))

    # ①b 隔离目录已空则删掉，避免越积越多；非空则保留并提示
    try:
        leftovers = os.listdir(target["dir"])
    except OSError:
        leftovers = []
    if leftovers and all(fn == "REVOKE.md" for fn in leftovers):
        try:
            shutil.move(os.path.join(target["dir"], "REVOKE.md"),
                        os.path.join(_vault_dir(), "REVOKE-%s.md" % target["stamp"]))
            result["revoke_report_kept"] = "REVOKE-%s.md" % target["stamp"]
            leftovers = []
        except OSError:
            pass
    if leftovers:
        result["dir_kept"] = True
        result["dir_leftovers"] = sorted(leftovers)
    else:
        try:
            os.rmdir(target["dir"])
            result["dir_removed"] = True
        except OSError as e:
            result["dir_kept"] = True
            result["dir_remove_error"] = str(e)

    # ② 服务 enable --now
    rc, _, err = _systemctl("enable", "--now", SERVICE)
    result["service_enabled"] = (rc == 0)
    if rc != 0:
        result["error"] = "服务启动失败: " + err[:200]

    # ③ 等端口起来再确认状态
    time.sleep(1.5)
    rc2, out2, _ = _systemctl("is-active", SERVICE)
    result["service_active"] = (out2 == "active")

    # ④ 实测一次调用（挑一个刚恢复的凭据）。
    #    探针只是加分项：服务已起来就算恢复成功，探针失败只警告、不算失败。
    for fn in result["restored"]:
        name = fn[:-len(".secret.enc")]
        try:
            meta = load_meta(name)
        except VaultError:
            continue
        domains = meta.get("domains") or []
        if not domains:
            continue
        host = domains[0].lstrip("*.") if domains[0].startswith("*.") else domains[0]
        path = probe_path(meta, host)
        code = _probe_via_proxy(name, host, path)
        result["verify_cred"] = name
        result["verify_host"] = host
        result["verify_path"] = path
        result["verify_code"] = code
        break

    # 恢复是否成功只看服务；探针不参与判定
    result["ok"] = (not result["failed"]) and bool(result["service_enabled"]) \
        and bool(result["service_active"])
    try:
        audit_event(
            action="restore", cred="-", host="-", path="-", status=0,
            note="restored %d credential(s) from %s; enabled=%s; verify=%s"
                 % (len(result["restored"]), os.path.basename(target["dir"]),
                    result["service_enabled"], result["verify_code"]),
        )
    except Exception:
        pass

    return result


def probe_path(meta, host):
    """给探针挑一个「大概率非 404」的路径。

    根路径 / 在很多 API 上是 404（例如 api.cloudflare.com/），
    所以按域名给已知端点；未知域名退回 /。
    探针只用来确认「代理能解密并成功转发」，不校验业务语义。
    """
    known = {
        "api.github.com": "/user",
        "api.cloudflare.com": "/client/v4/user",
        "api.openai.com": "/v1/models",
        "api.anthropic.com": "/v1/models",
        "slack.com": "/api/auth.test",
        "api.notion.com": "/v1/users/me",
    }
    return known.get((host or "").lower(), "/")


def _probe_via_proxy(name, host, path="/"):
    """走本地代理发一次 GET，只回状态码，不打印响应体（可能含敏感信息）。"""
    import urllib.error
    import urllib.request
    url = "http://127.0.0.1:%d/%s/%s%s" % (
        PROXY_PORT, name, host, path if path.startswith("/") else "/" + path)
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def revoke(name):
    """吊销单个凭据：密文挪进隔离目录，元数据也一并挪走（否则会留个空壳）。

    返回 (ok, quarantine_dir, moved_files, error)
    """
    if not CREDNAME_RE.match(name or ""):
        return False, None, [], "凭据名非法"
    secret = _secret_path(name)
    if not os.path.exists(secret):
        return False, None, [], "凭据不存在或无密文: " + name

    qdir = _quarantine_dir()
    paths = [secret]
    meta = _meta_path(name)
    if os.path.exists(meta):
        paths.append(meta)

    moved, failed = _move_aside(paths, qdir)
    if failed:
        return False, qdir, moved, failed[0][1]

    try:
        audit_event(action="revoke", cred=name, host="-", path="-", status=0,
                    note="revoked; quarantine=%s" % os.path.basename(qdir))
    except Exception:
        pass
    return True, qdir, moved, None


# ── 审计（append-only + 哈希链）─────────────────────────────────────────────
#
# 每行带 prev_hash / hash：
#     hash = sha256(prev_hash + 本行内容的规范化 JSON)
# 第一行链起点 prev_hash = "genesis"。
# 旧行（无 hash 字段）视为链起点之前的遗留记录，校验时跳过、不报错。
# 改一行 → 该行 hash 对不上；删一行 → 下一行 prev_hash 对不上。两者都能定位行号。

GENESIS = "genesis"


def _canonical(rec):
    """行的规范化内容：排除 prev_hash / hash 两个链字段，键排序后紧凑序列化。"""
    body = {k: v for k, v in rec.items() if k not in ("prev_hash", "hash")}
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _chain_hash(prev_hash, rec):
    return hashlib.sha256((prev_hash + _canonical(rec)).encode("utf-8")).hexdigest()


def last_hash():
    """读审计日志最后一行的 hash。无文件 / 空 / 末行是旧格式 → 返回 GENESIS。"""
    if not os.path.exists(audit_log_path()):
        return GENESIS
    try:
        with open(audit_log_path(), "r", encoding="utf-8", errors="replace") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
    except OSError:
        return GENESIS
    if not lines:
        return GENESIS
    try:
        rec = json.loads(lines[-1])
    except ValueError:
        return GENESIS
    # 末行是旧格式（没有 hash）→ 新链从 genesis 起
    return rec.get("hash") or GENESIS


def audit_event(**fields):
    """通用审计写入口。所有审计都走这里，无密钥纪律只有一处。

    **调用方必须保证传进来的字段不含凭据值。**
    """
    os.makedirs(_vault_dir(), mode=0o700, exist_ok=True)
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "epoch": int(time.time()),
    }
    rec.update(fields)
    prev = last_hash()
    rec["prev_hash"] = prev
    rec["hash"] = _chain_hash(prev, rec)
    line = json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n"
    # O_APPEND：并发写不会互相覆盖
    fd = os.open(audit_log_path(), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode())
    finally:
        os.close(fd)


def audit(cred, host, path, status, note=""):
    """请求类审计（代理用）。只记元信息，绝不记凭据值。"""
    fields = {
        "cred": cred or "-",
        "host": host or "-",
        "path": path or "-",
        "status": status,
    }
    if note:
        fields["note"] = note
    audit_event(**fields)


def verify_chain(path=None):
    """逐行校验哈希链。

    返回 (ok, problems, total, legacy_count)
      problems: [(行号, 说明)]  行号从 1 开始
    """
    path = path or audit_log_path()
    problems = []
    legacy = 0
    total = 0
    if not os.path.exists(path):
        # 文件缺失不是「完整」：无法校验就是无法校验
        return None, [(0, f"审计日志不存在，无法校验: {path}")], 0, 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw_lines = f.read().splitlines()
    if not [l for l in raw_lines if l.strip()]:
        return None, [(0, "审计日志为空，无法校验")], 0, 0

    expected_prev = GENESIS
    chain_started = False

    for idx, raw in enumerate(raw_lines, start=1):
        if not raw.strip():
            continue
        total += 1
        try:
            rec = json.loads(raw)
        except ValueError:
            problems.append((idx, "该行不是合法 JSON（可能被篡改）"))
            chain_started = True
            continue

        if "hash" not in rec:
            if not chain_started:
                legacy += 1          # 旧格式遗留行，作为链起点之前的内容，跳过
                continue
            problems.append((idx, "该行缺少 hash 字段（链在此中断，可能被删改）"))
            continue

        chain_started = True
        prev = rec.get("prev_hash")
        if prev != expected_prev:
            if prev == GENESIS and expected_prev == GENESIS:
                pass
            else:
                problems.append(
                    (idx, "prev_hash 与上一行 hash 不一致（第 %d 行之前可能有行被删除或篡改）" % idx))
        recomputed = _chain_hash(prev or "", rec)
        if recomputed != rec.get("hash"):
            problems.append((idx, "内容与自身 hash 不符（该行被篡改）"))
        expected_prev = rec.get("hash")

    return (len(problems) == 0), problems, total, legacy


def eprint(*a):
    print(*a, file=sys.stderr)


# ── 会话（storage_state）存储 ────────────────────────────────────────────────
#
# 会话 = 登录态，等同密码。所以：
#   - 整份 storage_state JSON 用同一套 openssl aes-256-cbc 加密（复用 vault.key）
#   - 文件权限 600，目录 700
#   - 元数据（名字/域名/时间）明文单独存，方便 list 不碰密文
#   - **绝不打印 cookie / localStorage 值**

SESSION_META_SUFFIX = ".session.json"
SESSION_ENC_SUFFIX = ".session.enc"


def _session_meta_path(name):
    return os.path.join(session_dir(), name + SESSION_META_SUFFIX)


def _session_enc_path(name):
    return os.path.join(session_dir(), name + SESSION_ENC_SUFFIX)


def session_exists(name):
    return os.path.exists(_session_enc_path(name))


def save_session(name, storage_state_json, domain, ttl_days=30, note=""):
    """加密保存 storage_state。返回元数据 dict。"""
    if not CREDNAME_RE.match(name or ""):
        raise VaultError("unknown_credential", "会话名非法")
    os.makedirs(session_dir(), mode=0o700, exist_ok=True)

    blob = encrypt(storage_state_json)
    tmp = _session_enc_path(name) + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
    os.chmod(tmp, 0o600)
    os.replace(tmp, _session_enc_path(name))

    now = int(time.time())
    meta = {
        "name": name,
        "domain": domain,
        "saved_at": now,
        "saved_at_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
        "expires_at": now + int(ttl_days * 86400),
        "expires_at_str": time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(now + int(ttl_days * 86400))),
        "ttl_days": ttl_days,
        "size": len(blob),
    }
    if note:
        meta["note"] = note

    mtmp = _session_meta_path(name) + ".tmp"
    with open(mtmp, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.chmod(mtmp, 0o600)
    os.replace(mtmp, _session_meta_path(name))
    return meta


def load_session_meta(name):
    p = _session_meta_path(name)
    if not os.path.exists(p):
        raise VaultError("unknown_credential", "会话不存在: " + name)
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def load_session_state(name):
    """解密取 storage_state JSON 字符串。调用方负责不要打印它。"""
    p = _session_enc_path(name)
    if not os.path.exists(p):
        raise VaultError("unknown_credential", "会话不存在: " + name)
    with open(p, "rb") as f:
        return decrypt(f.read())


def list_sessions():
    if not os.path.isdir(session_dir()):
        return []
    out = []
    for fn in sorted(os.listdir(session_dir())):
        if not fn.endswith(SESSION_META_SUFFIX):
            continue
        try:
            with open(os.path.join(session_dir(), fn), "r", encoding="utf-8") as f:
                out.append(json.load(f))
        except (OSError, ValueError):
            continue
    out.sort(key=lambda m: m.get("saved_at", 0), reverse=True)
    return out


def remove_session(name):
    removed = []
    for p in (_session_meta_path(name), _session_enc_path(name)):
        if os.path.exists(p):
            os.remove(p)
            removed.append(p)
    return removed


def session_expired(meta):
    exp = meta.get("expires_at")
    return bool(exp) and int(time.time()) > int(exp)
