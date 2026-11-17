#!/usr/bin/env bash
# 冒烟测试：在临时 HOME 里装一份、加一个合成凭据、打本地 mock，验证注入与白名单。
# 不碰真实凭据与真实 vault。
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"
PORT="${SMOKE_PORT:-18923}"
cleanup() { [ -n "${MOCK:-}" ] && kill "$MOCK" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT

HOME="$T" bash "$SRC/install.sh" >/dev/null
export HOME="$T"
export PATH="$T/.local/bin:$PATH"

cat > "$T/mock.py" <<'PY'
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path,
                           "auth": self.headers.get("Authorization", "")}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(__import__("os").environ["SMOKE_PORT"])), H).serve_forever()
PY
SMOKE_PORT=$PORT python3 "$T/mock.py" & MOCK=$!
sleep 0.8

echo "1) dsh-id 状态"
dsh-id | head -6

echo
echo "2) 加一个合成凭据（值走 stdin，不进 argv）"
printf 'canary-SECRET-%s\n' "$$" | vault-cred add testcred bearer --domains 127.0.0.1 >/dev/null
echo "   ok"

echo
echo "3) 注入并发请求"
out="$(vault-exec curl testcred "http://127.0.0.1:$PORT/probe")"
echo "   $out"
case "$out" in *"Bearer canary-SECRET-$$"*) echo "   ✓ 凭据已注入" ;; *) echo "   ✗ 没有注入"; exit 1 ;; esac

echo
echo "4) 白名单应当拒绝"
set +e
vault-exec curl testcred "http://localhost:$PORT/probe" >/dev/null 2>&1
code=$?
set -e
[ "$code" = "4" ] && echo "   ✓ 退出码 4（host_not_allowed）" || { echo "   ✗ 退出码 $code"; exit 1; }

echo
echo "5) 凭据值不得进审计"
if grep -q "canary-SECRET-$$" "$T/.deepseekbot/vault/audit.log"; then echo "   ✗ 泄漏"; exit 1; else echo "   ✓ 审计里没有值"; fi

echo
echo "6) 磁盘上是密文"
file "$T/.deepseekbot/vault/proxy/testcred.secret.enc" | grep -q "openssl enc'd data" \
  && echo "   ✓ openssl enc'd data（600）" || { echo "   ✗ 不是密文"; exit 1; }

echo "7) 错误路径要报错退出，不能 NameError"
for args in "rotate nope" "lease nope --days 5"; do
  set +e; out="$(vault-cred $args </dev/null 2>&1)"; code=$?; set -e
  if [ "$code" = "2" ] && echo "$out" | grep -q "vault-cred:"; then
    echo "   ✓ vault-cred $args → exit 2"
  else
    echo "   ✗ vault-cred $args → exit $code / $out"; exit 1
  fi
done

echo "8) 频率/熔断（防封号）"
export VAULT_DIR_OVERRIDE="$T/guard"; mkdir -p "$VAULT_DIR_OVERRIDE"
vault-guard check "发一条帖子" --scope A >/dev/null && echo "   ✓ 首次 allow" || { echo "   ✗ 首次被拦"; exit 1; }
vault-guard record "发一条帖子" --scope A >/dev/null
set +e; vault-guard check "发一条帖子" --scope A >/dev/null 2>&1; c=$?; set -e
[ "$c" = "11" ] && echo "   ✓ 间隔太近 → exit 11" || { echo "   ✗ 间隔检查失败 exit=$c"; exit 1; }
vault-guard record "发一条帖子" --scope B --fail >/dev/null
vault-guard record "发一条帖子" --scope B --fail >/dev/null
set +e; vault-guard check "发一条帖子" --scope B >/dev/null 2>&1; c=$?; set -e
[ "$c" = "11" ] && echo "   ✓ 连续失败熔断 → exit 11" || { echo "   ✗ 熔断失败 exit=$c"; exit 1; }
vault-guard reset --scope B >/dev/null
vault-guard check "发一条帖子" --scope B >/dev/null && echo "   ✓ reset 后恢复" || { echo "   ✗ reset 无效"; exit 1; }

echo
echo "9) 老格式归档（账实一致）"
unset VAULT_DIR_OVERRIDE
python3 - "$HOME" <<'PY'
import os, sys
home = sys.argv[1]
sys.path.insert(0, os.path.join(home, ".local", "lib"))
import vaultlib as V
V.ensure_key(); V.init_machine_binding()
open(os.path.join(V._vault_dir(), "probe__totp.enc"), "wb").write(V.encrypt("JBSWY3DPEHPK3PXP"))
PY
vault-cred adopt >/dev/null
vault-cred list | grep -q "probe" && echo "   ✓ 归档后进索引" || { echo "   ✗ 归档后仍不可见"; exit 1; }
set +e; vault-exec curl probe https://example.com/x >/dev/null 2>&1; c=$?; set -e
[ "$c" = "6" ] && echo "   ✓ totp 不能 exec → exit 6" || { echo "   ✗ totp 竟然能 exec exit=$c"; exit 1; }

echo
echo "10) 作用域（方法 + 路径）"
vault-cred scope testcred --methods GET --paths /probe >/dev/null
set +e; vault-exec curl testcred "http://127.0.0.1:$PORT/probe" -X DELETE >/dev/null 2>&1; c=$?; set -e
[ "$c" = "9" ] && echo "   ✓ DELETE 被作用域拒绝 → exit 9" || { echo "   ✗ 作用域没拦住 exit=$c"; exit 1; }
vault-exec curl testcred "http://127.0.0.1:$PORT/probe" >/dev/null && echo "   ✓ 允许的 GET 照常" || { echo "   ✗ 误拦了 GET"; exit 1; }

echo
echo "11) 机外锚（可核对）"
ANCHOR="$T/anchor.json"
vault-cred audit-anchor --out "$ANCHOR" >/dev/null
vault-cred audit-verify --anchor "$ANCHOR" >/dev/null && echo "   ✓ 锚与链一致" || { echo "   ✗ 锚校验失败"; exit 1; }
python3 - "$HOME" <<'PY'
import json, os, sys
home = sys.argv[1]
p = os.path.join(home, ".deepseekbot", "vault", "audit.log")
lines = open(p).read().splitlines()
rec = json.loads(lines[0]); rec["status"] = 999
lines[0] = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
open(p, "w").write("\n".join(lines) + "\n")
PY
set +e; out="$(vault-cred audit-verify --anchor "$ANCHOR" 2>&1)"; c=$?; set -e
[ "$c" = "1" ] && echo "   ✓ 改一行后锚报不一致 → exit 1" || { echo "   ✗ 改了还报一致: $out"; exit 1; }

echo
echo "全部通过"
