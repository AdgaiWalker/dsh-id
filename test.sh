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
echo "全部通过"
