#!/usr/bin/env bash
# dsh-id 安装：把 CLI 拷到 ~/.local/{bin,lib}，建数据目录。不启动任何服务。
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${HOME}/.local/bin"
LIB="${HOME}/.local/lib"
VAULT="${HOME}/.deepseekbot/vault"

mkdir -p "$BIN" "$LIB" "$VAULT"
chmod 700 "$VAULT"

for f in dsh-id dsh-id-panel vault-login vault-cred vault-session vault-guard vault-exec vault-proxy accounts; do
  install -m 755 "$SRC/cli/bin/$f" "$BIN/$f"
done
install -m 644 "$SRC/cli/bin/panel.html" "$BIN/panel.html"
install -m 644 "$SRC/cli/lib/vaultlib.py" "$LIB/vaultlib.py"
install -m 644 "$SRC/cli/lib/guardlib.py" "$LIB/guardlib.py"

echo "已安装："
echo "  $BIN/dsh-id 及 vault-* 五个命令"
echo "  $LIB/vaultlib.py  $LIB/guardlib.py"
echo "  数据目录 $VAULT (700)"
echo
echo "下一步："
echo "  dsh-id creds add <名字> bearer --domains <域名>   # 存第一个凭据"
echo "  dsh-id                                          # 看状态"
