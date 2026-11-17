#!/usr/bin/env bash
# dsh-id 安装：把 CLI 拷到 ~/.local/{bin,lib}，建数据目录。不启动任何服务。
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${HOME}/.local/bin"
LIB="${HOME}/.local/lib"
VAULT="${HOME}/.deepseekbot/vault"

mkdir -p "$BIN" "$LIB" "$VAULT"
chmod 700 "$VAULT"

# PATH 上只放 2 个真命令 + 3 个兼容壳
for f in dsh-id dsh-id-panel vault-login vault-session vault-exec; do
  install -m 755 "$SRC/cli/bin/$f" "$BIN/$f"
done
install -m 644 "$SRC/cli/bin/panel.html" "$BIN/panel.html"
install -m 644 "$SRC/cli/lib/vaultlib.py" "$LIB/vaultlib.py"
install -m 644 "$SRC/cli/lib/guardlib.py" "$LIB/guardlib.py"
mkdir -p "$LIB/dsh-id"
for f in creds guard exec session login; do
  install -m 644 "$SRC/cli/lib/dsh-id/$f.py" "$LIB/dsh-id/$f.py"
done

echo "已安装："
echo "  $BIN/dsh-id（伞形入口） $BIN/dsh-id-panel（面板服务）"
echo "  $BIN/vault-{exec,session,login}（兼容壳，转 dsh-id）"
echo "  内部实现 $LIB/dsh-id/*.py"
echo "  $LIB/vaultlib.py  $LIB/guardlib.py"
echo "  数据目录 $VAULT (700)"
echo
echo "下一步："
echo "  dsh-id creds add <名字> bearer --domains <域名>   # 存第一个凭据"
echo "  dsh-id                                          # 看状态"
