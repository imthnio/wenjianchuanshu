#!/bin/sh
# Upgrade application code while preserving the existing service's host, port and data directory.
set -eu
[ "$(id -u)" = 0 ] || { echo "请用 root 运行。"; exit 1; }
if [ -d /run/systemd/system ] && [ -f /etc/systemd/system/minishare.service ]; then
  SERVICE=/etc/systemd/system/minishare.service
  INIT=systemd
elif [ -f /etc/init.d/minishare ]; then
  SERVICE=/etc/init.d/minishare
  INIT=openrc
else
  echo "没找到已安装的 minishare，请先运行 install.sh。"
  exit 1
fi
command -v python3 >/dev/null 2>&1 || { echo "缺少 python3，请先重新安装。"; exit 1; }
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT
# Parse the known service templates as data; never execute/source a service file.
python3 - "$SERVICE" "$TMPD" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
values = {}
for name in ('SHARE_HOST', 'SHARE_PORT', 'SHARE_DATA'):
    match = re.search(r'^(?:Environment=|export )' + name + r'=(.+)$', text, re.M)
    if not match:
        sys.exit('无法读取现有配置：' + name)
    values[name] = match.group(1).strip().strip('"')
app = pathlib.Path(values['SHARE_DATA']).parent
if not (app / 'fileshare.py').is_file():
    sys.exit('找不到程序文件，未作修改。')
for name, value in {**values, 'APP_DIR': str(app)}.items():
    pathlib.Path(sys.argv[2], name).write_text(value)
PY
APP_DIR=$(cat "$TMPD/APP_DIR")
BIND=$(cat "$TMPD/SHARE_HOST")
PORT=$(cat "$TMPD/SHARE_PORT")
URL=https://raw.githubusercontent.com/imthnio/wenjianchuanshu/main/fileshare.py
if command -v curl >/dev/null 2>&1; then
  curl -fSL --connect-timeout 15 --max-time 120 --retry 2 "$URL" -o "$TMPD/fileshare.py"
else
  wget -q -T 120 -O "$TMPD/fileshare.py" "$URL"
fi
python3 - "$TMPD/fileshare.py" <<'PY'
import ast, pathlib, sys
ast.parse(pathlib.Path(sys.argv[1]).read_text())
PY
BACKUP="$APP_DIR/fileshare.py.backup.$(date +%Y%m%d%H%M%S).$$"
cp "$APP_DIR/fileshare.py" "$BACKUP"
cp "$TMPD/fileshare.py" "$APP_DIR/fileshare.py.new"
chmod 644 "$APP_DIR/fileshare.py.new"
mv "$APP_DIR/fileshare.py.new" "$APP_DIR/fileshare.py"
restart() {
  if [ "$INIT" = systemd ]; then systemctl restart minishare; else rc-service minishare restart; fi
}
if ! restart || ! python3 "$APP_DIR/fileshare.py" --check "$BIND" "$PORT"; then
  echo "更新后检查未通过，恢复原程序。"
  cp "$BACKUP" "$APP_DIR/fileshare.py"
  restart || true
  if [ "$INIT" = systemd ]; then journalctl -u minishare -n 30 --no-pager || true; else tail -n 30 /var/log/minishare.log /var/log/messages 2>/dev/null || true; fi
  exit 1
fi
# Only correct the IPv6 rule for an existing non-loopback IPv6 listener.
case "$BIND" in
  ::1|127.*) ;;
  *:*)
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
      ufw allow "$PORT"/tcp
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
      firewall-cmd --permanent --add-port="$PORT"/tcp && firewall-cmd --reload
    elif command -v ip6tables >/dev/null 2>&1; then
      ip6tables -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport "$PORT" -j ACCEPT || echo "IPv6 防火墙放行失败，请检查主机规则。"
      echo "请确认 IPv6 防火墙规则在重启后仍保留。"
    fi ;;
esac
echo "修复程序已安装，本机 HTTP 检查通过。原端口、监听地址、密码和文件保留。"
echo "原程序备份：$BACKUP"
echo "这不代表外网已通：还需核对安全组、NAT 映射、访问端的 IPv6 网络。"
echo "如果曾开启 HTTPS 且仍打不开，请重新运行新版 enable-https.sh。"
