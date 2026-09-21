#!/bin/sh
# minishare 一键开启 HTTPS（不用 Cloudflare）
# 要求：一个已经解析(A记录)到这台 VPS 的域名
# 做法：安装 Caddy 反向代理，自动申请 Let's Encrypt 证书并自动续期
# 用法：sh enable-https.sh   （只需回答 1 个问题：域名是什么）
set -eu

echo "==================================="
echo " minishare 一键开启 HTTPS"
echo "==================================="
echo ""

# ---- 必须是 root ----
if [ "$(id -u)" != "0" ]; then
  echo "请用 root 运行：先执行 sudo -i，再粘贴命令。"
  exit 1
fi

# ---- 只问 1 个问题：域名 ----
DOMAIN=""
while [ -z "$DOMAIN" ]; do
  printf "你的域名是什么？（例如：share.example.com）\n> "
  read DOMAIN
  DOMAIN="$(printf '%s' "$DOMAIN" | tr -d '[:space:]')"
done
echo "域名：$DOMAIN"
echo ""

# ---- 确认 minishare 已安装，并找出它的端口 ----
SRV_FILE=""
if [ -f /etc/systemd/system/minishare.service ]; then
  SRV_FILE="/etc/systemd/system/minishare.service"
elif [ -f /etc/init.d/minishare ]; then
  SRV_FILE="/etc/init.d/minishare"
fi
if [ -z "$SRV_FILE" ]; then
  echo "没检测到 minishare，请先装好 minishare 再来开 HTTPS。"
  exit 1
fi
PORT="$(grep -o 'SHARE_PORT=[^ ]*' "$SRV_FILE" 2>/dev/null | head -n 1 | cut -d= -f2 | tr -d '"' || true)"
if [ -z "$PORT" ]; then PORT="8080"; fi
echo "检测到 minishare 端口：$PORT"
echo ""

# ---- [1/6] 检查域名解析 ----
echo "[1/6] 检查域名解析…"
PUBIP="$(curl -s --max-time 10 ifconfig.me 2>/dev/null || curl -s --max-time 10 api.ipify.org 2>/dev/null || true)"
DNSIP="$(getent hosts "$DOMAIN" 2>/dev/null | awk '$1 ~ /^[0-9.]+$/ {print $1; exit}')"
if [ -z "$DNSIP" ]; then
  echo "域名 $DOMAIN 解析不到任何 IP。"
  echo "先去域名服务商把它的 A 记录指到这台 VPS，等生效后再运行。"
  exit 1
fi
if [ -n "$PUBIP" ] && [ "$DNSIP" != "$PUBIP" ]; then
  echo "域名现在解析到 $DNSIP，但本机公网 IP 是 $PUBIP，对不上。"
  echo "证书申请会失败。请先把 A 记录改成 $PUBIP，等生效后再运行。"
  exit 1
fi
echo "域名解析正常（$DOMAIN -> $DNSIP）。"
echo ""

# ---- [2/6] 检查 80/443 是否被占用 ----
echo "[2/6] 检查 80/443 端口…"
if command -v ss >/dev/null 2>&1; then
  for p in 80 443; do
    if ss -ltn 2>/dev/null | grep -q ":$p "; then
      echo "端口 $p 已被占用。HTTPS 需要 80 和 443，请先停掉占用它们的程序（如 nginx / apache），再重新运行。"
      exit 1
    fi
  done
fi
echo "80/443 端口空闲。"
echo ""

# ---- [3/6] 安装 Caddy（官方二进制，单文件） ----
echo "[3/6] 安装 Caddy…"
if ! command -v caddy >/dev/null 2>&1; then
  command -v curl >/dev/null 2>&1 || { echo "需要 curl，请先安装 curl 再运行。"; exit 1; }
  command -v tar >/dev/null 2>&1 || { echo "需要 tar，请先安装 tar 再运行。"; exit 1; }
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64) CARCH="amd64" ;;
    aarch64|arm64) CARCH="arm64" ;;
    armv7l) CARCH="armv7" ;;
    *) echo "不支持的架构：$ARCH"; exit 1 ;;
  esac
  TAG="$(curl -fsSL --max-time 20 https://api.github.com/repos/caddyserver/caddy/releases/latest 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || true)"
  if [ -z "$TAG" ]; then
    echo "获取 Caddy 最新版本失败（网络可能连不上 github），稍后再试。"
    exit 1
  fi
  VER="$(printf '%s' "$TAG" | sed 's/^v//')"
  URL="https://github.com/caddyserver/caddy/releases/download/${TAG}/caddy_${VER}_linux_${CARCH}.tar.gz"
  echo "下载 $URL …"
  TMPD="$(mktemp -d)"
  curl -fsSL --max-time 120 -o "$TMPD/caddy.tar.gz" "$URL"
  tar -xzf "$TMPD/caddy.tar.gz" -C "$TMPD" caddy
  install -m 0755 "$TMPD/caddy" /usr/local/bin/caddy
  rm -rf "$TMPD"
fi
echo "Caddy 就绪：$(caddy version)"
echo ""

# ---- [4/6] 写 Caddy 配置 ----
echo "[4/6] 配置反向代理…"
mkdir -p /etc/caddy
cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
	reverse_proxy 127.0.0.1:$PORT
}
EOF
echo "配置已写入 /etc/caddy/Caddyfile"
echo ""

# ---- [5/6] 设置开机自启并启动 ----
echo "[5/6] 设置开机自启…"
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  cat > /etc/systemd/system/caddy.service <<'EOF'
[Unit]
Description=Caddy Web Server (minishare HTTPS)
After=network-online.target minishare.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now caddy
elif command -v rc-update >/dev/null 2>&1; then
  cat > /etc/init.d/caddy <<'EOF'
#!/sbin/openrc-run
name="caddy"
description="Caddy Web Server (minishare HTTPS)"
command="/usr/local/bin/caddy"
command_args="run --config /etc/caddy/Caddyfile --adapter caddyfile"
command_background=true
pidfile="/run/caddy.pid"
depend() {
	need net
	after minishare
}
EOF
  chmod +x /etc/init.d/caddy
  rc-update add caddy default >/dev/null
  rc-service caddy restart || rc-service caddy start
else
  echo "没检测到 systemd 或 OpenRC，请手动后台运行："
  echo "  nohup /usr/local/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile >/var/log/caddy.log 2>&1 &"
fi
echo ""

# ---- [6/6] 放行防火墙 80/443 ----
echo "[6/6] 放行 80/443 端口…"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 80/tcp >/dev/null
  ufw allow 443/tcp >/dev/null
  echo "ufw 已放行 80/443。"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
  firewall-cmd --permanent --add-service=http >/dev/null
  firewall-cmd --permanent --add-service=https >/dev/null
  firewall-cmd --reload >/dev/null
  echo "firewalld 已放行 80/443。"
elif command -v iptables >/dev/null 2>&1; then
  iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 80 -j ACCEPT
  iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 443 -j ACCEPT
  echo "iptables 已放行 80/443。"
else
  echo "没检测到防火墙工具：如果外网打不开，去云服务商安全组放行 TCP 80/443。"
fi
echo ""

# ---- 收尾：等证书并验证 ----
echo "等待证书申请（最多约 1 分钟）…"
OK=""
i=1
while [ "$i" -le 12 ]; do
  sleep 5
  if curl -fsSL --max-time 10 "https://$DOMAIN/" >/dev/null 2>&1; then OK="yes"; break; fi
  i=$((i + 1))
done

echo ""
echo "==================================="
if [ -n "$OK" ]; then
  echo "HTTPS 开启成功！"
  echo "以后就用这个地址：https://$DOMAIN"
else
  echo "Caddy 已启动，但 https://$DOMAIN 暂时打不开。"
  echo "排查三步："
  echo "1) 域名 A 记录是否已生效（ping 一下 $DOMAIN 看 IP 对不对）"
  echo "2) 云服务商安全组是否放行了 TCP 80/443"
  echo "3) 看日志：journalctl -u caddy -n 50  （OpenRC 看 /var/log/messages）"
fi
echo "证书由 Caddy 自动申请、自动续期，不用管。"
echo "==================================="
