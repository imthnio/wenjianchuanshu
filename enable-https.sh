#!/bin/sh
# minishare 一键开启 HTTPS
# 两种模式：
#   普通 VPS：Caddy 监听 80/443，自动申请 Let's Encrypt 证书（不用 Cloudflare）
#   NAT 机器（80/443 从外网连不进来）：跟随第一步，Caddy 直接复用安装时的端口，
#            证书走 Cloudflare DNS 验证申请（需要一个 Cloudflare API 令牌）
# 用法：sh enable-https.sh，按提示回答几个问题
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

# ---- 问 1：域名 ----
echo "提示：建议用子域名，例如 file.example.com；"
echo "主域名（如 example.com）留着以后做别的用，子域名可以建很多个、每个服务一个。"
echo "（先去域名服务商把这个子域名的 A 记录指到这台 VPS，IPv6 则用 AAAA 记录，灰色云/仅 DNS）"
echo ""
DOMAIN=""
while [ -z "$DOMAIN" ]; do
  printf "你的域名是什么？（例如：file.example.com）\n> "
  read DOMAIN
  DOMAIN="$(printf '%s' "$DOMAIN" | tr -d '[:space:]')"
done
echo "域名：$DOMAIN"
echo ""

# ---- 确认 minishare 已安装，并找出它的端口和监听地址 ----
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
echo "检测到 minishare 端口：$PORT（HTTPS 会跟随这个端口）"
echo ""

# ---- 问 2：IPv4 还是 IPv6（默认跟随 minishare 的监听地址） ----
SRV_HOST="$(grep -o 'SHARE_HOST=[^ ]*' "$SRV_FILE" 2>/dev/null | head -n 1 | cut -d= -f2 | tr -d '"' || true)"
DETECTED_VER=4
case "$SRV_HOST" in *:*) DETECTED_VER=6 ;; esac
IPVER="${IPVER:-$DETECTED_VER}"
if [ -t 0 ] && [ -z "${NONINTERACTIVE:-}" ]; then
  printf "域名解析用 IPv4 还是 IPv6？（跟装 minishare 时保持一致）[%s]：" "$DETECTED_VER"
  read -r ans
  case "$ans" in
    6) IPVER=6 ;;
    4) IPVER=4 ;;
  esac
  echo ""
fi

# ---- 问 3：是不是 NAT 机器 ----
# 自动检测：本机出口 IP 和公网 IP 不一致，多半是 NAT
NAT_DETECTED=0
if [ "$IPVER" = "4" ]; then
  PUBIP_EARLY="$(curl -4 -s --max-time 10 ifconfig.me 2>/dev/null || curl -4 -s --max-time 10 api.ipify.org 2>/dev/null || true)"
  SRCIP="$(ip route get 1.1.1.1 2>/dev/null | grep -o 'src [0-9.]*' | head -n 1 | awk '{print $2}' || true)"
  if [ -n "$PUBIP_EARLY" ] && [ -n "${SRCIP:-}" ] && [ "$PUBIP_EARLY" != "$SRCIP" ]; then
    NAT_DETECTED=1
  fi
fi
NAT=0
if [ -t 0 ] && [ -z "${NONINTERACTIVE:-}" ]; then
  if [ "$NAT_DETECTED" = "1" ]; then
    echo "检测到这台机器是 NAT（内网 IP 出网），80/443 可能从外网连不进来。"
    printf "用 NAT 模式开启 HTTPS 吗？（Caddy 直接用端口 %s，证书走 Cloudflare DNS 申请）[Y/n]：" "$PORT"
    read -r ans
    case "$ans" in n|N) NAT=0 ;; *) NAT=1 ;; esac
  else
    printf "这是 NAT 机器吗？（80/443 从外网连不进来那种；是就输入 y）[y/N]："
    read -r ans
    case "$ans" in y|Y) NAT=1 ;; *) NAT=0 ;; esac
  fi
  echo ""
fi
if [ "$NAT" = "1" ] && [ "$IPVER" = "6" ]; then
  echo "NAT 模式目前只支持 IPv4，请用 IPv4 重装 minishare 后再试。"
  exit 1
fi
if [ "$NAT" = "1" ]; then
  echo "使用 NAT 模式：https://$DOMAIN:$PORT"
else
  echo "使用普通模式：https://$DOMAIN（80/443）"
fi
echo ""

# ---- [1] 检查域名解析 ----
echo "[1] 检查域名解析…"
if [ "$IPVER" = "6" ]; then
  PUBIP="$(curl -6 -s --max-time 10 ifconfig.me 2>/dev/null || curl -6 -s --max-time 10 api.ipify.org 2>/dev/null || true)"
  DNSIP="$(getent hosts "$DOMAIN" 2>/dev/null | awk '$1 ~ /:/ {print $1; exit}')"
  REC="AAAA"
else
  PUBIP="$(curl -4 -s --max-time 10 ifconfig.me 2>/dev/null || curl -4 -s --max-time 10 api.ipify.org 2>/dev/null || true)"
  DNSIP="$(getent hosts "$DOMAIN" 2>/dev/null | awk '$1 ~ /^[0-9.]+$/ {print $1; exit}')"
  REC="A"
fi
if [ -z "$DNSIP" ]; then
  echo "域名 $DOMAIN 解析不到任何 IP。"
  echo "先去域名服务商把它的 $REC 记录指到这台 VPS，等生效后再运行。"
  exit 1
fi
if [ -n "$PUBIP" ] && [ "$DNSIP" != "$PUBIP" ]; then
  echo "域名现在解析到 $DNSIP，但本机公网 IP 是 $PUBIP，对不上。"
  echo "证书申请会失败。请先把 $REC 记录改成 $PUBIP，等生效后再运行。"
  exit 1
fi
echo "域名解析正常（$DOMAIN -> $DNSIP）。"
echo ""

if [ "$NAT" = "1" ]; then

# ================= NAT 模式 =================
# Caddy 复用安装时的端口 PORT（minishare 收进 127.0.0.1），
# 证书用 certbot + Cloudflare DNS 验证申请，自动续期。

# ---- [2] Cloudflare API 令牌 ----
echo "[2] 准备 Cloudflare API 令牌…"
TOKEN_FILE="/root/.secrets-cloudflare.ini"
if grep -qs "dns_cloudflare_api_token" "$TOKEN_FILE" 2>/dev/null; then
  echo "找到已有的 Cloudflare 令牌：$TOKEN_FILE"
else
  echo "NAT 模式要用 Cloudflare DNS 自动验证域名，需要一个 API 令牌（只用来验证 DNS，不碰别的）。"
  echo "创建步骤："
  echo "  1) 打开 dash.cloudflare.com 登录"
  echo "  2) 右上角头像 → 我的个人资料 → 左侧 API 令牌 → 创建令牌"
  echo "  3) 选“编辑区域 DNS”模板，区域资源里选你的域名所在的区域"
  echo "  4) 继续 → 创建，把生成的令牌复制出来（只显示一次）"
  printf "把令牌粘贴到这里：\n> "
  read -r CFTOKEN
  CFTOKEN="$(printf '%s' "$CFTOKEN" | tr -d '[:space:]')"
  if [ -z "$CFTOKEN" ]; then echo "令牌不能为空。"; exit 1; fi
  printf 'dns_cloudflare_api_token = %s\n' "$CFTOKEN" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
  echo "令牌已保存到 $TOKEN_FILE"
fi
echo ""

# ---- [3] 安装 certbot ----
echo "[3] 安装 certbot…"
if ! command -v certbot >/dev/null 2>&1 || ! certbot plugins 2>/dev/null | grep -qi "dns-cloudflare"; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update && apt-get install -y certbot python3-certbot-dns-cloudflare
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache certbot certbot-dns-cloudflare
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y certbot python3-certbot-dns-cloudflare
  elif command -v yum >/dev/null 2>&1; then
    yum install -y certbot python3-certbot-dns-cloudflare
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm certbot certbot-dns-cloudflare
  else
    echo "找不到包管理器，请手动安装 certbot 和 dns-cloudflare 插件后重试。"
    exit 1
  fi
fi
if ! certbot plugins 2>/dev/null | grep -qi "dns-cloudflare"; then
  echo "没装上 certbot 的 dns-cloudflare 插件，请手动安装后重试。"
  exit 1
fi
echo "certbot 就绪。"
echo ""

# ---- [4] 申请证书（Cloudflare DNS 验证） ----
echo "[4] 申请证书（Cloudflare DNS 验证）…"
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  RELOAD_HOOK="systemctl reload caddy 2>/dev/null || systemctl restart caddy 2>/dev/null || true"
else
  RELOAD_HOOK="rc-service caddy restart 2>/dev/null || true"
fi
certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
  --dns-cloudflare --dns-cloudflare-credentials "$TOKEN_FILE" \
  --dns-cloudflare-propagation-seconds 20 \
  -d "$DOMAIN" \
  --deploy-hook "$RELOAD_HOOK"
CERTDIR="/etc/letsencrypt/live/$DOMAIN"
echo "证书就绪：$CERTDIR"
echo ""

# ---- [5] 把 minishare 收进内网，端口让给 Caddy ----
echo "[5] 把 minishare 收进内网（127.0.0.1:$PORT），端口 $PORT 让给 Caddy…"
case "$SRV_FILE" in
  *.service)
    sed -i 's/^Environment=SHARE_HOST=.*/Environment=SHARE_HOST=127.0.0.1/' "$SRV_FILE"
    systemctl daemon-reload
    systemctl restart minishare
    ;;
  *)
    sed -i 's/^export SHARE_HOST=.*/export SHARE_HOST="127.0.0.1"/' "$SRV_FILE"
    rc-service minishare restart
    ;;
esac
echo ""

# ---- [6] 安装 Caddy（官方二进制，单文件） ----
echo "[6] 安装 Caddy…"
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

# ---- [7] 写 Caddy 配置 ----
echo "[7] 配置反向代理（Caddy 监听 $PORT）…"
mkdir -p /etc/caddy
cat > /etc/caddy/Caddyfile <<EOF
https://$DOMAIN:$PORT {
	tls $CERTDIR/fullchain.pem $CERTDIR/privkey.pem
	reverse_proxy 127.0.0.1:$PORT
}
EOF
echo "配置已写入 /etc/caddy/Caddyfile"
echo ""

# ---- [8] 设置开机自启并启动 ----
echo "[8] 设置开机自启…"
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
  systemctl enable caddy >/dev/null 2>&1 || true
  systemctl restart caddy
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

# ---- [9] 放行防火墙 ----
echo "[9] 放行 $PORT 端口…"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "$PORT"/tcp >/dev/null
  echo "ufw 已放行 $PORT。"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
  firewall-cmd --permanent --add-port="$PORT"/tcp >/dev/null
  firewall-cmd --reload >/dev/null
  echo "firewalld 已放行 $PORT。"
elif command -v iptables >/dev/null 2>&1; then
  iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT
  echo "iptables 已放行 $PORT。"
else
  echo "没检测到防火墙工具：如果外网打不开，去云服务商安全组放行 TCP $PORT。"
fi
echo ""

# ---- certbot 自动续期 ----
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  echo "证书每 90 天由 certbot 自动续期（Cloudflare DNS 验证），不用管。"
else
  if command -v crontab >/dev/null 2>&1 && ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
    (crontab -l 2>/dev/null || true; echo "17 3 * * * certbot renew -q") | crontab -
    echo "已添加每天自动续期任务。"
  fi
fi
echo ""

# ---- 收尾：验证 ----
echo "验证 https://$DOMAIN:$PORT/ …"
OK=""
i=1
while [ "$i" -le 12 ]; do
  sleep 5
  if curl -fsSL --max-time 10 "https://$DOMAIN:$PORT/" >/dev/null 2>&1; then OK="yes"; break; fi
  i=$((i + 1))
done

echo ""
echo "==================================="
if [ -n "$OK" ]; then
  echo "HTTPS 开启成功！"
  echo "以后就用这个地址：https://$DOMAIN:$PORT"
  echo "（minishare 已收进内网，Caddy 在 $PORT 上提供 HTTPS）"
else
  echo "Caddy 已启动，但 https://$DOMAIN:$PORT 暂时打不开。"
  echo "排查三步："
  echo "1) 域名 A 记录是否已生效（ping 一下 $DOMAIN 看 IP 对不对）"
  echo "2) 服务商有没有把 TCP 端口 $PORT 转发到这台机器"
  echo "3) 看日志：journalctl -u caddy -n 50  （OpenRC 看 /var/log/messages）"
fi
echo "==================================="

else

# ================= 普通模式 =================
# Caddy 监听 80/443，自动申请 Let's Encrypt 证书。

# ---- [2] 检查 80/443 是否被占用 ----
echo "[2] 检查 80/443 端口…"
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

# ---- [3] 安装 Caddy（官方二进制，单文件） ----
echo "[3] 安装 Caddy…"
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

# ---- [4] 写 Caddy 配置 ----
echo "[4] 配置反向代理…"
mkdir -p /etc/caddy
cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
	reverse_proxy 127.0.0.1:$PORT
}
EOF
echo "配置已写入 /etc/caddy/Caddyfile"
echo ""

# ---- [5] 设置开机自启并启动 ----
echo "[5] 设置开机自启…"
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
  systemctl enable caddy >/dev/null 2>&1 || true
  systemctl restart caddy
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

# ---- [6] 放行防火墙 80/443 ----
echo "[6] 放行 80/443 端口…"
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

fi
