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

# 查域名解析到的 IP：精简版 Alpine 默认没有 getent（它在 musl-utils 包里，
# 小鸡模板一般不装），getent 不可用就换 python3（装 minishare 时必装了 python3）
dns_ip() { # 用法: dns_ip 域名 4|6
  _di_domain="$1" _di_ver="$2"
  if command -v getent >/dev/null 2>&1; then
    if [ "$_di_ver" = "6" ]; then
      getent hosts "$_di_domain" 2>/dev/null | awk '$1 ~ /:/ {print $1; exit}'
    else
      getent hosts "$_di_domain" 2>/dev/null | awk '$1 ~ /^[0-9.]+$/ {print $1; exit}'
    fi
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$_di_domain" "$_di_ver" 2>/dev/null <<'EOF'
import socket, sys
fam = socket.AF_INET6 if sys.argv[2] == "6" else socket.AF_INET
try:
    for a in socket.getaddrinfo(sys.argv[1], None, fam, socket.SOCK_STREAM):
        print(a[4][0])
        break
except Exception:
    pass
EOF
  fi
}

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
if [ -z "$PORT" ]; then PORT="18080"; fi
echo "检测到 minishare 端口：${PORT}（HTTPS 会跟随这个端口）"
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
  if [ -z "$SRCIP" ] && command -v python3 >/dev/null 2>&1; then
    # 精简系统可能没装 iproute2（没有 ip 命令），用 python 拿本机出口 IP
    SRCIP="$(python3 - 2>/dev/null <<'EOF'
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("1.1.1.1", 80))
    print(s.getsockname()[0])
except Exception:
    pass
EOF
)"
  fi
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
ORIG_PORT="$PORT"
if [ "$NAT" = "1" ] && [ -f /etc/minishare-nat-port ]; then
  PORT="$(cat /etc/minishare-nat-port)"
  case "$PORT" in ''|*[!0-9]*) echo "保存的 HTTPS 端口无效。"; exit 1 ;; esac
  if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then exit 1; fi
fi
if [ "$NAT" = "1" ]; then
  echo "使用 NAT 模式：https://$DOMAIN:$PORT"
else
  echo "使用普通模式：https://${DOMAIN}（80/443）"
fi
echo ""

# ---- [1] 检查域名解析 ----
echo "[1] 检查域名解析…"
if [ "$IPVER" = "6" ]; then
  PUBIP="$(curl -6 -s --max-time 10 ifconfig.me 2>/dev/null || curl -6 -s --max-time 10 api.ipify.org 2>/dev/null || true)"
  DNSIP="$(dns_ip "$DOMAIN" 6)"
  REC="AAAA"
else
  PUBIP="$(curl -4 -s --max-time 10 ifconfig.me 2>/dev/null || curl -4 -s --max-time 10 api.ipify.org 2>/dev/null || true)"
  DNSIP="$(dns_ip "$DOMAIN" 4)"
  REC="A"
fi
if [ -z "$DNSIP" ]; then
  echo "域名 $DOMAIN 解析不到任何 IP。"
  echo "先去域名服务商把它的 $REC 记录指到这台 VPS，等生效后再运行。"
  exit 1
fi
if [ -n "$PUBIP" ] && [ "$DNSIP" != "$PUBIP" ]; then
  echo "域名现在解析到 ${DNSIP}，但本机公网 IP 是 ${PUBIP}，对不上。"
  echo "证书申请会失败。请先把 $REC 记录改成 ${PUBIP}，等生效后再运行。"
  exit 1
fi
echo "域名解析正常（$DOMAIN -> ${DNSIP}）。"
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

# ---- [5] 安装 Caddy（官方二进制，单文件，先装好再动 minishare） ----
echo "[5] 安装 Caddy…"
if ! command -v caddy >/dev/null 2>&1; then
  if ! command -v curl >/dev/null 2>&1; then
    echo "正在安装 curl..."
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update && apt-get install -y curl
    elif command -v apk >/dev/null 2>&1; then
      apk add --no-cache curl
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y curl
    elif command -v yum >/dev/null 2>&1; then
      yum install -y curl
    elif command -v pacman >/dev/null 2>&1; then
      pacman -Sy --noconfirm curl
    fi
  fi
  command -v curl >/dev/null 2>&1 || { echo "装不上 curl，请手动安装后重试。"; exit 1; }
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

# Caddy wildcard bind and Python loopback bind cannot share one TCP port.
BACKEND_PORT="$(python3 - <<'PYPORT'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PYPORT
)"
ORIG_HOST="${SRV_HOST:-0.0.0.0}"
BACKUP_DIR="$(mktemp -d)"
cp "$SRV_FILE" "$BACKUP_DIR/minishare-service"
mkdir -p /etc/caddy
if [ -f /etc/caddy/Caddyfile ]; then cp /etc/caddy/Caddyfile "$BACKUP_DIR/Caddyfile"; fi
rollback_https() {
  result=$?
  trap - EXIT
  if [ "$result" -ne 0 ]; then
    echo "HTTPS 启动失败，恢复原 minishare 配置（$ORIG_HOST:${ORIG_PORT}）。"
    if [ -d /run/systemd/system ]; then
      systemctl stop caddy || true
    else
      rc-service caddy stop || true
    fi
    cp "$BACKUP_DIR/minishare-service" "$SRV_FILE"
    if [ -d /run/systemd/system ]; then
      systemctl daemon-reload
      systemctl restart minishare || true
    else
      rc-service minishare restart || true
    fi
    if [ -f "$BACKUP_DIR/Caddyfile" ]; then
      cp "$BACKUP_DIR/Caddyfile" /etc/caddy/Caddyfile
      if [ -d /run/systemd/system ]; then systemctl restart caddy || true; else rc-service caddy restart || true; fi
    else
      rm -f /etc/caddy/Caddyfile
    fi
  fi
  rm -rf "$BACKUP_DIR"
  exit "$result"
}
trap rollback_https EXIT

# ---- [6] 写 Caddy 配置 ----
echo "[6] Caddy 监听 ${PORT}，Python 后端使用独立本地端口 ${BACKEND_PORT}…"
cat > /etc/caddy/Caddyfile <<EOF
https://$DOMAIN:$PORT {
	tls $CERTDIR/fullchain.pem $CERTDIR/privkey.pem
	reverse_proxy 127.0.0.1:$BACKEND_PORT
}
EOF

# ---- [7] 把 minishare 收进内网，使用不同端口 ----
case "$SRV_FILE" in
  *.service)
    sed -i -e 's/^Environment=SHARE_HOST=.*/Environment=SHARE_HOST=127.0.0.1/' \
      -e "s/^Environment=SHARE_PORT=.*/Environment=SHARE_PORT=$BACKEND_PORT/" "$SRV_FILE"
    systemctl daemon-reload
    systemctl restart minishare
    ;;
  *)
    sed -i -e 's/^export SHARE_HOST=.*/export SHARE_HOST="127.0.0.1"/' \
      -e "s/^export SHARE_PORT=.*/export SHARE_PORT=\"$BACKEND_PORT\"/" "$SRV_FILE"
    rc-service minishare restart
    ;;
esac

# ---- [8] 设置开机自启并启动（启动失败则回滚 minishare，不让站点变砖） ----
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
	use net
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

# ---- [8b] 确认 Caddy 真的在跑，否则回滚 minishare ----
CADDY_OK=0
CADDY_MANAGED=1
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  sleep 3
  systemctl is-active --quiet caddy && CADDY_OK=1
elif command -v rc-service >/dev/null 2>&1; then
  sleep 3
  rc-service caddy status >/dev/null 2>&1 && CADDY_OK=1
else
  CADDY_MANAGED=0
fi
if [ "$CADDY_MANAGED" = "1" ] && [ "$CADDY_OK" != "1" ]; then
  echo "Caddy 没能启动，请检查日志；即将自动恢复原配置。"
  exit 1
fi
if [ "$CADDY_MANAGED" != "1" ]; then
  echo "缺少受支持的服务管理器，HTTPS 未完成。"
  exit 1
fi
printf '%s\n' "$PORT" > /etc/minishare-nat-port
trap - EXIT
rm -rf "$BACKUP_DIR"
echo "Caddy 运行中。"
echo ""

# ---- [9] 放行防火墙 ----
echo "[9] 放行 $PORT 端口…"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "$PORT"/tcp >/dev/null
  echo "ufw 已放行 ${PORT}。"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
  firewall-cmd --permanent --add-port="$PORT"/tcp >/dev/null
  firewall-cmd --reload >/dev/null
  echo "firewalld 已放行 ${PORT}。"
elif command -v iptables >/dev/null 2>&1; then
  iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT
  echo "iptables 已放行 ${PORT}。"
else
  echo "没检测到防火墙工具：如果外网打不开，去云服务商安全组放行 TCP ${PORT}。"
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
  # OpenRC 系统上 cron 守护进程默认可能没进开机启动，任务加了也白加；尽量把它拉起来
  _CRON_OK=""
  if command -v rc-update >/dev/null 2>&1; then
    for _cs in crond dcron cron; do
      if [ -f "/etc/init.d/$_cs" ]; then
        rc-update add "$_cs" default >/dev/null 2>&1
        if rc-service "$_cs" start >/dev/null 2>&1; then _CRON_OK="yes"; fi
        break
      fi
    done
  fi
  if [ -z "$_CRON_OK" ]; then
    echo "提醒：这台机器上没找到运行中的 cron 服务，证书到期不会自动续期。"
    echo "Alpine 上可执行 apk add --no-cache dcron 后重新运行本脚本。"
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
# ss 在精简系统上可能没有（iproute2 没装），用 busybox 自带的 netstat 兜底；
# 两个都没有就跳过检查（后面 Caddy 起不来会有明确报错）
if command -v ss >/dev/null 2>&1; then
  _LISTEN="$(ss -ltn 2>/dev/null)"
elif command -v netstat >/dev/null 2>&1; then
  _LISTEN="$(netstat -ltn 2>/dev/null)"
else
  _LISTEN=""
fi
for p in 80 443; do
  if [ -n "$_LISTEN" ] && printf '%s\n' "$_LISTEN" | grep -q ":$p "; then
    echo "端口 $p 已被占用。HTTPS 需要 80 和 443，请先停掉占用它们的程序（如 nginx / apache），再重新运行。"
    exit 1
  fi
done
echo "80/443 端口空闲."
echo ""

# ---- [3] 安装 Caddy（官方二进制，单文件） ----
echo "[3] 安装 Caddy…"
if ! command -v caddy >/dev/null 2>&1; then
  if ! command -v curl >/dev/null 2>&1; then
    echo "正在安装 curl..."
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update && apt-get install -y curl
    elif command -v apk >/dev/null 2>&1; then
      apk add --no-cache curl
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y curl
    elif command -v yum >/dev/null 2>&1; then
      yum install -y curl
    elif command -v pacman >/dev/null 2>&1; then
      pacman -Sy --noconfirm curl
    fi
  fi
  command -v curl >/dev/null 2>&1 || { echo "装不上 curl，请手动安装后重试。"; exit 1; }
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
case "$SRV_HOST" in
  ::) UPSTREAM="[::1]:$PORT" ;;
  *:*) UPSTREAM="[$SRV_HOST]:$PORT" ;;
  0.0.0.0|'') UPSTREAM="127.0.0.1:$PORT" ;;
  *) UPSTREAM="$SRV_HOST:$PORT" ;;
esac
mkdir -p /etc/caddy
cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
	reverse_proxy $UPSTREAM
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
	use net
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
else
  FW=iptables
  [ "$IPVER" = "6" ] && FW=ip6tables
  if command -v "$FW" >/dev/null 2>&1; then
    for HTTP_PORT in 80 443; do
      "$FW" -C INPUT -p tcp --dport "$HTTP_PORT" -j ACCEPT 2>/dev/null || "$FW" -I INPUT -p tcp --dport "$HTTP_PORT" -j ACCEPT
    done
    echo "$FW 已临时放行 80/443，请确认规则持久化。"
  else
    echo "请检查主机防火墙和服务商安全组，放行 TCP 80/443。"
  fi
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
