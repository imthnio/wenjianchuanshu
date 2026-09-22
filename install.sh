#!/bin/sh
# minishare 一键安装：Debian / Ubuntu / Alpine / CentOS / Arch 通用
#
# 小白用法：SSH 连上服务器（root 用户）后，粘贴下面这一段，回车，
# 然后按提示操作（看不懂就一路回车用默认）：
#
#   (curl -fSL --connect-timeout 20 --max-time 180 --retry 2 -o /tmp/minishare-install.sh https://raw.githubusercontent.com/imthnio/wenjianchuanshu/main/install.sh || curl -fSL --connect-timeout 20 --max-time 180 --retry 2 -o /tmp/minishare-install.sh https://cdn.jsdelivr.net/gh/imthnio/wenjianchuanshu@main/install.sh) && sh /tmp/minishare-install.sh
#
# 进阶：非交互安装可用环境变量预设
#   APP_DIR / PORT / IPVER(4 或 6，默认 4) / BIND / MINISHARE_REPO / NONINTERACTIVE=1
set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 用户运行（root 下直接运行，或在命令前加 sudo）"
  exit 1
fi

APP_DIR="${APP_DIR:-/opt/minishare}"
# 注意：PORT 没有默认值，安装时必须由用户输入（向导第 2 问），
# 或非交互安装时用环境变量 PORT 指定。
PORT="${PORT:-}"
IPVER="${IPVER:-4}"
BIND="${BIND:-}"
MINISHARE_REPO="${MINISHARE_REPO:-imthnio/wenjianchuanshu}"

# ---- 0. 准备安装文件（远程安装时自动下载） ----
if [ ! -f fileshare.py ] || [ ! -f minishare.service ]; then
  # 精简版 Alpine 常常 curl/wget 都没有（只有 busybox），先自己装一个，
  # 跟下面自动装 python3 一个思路，保证"粘贴就行"
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
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
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    echo "装不上 curl/wget，请手动安装其一后重试（比如 apt install -y curl）"
    exit 1
  fi
  echo "正在下载 minishare..."
  # 按顺序试多个下载地址：GitHub 官方 -> jsdelivr 镜像（部分网络连 GitHub 很慢或连不上）
  MIRRORS="https://raw.githubusercontent.com/${MINISHARE_REPO}/main https://cdn.jsdelivr.net/gh/${MINISHARE_REPO}@main"
  dl() { # 用法: dl 文件名 —— 每个镜像都试一遍，成功就返回
    for m in $MIRRORS; do
      if command -v curl >/dev/null 2>&1; then
        curl -fSL --connect-timeout 15 --max-time 120 --retry 2 -o "$1" "$m/$1" 2>/dev/null && return 0
      else
        # wget 参数必须同时兼容 GNU wget 和 busybox wget（精简 Alpine 只有后者，
        # 它不支持 --connect-timeout，用了会直接报错退出）：-T 两边都是超时秒数
        wget -q -T 120 --tries=2 -O "$1" "$m/$1" 2>/dev/null && return 0
      fi
    done
    return 1
  }
  TMPD="$(mktemp -d)"
  cd "$TMPD"
  for f in fileshare.py minishare.service minishare.openrc; do
    dl "$f" || { echo ""; echo "下载 $f 失败：连不上 GitHub 和镜像站，请检查服务器网络后重试。"; exit 1; }
  done
  echo "下载完成。"
fi

# ---- 1. 安装向导：只有 3 个问题 ----
if [ -t 0 ] && [ -z "$NONINTERACTIVE" ]; then
  echo "=== minishare 安装向导 ==="
  echo "下面只有 3 个问题，第 2 问（端口）没有默认值，必须自己输入。"
  printf "1/3 装到哪个目录？[%s]：" "$APP_DIR"
  read -r ans; [ -n "$ans" ] && APP_DIR="$ans"
  if [ -z "$PORT" ]; then
    while :; do
      printf "2/3 网页用哪个端口？（必须输入，例如 18080）："
      read -r PORT || { echo ""; echo "未输入端口，安装已取消。"; exit 1; }
      case "$PORT" in
        ''|*[!0-9]*) echo "端口必须是纯数字，请重新输入。" ;;
        *) break ;;
      esac
    done
  else
    echo "2/3 网页用哪个端口？$PORT（已通过环境变量 PORT 指定）"
  fi
  printf "3/3 用 IPv4 还是 IPv6？（输入1回车是ipv4,输入2回车是ipv6）："
  read -r ans
  case "$ans" in
    2) IPVER=6 ;;
    *) IPVER=4 ;;
  esac
  echo ""
fi

# 端口必须有效：非交互安装请用环境变量 PORT 指定纯数字端口
case "$PORT" in
  ''|*[!0-9]*)
    echo "未指定有效端口：交互安装请在向导第 2 问输入纯数字端口；非交互安装请设置环境变量 PORT（例如：PORT=18080 …）。"
    exit 1 ;;
esac

# 按选择的 IP 版本决定监听地址
case "$IPVER" in
  6) BIND="${BIND:-::}" ;;
  *) IPVER=4; BIND="${BIND:-0.0.0.0}" ;;
esac

# ---- 2. 安装 python3 ----
if ! command -v python3 >/dev/null 2>&1; then
  echo "正在安装 python3..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update && apt-get install -y python3
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache python3
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm python
  else
    echo "找不到包管理器，请手动安装 python3 后重试"
    exit 1
  fi
fi
PYTHON="$(command -v python3)"

# ---- 3. 拷文件 ----
mkdir -p "$APP_DIR/data/files"
cp fileshare.py "$APP_DIR/fileshare.py"
chmod 644 "$APP_DIR/fileshare.py"

# ---- 4. 开机自启 ----
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  sed -e "s|@APP_DIR@|$APP_DIR|g" -e "s|@BIND@|$BIND|g" \
      -e "s|@PORT@|$PORT|g" -e "s|@PYTHON@|$PYTHON|g" \
      minishare.service > /etc/systemd/system/minishare.service
  systemctl daemon-reload
  systemctl enable minishare
  # 必须用 restart 而不是 start：机器上如果已经跑着旧实例（比如之前装过、
  # 换了端口重装），start 不会重启它，新端口永远不会监听，装完也打不开
  systemctl restart minishare
  echo "已设为开机自启并启动（systemd）"
elif command -v rc-service >/dev/null 2>&1; then
  sed -e "s|@APP_DIR@|$APP_DIR|g" -e "s|@BIND@|$BIND|g" \
      -e "s|@PORT@|$PORT|g" -e "s|@PYTHON@|$PYTHON|g" \
      minishare.openrc > /etc/init.d/minishare
  chmod +x /etc/init.d/minishare
  rc-update add minishare default
  # 必须用 restart 而不是 start：机器上如果已经跑着旧实例（比如之前装过、
  # 换了端口重装），start 不会重启它，新端口永远不会监听，装完也打不开
  rc-service minishare restart
  echo "已设为开机自启并启动（OpenRC）"
else
  echo "没检测到 systemd / OpenRC，请手动后台运行："
  echo "  cd $APP_DIR && SHARE_HOST=$BIND SHARE_PORT=$PORT nohup $PYTHON fileshare.py >/dev/null 2>&1 &"
fi

# ---- 5. 放行端口 ----
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

# ---- 6. 收尾：告诉小白下一步做什么 ----
if [ "$IPVER" = "6" ]; then
  IP="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep ':' | grep -vi '^fe80' | head -n 1)"
  CURLVER="-6"
else
  IP="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9.]+$' | grep -v '^127\.' | head -n 1)"
  CURLVER="-4"
fi
# busybox 的 hostname 不支持 -I（精简 Alpine 常见），拿不到就用 python 兜底，
# 只是展示用，拿不到也不影响安装
if [ -z "$IP" ] && command -v python3 >/dev/null 2>&1; then
  IP="$(python3 - "$IPVER" 2>/dev/null <<'EOF'
import socket, sys
fam = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
try:
    for a in socket.getaddrinfo(socket.gethostname(), None, fam, socket.SOCK_STREAM):
        ip = a[4][0]
        if not (ip.startswith("127.") or ip.startswith("fe80:") or ip == "::1"):
            print(ip)
            break
except Exception:
    pass
EOF
)"
fi
if [ -z "$IP" ]; then IP="<你的服务器IP>"; fi
PUBIP=""
if command -v curl >/dev/null 2>&1; then
  # 强制用选定的 IP 版本查公网 IP，避免机器 IPv6 不好用却返回 v6 地址
  PUBIP="$(curl $CURLVER -s --max-time 5 ifconfig.me 2>/dev/null || curl $CURLVER -s --max-time 5 api.ipify.org 2>/dev/null)"
fi
# IPv6 地址在网址里要加方括号
url() { if [ "$IPVER" = "6" ]; then printf 'http://[%s]:%s' "$1" "$PORT"; else printf 'http://%s:%s' "$1" "$PORT"; fi; }
echo ""
echo "==================================="
echo "安装完成！"
echo "浏览器打开：$(url "$IP")"
if [ -n "$PUBIP" ] && [ "$PUBIP" != "$IP" ]; then
  echo "上面是内网地址，只能在机房内网打开。"
  echo "从外网（手机/家里）打开用这个：$(url "$PUBIP")"
fi
echo "如果外网还是打不开，去云服务商控制台的安全组里放行 TCP 端口 $PORT"
echo "第一次打开会让你设置管理员密码，设完就能用。"
echo "==================================="
