#!/bin/sh
# minishare 一键安装：Debian / Ubuntu / Alpine / CentOS / Arch 通用
#
# 小白用法：SSH 连上服务器（root 用户）后，粘贴下面这一段，回车，
# 然后按提示操作（看不懂就一路回车用默认）：
#
#   curl -fsSL -o /tmp/minishare-install.sh https://raw.githubusercontent.com/imthnio/minishare/main/install.sh && sh /tmp/minishare-install.sh
#
# 进阶：非交互安装可用环境变量预设
#   APP_DIR / PORT / BIND / MINISHARE_REPO / NONINTERACTIVE=1
set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 用户运行（root 下直接运行，或在命令前加 sudo）"
  exit 1
fi

APP_DIR="${APP_DIR:-/opt/minishare}"
PORT="${PORT:-8080}"
BIND="${BIND:-0.0.0.0}"
MINISHARE_REPO="${MINISHARE_REPO:-imthnio/minishare}"

# ---- 0. 准备安装文件（远程安装时自动从 GitHub 下载） ----
if [ ! -f fileshare.py ]; then
  echo "正在从 GitHub 下载 minishare..."
  TMPD="$(mktemp -d)"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "https://github.com/${MINISHARE_REPO}/archive/refs/heads/main.tar.gz" -o "$TMPD/ms.tar.gz"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMPD/ms.tar.gz" "https://github.com/${MINISHARE_REPO}/archive/refs/heads/main.tar.gz"
  else
    echo "需要 curl 或 wget 来下载，请先安装其一"
    exit 1
  fi
  tar xzf "$TMPD/ms.tar.gz" -C "$TMPD"
  cd "$TMPD/${MINISHARE_REPO##*/}-main"
fi

# ---- 1. 安装向导：只有 2 个问题，看不懂就直接回车 ----
if [ -t 0 ] && [ -z "$NONINTERACTIVE" ]; then
  echo "=== minishare 安装向导 ==="
  echo "下面只有 2 个问题，看不懂就直接回车，用括号里的默认。"
  printf "1/2 装到哪个目录？[%s]：" "$APP_DIR"
  read -r ans; [ -n "$ans" ] && APP_DIR="$ans"
  printf "2/2 网页用哪个端口？[%s]：" "$PORT"
  read -r ans; [ -n "$ans" ] && PORT="$ans"
  case "$PORT" in
    ''|*[!0-9]*)
      echo "端口必须是数字，已恢复默认 8080"
      PORT=8080 ;;
  esac
  echo ""
fi

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
  systemctl enable --now minishare
  echo "已设为开机自启并启动（systemd）"
elif command -v rc-service >/dev/null 2>&1; then
  sed -e "s|@APP_DIR@|$APP_DIR|g" -e "s|@BIND@|$BIND|g" \
      -e "s|@PORT@|$PORT|g" -e "s|@PYTHON@|$PYTHON|g" \
      minishare.openrc > /etc/init.d/minishare
  chmod +x /etc/init.d/minishare
  rc-update add minishare default
  rc-service minishare start
  echo "已设为开机自启并启动（OpenRC）"
else
  echo "没检测到 systemd / OpenRC，请手动后台运行："
  echo "  cd $APP_DIR && SHARE_HOST=$BIND SHARE_PORT=$PORT nohup $PYTHON fileshare.py >/dev/null 2>&1 &"
fi

# ---- 5. 收尾：告诉小白下一步做什么 ----
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [ -z "$IP" ]; then IP="<你的服务器IP>"; fi
PUBIP=""
if command -v curl >/dev/null 2>&1; then
  PUBIP="$(curl -s --max-time 5 ifconfig.me 2>/dev/null || curl -s --max-time 5 api.ipify.org 2>/dev/null)"
fi
echo ""
echo "==================================="
echo "安装完成！"
echo "浏览器打开：http://$IP:$PORT"
if [ -n "$PUBIP" ] && [ "$PUBIP" != "$IP" ]; then
  echo "上面是内网地址，只能在机房内网打开。"
  echo "从外网（手机/家里）打开用这个：http://$PUBIP:$PORT"
fi
echo "如果外网打不开，先在云服务器安全组/防火墙放行 TCP 端口 $PORT"
echo "第一次打开会让你设置管理员密码，设完就能用。"
echo "==================================="
