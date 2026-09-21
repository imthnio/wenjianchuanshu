#!/bin/sh
# minishare 一键安装：Debian / Ubuntu / Alpine / CentOS / Arch 通用
# 用法：
#   本地安装：  git clone <repo> && cd minishare && sudo sh install.sh
#   远程安装：  curl -fsSL <install.sh直链> | sudo MINISHARE_REPO=<user>/<repo> sh
# 环境变量（非交互/预设）：APP_DIR / PORT / BIND / MINISHARE_REPO / NONINTERACTIVE=1
set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行：sudo sh install.sh"
  exit 1
fi

APP_DIR="${APP_DIR:-/opt/minishare}"
PORT="${PORT:-8080}"
BIND="${BIND:-0.0.0.0}"

# ---- 0. 准备安装文件（远程安装时自动下载） ----
if [ ! -f fileshare.py ]; then
  if [ -z "$MINISHARE_REPO" ]; then
    echo "找不到 fileshare.py。"
    echo "请在仓库目录运行，或用环境变量指定仓库："
    echo "  curl -fsSL <install.sh直链> | sudo MINISHARE_REPO=<user>/<repo> sh"
    exit 1
  fi
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

# ---- 1. 交互式确认（可选） ----
if [ -t 0 ] && [ -z "$NONINTERACTIVE" ]; then
  printf "安装目录 [%s]: " "$APP_DIR"; read -r ans; [ -n "$ans" ] && APP_DIR="$ans"
  printf "监听端口 [%s]: " "$PORT"; read -r ans; [ -n "$ans" ] && PORT="$ans"
  printf "监听地址 [%s]: " "$BIND"; read -r ans; [ -n "$ans" ] && BIND="$ans"
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
  echo "已通过 systemd 启动并设为开机自启"
elif command -v rc-service >/dev/null 2>&1; then
  sed -e "s|@APP_DIR@|$APP_DIR|g" -e "s|@BIND@|$BIND|g" \
      -e "s|@PORT@|$PORT|g" -e "s|@PYTHON@|$PYTHON|g" \
      minishare.openrc > /etc/init.d/minishare
  chmod +x /etc/init.d/minishare
  rc-update add minishare default
  rc-service minishare start
  echo "已通过 OpenRC 启动并设为开机自启"
else
  echo "未检测到 systemd / OpenRC，请手动后台运行："
  echo "  cd $APP_DIR && SHARE_HOST=$BIND SHARE_PORT=$PORT nohup $PYTHON fileshare.py >/dev/null 2>&1 &"
fi

echo ""
echo "完成！浏览器打开 http://<服务器IP>:$PORT"
echo "首次打开会让你设置管理员密码，设置完就能发文件 / 建接收链接了。"
