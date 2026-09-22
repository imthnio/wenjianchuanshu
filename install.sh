#!/bin/sh
# minishare 一键安装：Debian / Ubuntu / Alpine / CentOS / Arch 通用
#
# 小白用法：SSH 连上服务器（root 用户）后，粘贴下面这一段，回车，
# 然后按提示操作（端口必须自己输入）：
#
#   (curl -fSL --connect-timeout 20 --max-time 180 --retry 2 -o /tmp/minishare-install.sh https://raw.githubusercontent.com/imthnio/wenjianchuanshu/main/install.sh || curl -fSL --connect-timeout 20 --max-time 180 --retry 2 -o /tmp/minishare-install.sh https://cdn.jsdelivr.net/gh/imthnio/wenjianchuanshu@main/install.sh) && sh /tmp/minishare-install.sh
#
# 进阶：非交互安装可用环境变量预设
#   APP_DIR / PORT / IPVER(4 或 6，默认 4) / BIND / MINISHARE_REPO / NONINTERACTIVE=1
#   PUBLIC_HOST / PUBLIC_PORT：NAT 入站地址和外部映射端口，可选
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
SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$SOURCE_DIR/fileshare.py" ] && [ -f "$SOURCE_DIR/minishare.service" ] && [ -f "$SOURCE_DIR/minishare.openrc" ]; then
  cd "$SOURCE_DIR"
else
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
        wget -q -T 120 -O "$1" "$m/$1" 2>/dev/null && return 0
      fi
    done
    return 1
  }
  TMPD="$(mktemp -d)"
  trap 'rm -rf "$TMPD"' EXIT
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
    echo "2/3 网页用哪个端口？${PORT}（已通过环境变量 PORT 指定）"
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
if [ "$PORT" -lt 1 ] 2>/dev/null || ! [ "$PORT" -le 65535 ] 2>/dev/null; then
  echo "端口必须在 1–65535 之间。"
  exit 1
fi
# Service templates embed paths in shell/systemd syntax: reject unsafe paths.
case "$APP_DIR" in
  /*) ;;
  *) echo "安装目录必须是绝对路径，例如 /opt/minishare。"; exit 1 ;;
esac
case "$APP_DIR" in
  *[!a-zA-Z0-9_./-]*) echo "安装目录只能含英文字母、数字、下划线、点、斜杠和短横线。"; exit 1 ;;
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
# Validate before touching an existing installation.
"$PYTHON" - "$BIND" <<'PY'
import ipaddress, sys
try:
    ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit("BIND 必须是有效的 IPv4 或 IPv6 地址。")
PY
case "$BIND" in *:*) IPVER=6 ;; *) IPVER=4 ;; esac
"$PYTHON" - fileshare.py <<'PY'
import ast, sys
with open(sys.argv[1], encoding="utf-8") as f:
    ast.parse(f.read())
PY
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  INIT=systemd
elif command -v rc-service >/dev/null 2>&1; then
  INIT=openrc
else
  echo "未检测到 systemd / OpenRC，无法自动启动；安装已停止。"
  exit 1
fi

# ---- 3. 拷文件 ----
mkdir -p "$APP_DIR/data/files"
if [ "$(pwd)" != "$APP_DIR" ]; then cp fileshare.py "$APP_DIR/fileshare.py"; fi
chmod 644 "$APP_DIR/fileshare.py"

# ---- 4. 开机自启 ----
if [ "$INIT" = "systemd" ]; then
  sed -e "s|@APP_DIR@|$APP_DIR|g" -e "s|@BIND@|$BIND|g" \
      -e "s|@PORT@|$PORT|g" -e "s|@PYTHON@|$PYTHON|g" \
      minishare.service > /etc/systemd/system/minishare.service
  systemctl daemon-reload
  systemctl enable minishare
  # 必须用 restart 而不是 start：机器上如果已经跑着旧实例（比如之前装过、
  # 换了端口重装），start 不会重启它，新端口永远不会监听，装完也打不开
  systemctl restart minishare || { journalctl -u minishare -n 30 --no-pager; exit 1; }
  echo "已设为开机自启并启动（systemd）"
elif [ "$INIT" = "openrc" ]; then
  sed -e "s|@APP_DIR@|$APP_DIR|g" -e "s|@BIND@|$BIND|g" \
      -e "s|@PORT@|$PORT|g" -e "s|@PYTHON@|$PYTHON|g" \
      minishare.openrc > /etc/init.d/minishare
  chmod +x /etc/init.d/minishare
  rc-update add minishare default
  # 必须用 restart 而不是 start：机器上如果已经跑着旧实例（比如之前装过、
  # 换了端口重装），start 不会重启它，新端口永远不会监听，装完也打不开
  rc-service minishare restart || { tail -n 30 /var/log/minishare.log; exit 1; }
  echo "已设为开机自启并启动（OpenRC）"
else
  echo "没检测到 systemd / OpenRC，请手动后台运行："
  echo "  cd $APP_DIR && SHARE_HOST=$BIND SHARE_PORT=$PORT nohup $PYTHON fileshare.py >/dev/null 2>&1 &"
fi

# A service manager accepting start does not prove Python stayed running.
if ! "$PYTHON" "$APP_DIR/fileshare.py" --check "$BIND" "$PORT"; then
  echo "服务没有正常响应，安装未成功。错误日志："
  if [ "$INIT" = "systemd" ]; then
    journalctl -u minishare -n 30 --no-pager || true
  else
    tail -n 30 /var/log/minishare.log || true
  fi
  exit 1
fi

# ---- 5. 放行端口 ----
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "$PORT"/tcp >/dev/null
  echo "ufw 已放行 ${PORT}。"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
  firewall-cmd --permanent --add-port="$PORT"/tcp >/dev/null
  firewall-cmd --reload >/dev/null
  echo "firewalld 已放行 ${PORT}。"
else
  FW=iptables
  [ "$IPVER" = "6" ] && FW=ip6tables
  if command -v "$FW" >/dev/null 2>&1; then
    if "$FW" -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || "$FW" -I INPUT -p tcp --dport "$PORT" -j ACCEPT; then
      echo "$FW 已临时放行 TCP ${PORT}（重启后请确认规则持久化）。"
    else
      echo "警告：$FW 放行失败，请检查主机防火墙。"
    fi
  else
    echo "未自动修改主机防火墙，请确认 nftables/服务商安全组允许 TCP ${PORT}。"
  fi
fi

# ---- 6. 生成经过校验的地址；公网出口不等于 NAT 入站地址 ----
"$PYTHON" - "$IPVER" "$PORT" "${PUBLIC_HOST:-}" "${PUBLIC_PORT:-$PORT}" <<'PYADDR'
import ipaddress, json, socket, subprocess, sys
from urllib.parse import urlsplit
ver, port, public_host, public_port = sys.argv[1:]
if not public_port.isdigit() or not 1 <= int(public_port) <= 65535:
    sys.exit("PUBLIC_PORT 必须在 1–65535 之间。")
def valid(value):
    try:
        a = ipaddress.ip_address(value.strip())
        return str(a) if a.version == int(ver) and a.is_global else None
    except ValueError:
        return None
ips = []
try:
    data = subprocess.check_output(["ip", "-j", "addr"], timeout=3, stderr=subprocess.DEVNULL)
    for interface in json.loads(data):
        for item in interface.get("addr_info", []):
            addr = valid(item.get("local", ""))
            if addr and addr not in ips:
                ips.append(addr)
except (OSError, ValueError, subprocess.SubprocessError):
    pass
# Alpine may lack iproute2; UDP connect selects a local address without sending a packet.
try:
    family = socket.AF_INET6 if ver == "6" else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.connect(("2606:4700:4700::1111" if ver == "6" else "1.1.1.1", 80))
        addr = valid(sock.getsockname()[0])
        if addr and addr not in ips:
            ips.append(addr)
except OSError:
    pass
outbound = None
for endpoint in ("https://api64.ipify.org", "https://ifconfig.me/ip"):
    try:
        result = subprocess.check_output(["curl", "-" + ver, "-fsS", "--noproxy", "*",
                                          "--max-time", "5", endpoint],
                                         timeout=6, stderr=subprocess.DEVNULL).decode()
        outbound = valid(result)
        if outbound:
            break
    except (OSError, UnicodeError, subprocess.SubprocessError):
        pass
def url(host, number):
    return "http://%s:%s" % ("[" + host + "]" if ":" in host else host, number)
print("\n===================================")
print("安装完成，本机 HTTP 检查通过；外网连通性尚未验证。")
if public_host:
    host = public_host.strip("[]")
    parsed = urlsplit(url(host, public_port))
    if parsed.hostname != host or parsed.username or parsed.path or parsed.query or parsed.fragment:
        sys.exit("PUBLIC_HOST 必须是纯 IP 或域名，不含协议、端口或路径。")
    print("使用你指定的入站地址：" + url(host, public_port))
elif ips:
    for addr in ips:
        print("本机公网地址：" + url(addr, port))
else:
    print("未找到本机公网地址；请从服务商控制台确认入站 IP 和 TCP 映射端口。")
if outbound and outbound not in ips:
    print("检测到公网出口 IP：" + outbound + "（不能据此推断 NAT 入站地址/端口）。")
print("NAT 小鸡：网址用外部端口，安装时填映射到本机的内部端口。")
print("请确认主机防火墙及服务商安全组放行所选 TCP 端口。")
if ver == "6":
    print("IPv6 地址需要访问端也有 IPv6 网络；网址中的方括号不能去掉。")
print("尚未开启 HTTPS 时，请完整输入 http://，不要使用 https://。")
print("第一次打开会让你设置管理员密码。")
print("===================================")
PYADDR
