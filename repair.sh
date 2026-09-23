#!/bin/sh
# 保留数据修复已合并进 install.sh：它会自动识别已安装的 minishare 并进入
# 保留数据修复模式（只更新 Python 程序，保留监听地址、端口、密码和上传文件）。
# 此文件仅为兼容旧版"修复"一键命令而保留，行为与原来相同。
set -eu
[ "$(id -u)" = 0 ] || { echo "请用 root 运行。"; exit 1; }
ok=0
# raw.githubusercontent.com 有约 5 分钟 CDN 缓存：刚推上去的修复，
# 用户立刻重装会拿到旧脚本。时间戳参数绕过边缘缓存、回源拿最新。
TS="$(date +%s)"
for u in "https://raw.githubusercontent.com/imthnio/wenjianchuanshu/main/install.sh?t=$TS" "https://cdn.jsdelivr.net/gh/imthnio/wenjianchuanshu@main/install.sh"; do
  if command -v curl >/dev/null 2>&1; then
    curl -fSL --connect-timeout 15 --max-time 120 --retry 2 -o /tmp/minishare-install.sh "$u" 2>/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 120 -O /tmp/minishare-install.sh "$u" 2>/dev/null
  fi
  # 代理/缓存可能返回 200 的错误页面：确认是安装脚本才执行
  if [ -f /tmp/minishare-install.sh ] && head -c 11 /tmp/minishare-install.sh 2>/dev/null | grep -q "^#!/bin/sh"; then
    ok=1
    break
  fi
done
[ "$ok" = 1 ] || { echo "下载失败：连不上 GitHub 和镜像站，请检查服务器网络后重试。"; exit 1; }
exec sh /tmp/minishare-install.sh
