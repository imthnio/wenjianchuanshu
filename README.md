# minishare —— 极简网页文件传送

自己服务器上的"网页版 U 盘"：发文件给别人，或者收别人发来的文件。

## 一键安装 / 修复（SSH 粘贴就行）

   ```sh
   sh -c 'command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || { if command -v apk >/dev/null 2>&1; then apk add --no-cache curl ca-certificates; elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y curl ca-certificates; elif command -v dnf >/dev/null 2>&1; then dnf install -y curl ca-certificates; elif command -v yum >/dev/null 2>&1; then yum install -y curl ca-certificates; elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm curl ca-certificates; fi; }; ok=; for u in "https://raw.githubusercontent.com/imthnio/wenjianchuanshu/main/install.sh?cb=$(date +%s)" "https://cdn.jsdelivr.net/gh/imthnio/wenjianchuanshu@main/install.sh"; do if command -v curl >/dev/null 2>&1; then curl -fSL --connect-timeout 20 --max-time 180 --retry 2 -o /tmp/minishare-install.sh "$u" 2>/dev/null; else wget -q -T 180 -O /tmp/minishare-install.sh "$u" 2>/dev/null; fi; if [ -f /tmp/minishare-install.sh ] && head -c 11 /tmp/minishare-install.sh 2>/dev/null | grep -q "^#!/bin/sh"; then ok=1; break; fi; done; if [ -n "$ok" ]; then sh /tmp/minishare-install.sh; else echo "下载失败：连不上 GitHub 和镜像站，请检查服务器网络后重试。"; exit 1; fi'
   ```

## 开启 HTTPS（可选）

需要一个已经解析到这台 VPS 的域名（A 记录指过来，灰色云/仅 DNS）。SSH 用 root 登录后粘贴：

```sh
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then if command -v apk >/dev/null 2>&1; then apk add --no-cache curl; elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y curl; fi; fi; (curl -fSL --connect-timeout 20 --max-time 180 --retry 2 -o /tmp/minishare-https.sh https://raw.githubusercontent.com/imthnio/wenjianchuanshu/main/enable-https.sh || curl -fSL --connect-timeout 20 --max-time 180 --retry 2 -o /tmp/minishare-https.sh https://cdn.jsdelivr.net/gh/imthnio/wenjianchuanshu@main/enable-https.sh || wget -q -T 180 -O /tmp/minishare-https.sh https://raw.githubusercontent.com/imthnio/wenjianchuanshu/main/enable-https.sh || wget -q -T 180 -O /tmp/minishare-https.sh https://cdn.jsdelivr.net/gh/imthnio/wenjianchuanshu@main/enable-https.sh) && sh /tmp/minishare-https.sh
```

## 和「存视频」一起用

同一台 VPS 上还装了 [存视频（vps-ytdlp）](https://github.com/imthnio/vps-ytdlp) 时，存视频的任务上会多一个「上传到文件传输」按钮：选一个发送分享，下好的视频直接放进去，不用先下到电脑再传上来。不用做任何设置，两边自己认得对方。

（技术细节：minishare 1.7.0 起启动时在数据目录生成 `ext-key`，只有 root 能读。同机程序带着它调用 `GET /api/ext/shares` 和 `POST /api/ext/upload`。）
