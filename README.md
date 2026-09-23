# minishare —— 极简网页文件传送

自己服务器上的"网页版 U 盘"：发文件给别人，或者收别人发来的文件。

## 一键安装 / 修复（SSH 粘贴就行）

1. SSH 连上你的服务器（用 root 用户）。
2. 粘贴下面这段，回车（缺下载工具会自动装，自动选能连上的镜像）：
   ```sh
   sh -c 'command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || { if command -v apk >/dev/null 2>&1; then apk add --no-cache curl ca-certificates; elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y curl ca-certificates; elif command -v dnf >/dev/null 2>&1; then dnf install -y curl ca-certificates; elif command -v yum >/dev/null 2>&1; then yum install -y curl ca-certificates; elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm curl ca-certificates; fi; }; ok=; for u in "https://raw.githubusercontent.com/imthnio/wenjianchuanshu/main/install.sh?cb=$(date +%s)" "https://cdn.jsdelivr.net/gh/imthnio/wenjianchuanshu@main/install.sh"; do if command -v curl >/dev/null 2>&1; then curl -fSL --connect-timeout 20 --max-time 180 --retry 2 -o /tmp/minishare-install.sh "$u" 2>/dev/null; else wget -q -T 180 -O /tmp/minishare-install.sh "$u" 2>/dev/null; fi; if [ -f /tmp/minishare-install.sh ] && head -c 11 /tmp/minishare-install.sh 2>/dev/null | grep -q "^#!/bin/sh"; then ok=1; break; fi; done; if [ -n "$ok" ]; then sh /tmp/minishare-install.sh; else echo "下载失败：连不上 GitHub 和镜像站，请检查服务器网络后重试。"; exit 1; fi'
   ```
3. 脚本会自动识别，不用你选命令：
   - **没装过**：进入安装向导，只有 3 个问题，其中第 2 问（端口）没有默认值，必须自己输入一个数字端口。
   - **已经装过**：会问你是选 1 还是选 2——直接回车（选 1）是保留数据修复：只更新 Python 程序，保留现有监听地址、端口、密码和上传文件，先备份原程序，重启后检查失败则自动恢复原程序；选 2 是重新安装，按向导重设目录、端口等（比如要换端口）。
4. 装完/修完会显示一个地址（比如 `http://1.2.3.4:18080`），浏览器打开它；第一次打开会让你设置管理员密码，设完就能用。

## 开启 HTTPS（可选）

需要一个已经解析到这台 VPS 的域名（A 记录指过来，灰色云/仅 DNS）。SSH 用 root 登录后粘贴：

```sh
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then if command -v apk >/dev/null 2>&1; then apk add --no-cache curl; elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y curl; fi; fi; (curl -fSL --connect-timeout 20 --max-time 180 --retry 2 -o /tmp/minishare-https.sh https://raw.githubusercontent.com/imthnio/wenjianchuanshu/main/enable-https.sh || curl -fSL --connect-timeout 20 --max-time 180 --retry 2 -o /tmp/minishare-https.sh https://cdn.jsdelivr.net/gh/imthnio/wenjianchuanshu@main/enable-https.sh || wget -q -T 180 -O /tmp/minishare-https.sh https://raw.githubusercontent.com/imthnio/wenjianchuanshu/main/enable-https.sh || wget -q -T 180 -O /tmp/minishare-https.sh https://cdn.jsdelivr.net/gh/imthnio/wenjianchuanshu@main/enable-https.sh) && sh /tmp/minishare-https.sh
```

按提示回答几个问题：域名、IPv4/IPv6、是不是 NAT 机器。

- **普通 VPS**：Caddy 监听 80/443，自动申请 Let's Encrypt 证书并自动续期，不用 Cloudflare。成功后用 `https://你的域名` 访问。
- **NAT 机器**（80/443 从外网连不进来）：跟随第一步，Caddy 直接复用安装 minishare 时的端口（比如安装时填了 19332，HTTPS 地址就是 `https://你的域名:19332`）。证书走 Cloudflare DNS 验证申请，需要一个 Cloudflare API 令牌（脚本里会一步步教你创建），证书也是自动续期。

## 能做什么

- **发文件**：你在网页上传文件，生成一个链接发给对方，对方打开就能下载。
- **收文件**：你在网页生成一个"接收链接"发给对方，对方打开网页上传，文件存到你的服务器。
- **管文件**：控制台"全部文件"里能看到发送和接收的所有文件，可勾选批量删除或单个删除，删除是彻底删除。
- **改备注/改过期**：每个分享卡片上都能直接改备注名和过期时间，不用删了重建。
