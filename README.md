# minishare —— 极简网页文件传送

自己服务器上的"网页版 U 盘"：发文件给别人，或者收别人发来的文件。

## 一键安装 / 修复（SSH 粘贴就行）

1. SSH 连上你的服务器（用 root 用户）。
2. 粘贴下面这段，回车（缺下载工具会自动装，自动选能连上的镜像）：
   ```sh
   sh -c 'command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || { if command -v apk >/dev/null 2>&1; then apk add --no-cache curl ca-certificates; elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y curl ca-certificates; elif command -v dnf >/dev/null 2>&1; then dnf install -y curl ca-certificates; elif command -v yum >/dev/null 2>&1; then yum install -y curl ca-certificates; elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm curl ca-certificates; fi; }; ok=; for u in "https://raw.githubusercontent.com/imthnio/wenjianchuanshu/main/install.sh?cb=$(date +%s)" "https://cdn.jsdelivr.net/gh/imthnio/wenjianchuanshu@main/install.sh"; do if command -v curl >/dev/null 2>&1; then curl -fSL --connect-timeout 20 --max-time 180 --retry 2 -o /tmp/minishare-install.sh "$u" 2>/dev/null; else wget -q -T 180 -O /tmp/minishare-install.sh "$u" 2>/dev/null; fi; if [ -f /tmp/minishare-install.sh ] && head -c 11 /tmp/minishare-install.sh 2>/dev/null | grep -q "^#!/bin/sh"; then ok=1; break; fi; done; if [ -n "$ok" ]; then sh /tmp/minishare-install.sh; else echo "下载失败：连不上 GitHub 和镜像站，请检查服务器网络后重试。"; exit 1; fi'
   ```
3. 脚本会自动识别，不用你选：
   - **没装过**：进入安装向导，只有 3 个问题，其中第 2 问（端口）没有默认值，必须自己输入一个数字端口。
   - **已经装过**：自动进入保留数据修复——只更新 Python 程序，保留现有监听地址、端口、密码和上传文件；先备份原程序，重启后检查失败则自动恢复原程序。
4. 装完/修完会显示一个地址（比如 `http://1.2.3.4:18080`），浏览器打开它；第一次打开会让你设置管理员密码，设完就能用。

想换端口重装（跳过修复、强制全新安装）：在上面命令的最前面加上 `FORCE_INSTALL=1 `，例如 `FORCE_INSTALL=1 sh -c '…'`。

如果之前开启过 HTTPS，修复程序后请重新执行下方 HTTPS 脚本，以修正旧的代理配置。NAT 模式的 Caddy 对外端口保持原值，Python 改用独立的本地端口。

本机检查通过仅代表应用启动成功。外网仍打不开时，还需要核对：

- **NAT 小鸡**：服务商的「外部端口 → 内部端口」映射。安装时填内部端口，浏览器使用外部端口；出口 IP 不一定是入站 IP。
- **IPv6**：浏览器所在网络也需要 IPv6，地址格式为 `http://[IPv6地址]:端口`。
- **协议**：尚未配置 HTTPS 时输入完整的 `http://`。
- **防火墙**：主机和服务商安全组都要允许对应 TCP 端口；直接添加的 iptables/ip6tables 规则需另行持久化。

新安装只在本机 HTTP 和数据库检查通过后报告完成；失败时显示日志。非交互安装须设置 `PORT`，例如 `PORT=18080 IPVER=6 NONINTERACTIVE=1 sh install.sh`。NAT 入站信息可用 `PUBLIC_HOST` 和 `PUBLIC_PORT` 指定，仅用于显示访问地址，不会创建服务商端口映射。

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


## 修复与验证

- 修复 IPv6 地址仍用 IPv4 套接字、NAT HTTPS 前后端抢占同一端口、IPv6 代理上游和防火墙选择错误。
- 增加本机 HTTP/数据库检查和 OpenRC 日志；端口必须为 1–65535。
- 公网地址只接受经过校验的 IP，不再把探测站的错误页面或 NAT 出口地址当成可直接访问的网址。
- 安装与修复已合并为同一个一键命令：自动识别是否已安装，已安装则保留数据修复（先备份、检查失败自动恢复）；`FORCE_INSTALL=1` 可强制全新安装。
- 回归测试：`PYTHONDONTWRITEBYTECODE=1 python3 test_connectivity.py`。包含真实本机 IPv4/IPv6 请求、数据库失败、错误服务响应、安装失败检测，以及隔离目录中的 HTTPS 配置/回滚测试。
- 测试环境为 macOS Python 3.9。服务管理器在隔离测试中模拟；不等于已在真实 Alpine/OpenRC、Debian/systemd、公网 NAT 或证书签发环境验证。
