# minishare —— 极简网页文件传送

自己服务器上的"网页版 U 盘"：发文件给别人，或者收别人发来的文件。

## 小白安装（SSH 粘贴就行）

1. SSH 连上你的服务器（用 root 用户）。
2. 粘贴下面这段，回车：
   ```sh
   if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then if command -v apk >/dev/null 2>&1; then apk add --no-cache curl; elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y curl; fi; fi; (curl -fSL --connect-timeout 20 --max-time 180 --retry 2 -o /tmp/minishare-install.sh https://raw.githubusercontent.com/imthnio/wenjianchuanshu/main/install.sh || curl -fSL --connect-timeout 20 --max-time 180 --retry 2 -o /tmp/minishare-install.sh https://cdn.jsdelivr.net/gh/imthnio/wenjianchuanshu@main/install.sh || wget -q -T 180 -O /tmp/minishare-install.sh https://raw.githubusercontent.com/imthnio/wenjianchuanshu/main/install.sh || wget -q -T 180 -O /tmp/minishare-install.sh https://cdn.jsdelivr.net/gh/imthnio/wenjianchuanshu@main/install.sh) && sh /tmp/minishare-install.sh
   ```
3. 按提示操作：只有 3 个问题，看不懂就一路回车用默认。
4. 装完会显示一个地址（比如 `http://1.2.3.4:8080`），浏览器打开它；第一次打开会让你设置管理员密码，设完就能用。

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

