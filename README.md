# minishare —— 极简网页文件传送

自己服务器上的"网页版 U 盘"：发文件给别人，或者收别人发来的文件。

## 小白安装（SSH 粘贴就行）

1. SSH 连上你的服务器（用 root 用户）。
2. 粘贴下面这段，回车：
   ```sh
   curl -fsSL -o /tmp/minishare-install.sh https://raw.githubusercontent.com/imthnio/minishare/main/install.sh && sh /tmp/minishare-install.sh
   ```
3. 按提示操作：只有 2 个问题，看不懂就一路回车用默认。
4. 装完会显示一个地址（比如 `http://1.2.3.4:8080`），浏览器打开它；第一次打开会让你设置管理员密码，设完就能用。

## 能做什么

- **发文件**：你在网页上传文件，生成一个链接发给对方，对方打开就能下载。
- **收文件**：你在网页生成一个"接收链接"发给对方，对方打开网页上传，文件存到你的服务器。

## 常见问题

- **装完浏览器打不开？** 云服务器要在安全组 / 防火墙里放行你设置的端口（默认 8080）。
- **想用域名 + https？** 在前面加一层反代（Nginx / Caddy）就行，本程序只管 http。
- **文件存在哪？** `/opt/minishare/data`，备份时把这个目录拷走就行。
- **怎么卸载？** `systemctl disable --now minishare`，再删掉 `/opt/minishare`。

## 进阶（给懂的人）

- 非交互安装：`NONINTERACTIVE=1 sh install.sh`；可用环境变量预设：`APP_DIR`（默认 /opt/minishare）、`PORT`（默认 8080）、`BIND`（默认 0.0.0.0）、`MINISHARE_REPO`（默认 imthnio/minishare）。
- 手动安装：`git clone https://github.com/imthnio/minishare.git && cd minishare && sudo sh install.sh`
- Alpine（OpenRC）会自动用 OpenRC 配置开机自启；既没有 systemd 也没有 OpenRC 的，脚本会给出 nohup 后台运行命令。
- 纯 Python 标准库，无第三方依赖。

## License

MIT
