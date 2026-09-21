# minishare —— 极简网页文件传送

单文件、纯 Python 标准库、零第三方依赖。
任何有 Python 3 的 Linux 服务器都能跑：Debian / Ubuntu / Alpine / CentOS，
物理机、虚拟机、NAT 小鸡都行，不需要公网 IP，不需要域名备案。

## 功能

- **📤 发文件**：你在网页后台上传文件 → 得到分享链接 → 对方浏览器打开直接下载
- **📥 收文件**：你生成一个接收链接发给对方 → 对方打开网页上传 → 文件存到你的服务器
- 分享可设有效期（天数或永久），过期自动清理
- 管理员密码登录，可在控制台修改密码
- 大文件流式上传 / 下载，内存占用极低（384MB 小鸡实测无压力）
- 中文文件名正常显示和下载

## 快速开始

```bash
git clone https://github.com/imthnio/minishare.git
cd minishare
sudo sh install.sh
```

按提示选端口和监听地址，装完浏览器打开 `http://服务器IP:端口`，
首次打开设置管理员密码即可使用。

也可以一行命令远程安装（需先把仓库地址填进脚本或用环境变量）：

```bash
curl -fsSL https://raw.githubusercontent.com/imthnio/minishare/main/install.sh | sudo MINISHARE_REPO=imthnio/minishare sh
```

## 手动安装（任意发行版）

只需要 Python 3：

```bash
# 1. 把 fileshare.py 拷到服务器，如 /opt/minishare/
# 2. 运行
python3 fileshare.py
# 或后台运行并监听所有网卡：
SHARE_HOST=0.0.0.0 SHARE_PORT=8080 nohup python3 fileshare.py >/dev/null 2>&1 &
```

## 环境变量

| 变量               | 默认值      | 说明                    |
|--------------------|-------------|-------------------------|
| `SHARE_HOST`       | 127.0.0.1   | 监听地址                |
| `SHARE_PORT`       | 8080        | 监听端口                |
| `SHARE_DATA`       | ./data      | 数据目录（数据库+文件） |
| `SHARE_MAX_UPLOAD` | 10737418240 | 单次上传上限（字节），默认 10GB |

## 开机自启

`install.sh` 会自动处理：检测到 systemd 就装 service，
检测到 OpenRC（Alpine）就装 init 脚本并 `rc-update`。
都没有的话，脚本会给出 `nohup` 手动后台运行命令。

## 反代加 HTTPS（可选）

本程序可直接裸跑。若需要域名 + HTTPS，在前面加一层反代即可，
Caddy / Nginx 都行，反代到 `127.0.0.1:8080`：

```caddy
example.com {
    reverse_proxy 127.0.0.1:8080
}
```

## 安全建议

- 直接暴露公网时，务必设置高强度管理员密码，并用防火墙限制端口访问
- 分享 / 接收链接是随机 ID，猜不到；管理后台需密码登录
- 公网长期使用建议套一层 HTTPS 反代

## 备份与迁移

数据都在 `SHARE_DATA` 目录：`share.db`（SQLite）+ `files/`。
备份拷走整个目录即可，迁移时原样放回去。

## 卸载

```bash
# systemd
sudo systemctl disable --now minishare
sudo rm /etc/systemd/system/minishare.service
# OpenRC
sudo rc-service minishare stop
sudo rc-update del minishare default
sudo rm /etc/init.d/minishare
# 程序本体
sudo rm -rf /opt/minishare
```

## License

MIT
