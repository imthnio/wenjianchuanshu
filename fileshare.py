#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
minishare —— 极简文件分享 / 接收服务

* 单文件，纯 Python 标准库，零第三方依赖
* Debian / Ubuntu / Alpine 等任何有 Python3 的系统都能直接跑
* 两个核心功能：
*   1. 发送：管理员上传文件 -> 得到分享链接 -> 对方浏览器打开直接下载
*   2. 接收：管理员创建一个接收链接 -> 对方打开链接上传 -> 文件落到服务器

启动：  python3 fileshare.py
环境变量：
  SHARE_HOST        监听地址，默认 127.0.0.1
  SHARE_PORT        监听端口，默认 8080
  SHARE_DATA        数据目录，默认 ./data
  SHARE_MAX_UPLOAD  单次上传上限(字节)，默认 10GB
  SHARE_MSS         TCP MSS 上限，默认 1220（防 PMTU 黑洞）；设 0 不限制
"""
import os
import sys
import errno
import re
import json
import time
import hmac
import html
import ipaddress
import socket
import mimetypes
import hashlib
import secrets
import sqlite3
import threading
import tempfile
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote, unquote

# ---------------- 配置 ----------------
VERSION = "1.2.1"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("SHARE_DATA", os.path.join(BASE_DIR, "data"))
FILES_DIR = os.path.join(DATA_DIR, "files")
DB_PATH = os.path.join(DATA_DIR, "share.db")
HOST = os.environ.get("SHARE_HOST", "127.0.0.1")
PORT = int(os.environ.get("SHARE_PORT", "8080"))
MAX_UPLOAD = int(os.environ.get("SHARE_MAX_UPLOAD", str(10 * 1024 ** 3)))
SESSION_DAYS = 30
CHUNK = 65536
# TCP MSS 上限：某些链路存在 PMTU 黑洞——服务端发出的大包被中间
# 环节静默丢弃，ICMP 分片通知又回不来，连接就会一直卡住（能握手、
# 小包能过，只有大回复回不来）。把 MSS 钳小后服务端只发小包，
# 这类链路也能正常工作；正常链路几乎无影响。设为 0 则不限制。
MSS = int(os.environ.get("SHARE_MSS", "1220"))

# Cloudflare 公布的网段（2026-09-24）。只用来判断连上来的是不是 Cloudflare。
# 是的话，登录限流按访客自己的 IP 算，避免所有人挤在同一个 Cloudflare 地址上。
# 直接访问本机端口的人不在这些网段里，伪造的转发头会被忽略。
_CF_CIDRS = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)
_CF_NETS = None
_DNS_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$",
    re.I)
_NOISE_TLDS = {
    "py", "sh", "service", "conf", "yml", "yaml", "log", "txt",
    "sock", "pid", "local", "internal", "invalid", "localhost",
}

def cloudflare_networks():
    global _CF_NETS
    if _CF_NETS is None:
        nets = []
        for item in _CF_CIDRS:
            try:
                nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                continue
        _CF_NETS = tuple(nets)
    return _CF_NETS

def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def trusted_proxy(peer):
    """本机反代或 Cloudflare 的接入地址。其他来源带来的转发头不可信。"""
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    if addr.is_loopback:
        return True
    return any(addr in net for net in cloudflare_networks())

def client_rate_key(peer, cf_connecting_ip):
    """登录限流用的 IP。直连用对端地址；只有可信反代才采用 CF-Connecting-IP。"""
    if trusted_proxy(peer):
        raw = (cf_connecting_ip or "").split(",")[0].strip()
        if _is_ip(raw):
            return raw
    return peer

def _is_dns_name(host):
    host = (host or "").strip().lower().rstrip(".")
    if not _DNS_NAME.match(host):
        return False
    return host.rsplit(".", 1)[-1] not in _NOISE_TLDS

def normalize_public_base(value):
    """只接受 https://域名 或 https://域名:端口。域名来自现有配置或这次访问，不写死。"""
    raw = (value or "").strip().strip('"').strip("'")
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urlparse(raw)
    except ValueError:
        return ""
    if parts.scheme != "https" or parts.username or parts.password:
        return ""
    if parts.query or parts.fragment or parts.path not in ("", "/"):
        return ""
    host = (parts.hostname or "").lower().rstrip(".")
    if not _is_dns_name(host):
        return ""
    try:
        port = parts.port
    except ValueError:
        return ""
    if port in (None, 443):
        return "https://" + host
    if not 1 <= port <= 65535:
        return ""
    return "https://%s:%d" % (host, port)

def public_link(path, base):
    if not path.startswith("/"):
        path = "/" + path
    base = normalize_public_base(base)
    if not base:
        return path
    return base + path

def _read_caddyfile():
    # enable-https.sh 会把用户填的域名写进这份文件。没有就不猜。
    path = os.environ.get("MINISHARE_CADDYFILE", "/etc/caddy/Caddyfile")
    try:
        if not path or not os.path.isfile(path) or os.path.getsize(path) > 200_000:
            return ""
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(200_000)
    except OSError:
        return ""

def _caddy_sites(text):
    sites = []
    current = None
    depth = 0
    buf = []
    for line in text.splitlines():
        stripped = line.strip()
        if current is None:
            if not stripped or stripped.startswith("#"):
                continue
            match = re.match(r"^(\S+)\s*\{(.*)$", stripped)
            if not match:
                continue
            current = match.group(1)
            rest = match.group(2)
            buf = [rest]
            depth = 1 + rest.count("{") - rest.count("}")
            if depth <= 0:
                sites.append((current, "\n".join(buf)))
                current = None
                depth = 0
            continue
        buf.append(stripped)
        depth += stripped.count("{") - stripped.count("}")
        if depth <= 0:
            sites.append((current, "\n".join(buf)))
            current = None
            depth = 0
    return sites

def caddy_public_base(listen_port):
    """沿用 enable-https.sh 已经写好的域名。没有这份配置就返回空。"""
    text = _read_caddyfile()
    if not text:
        return ""
    sites = _caddy_sites(text)
    if not sites:
        return ""
    port = str(listen_port or "").strip()
    matched = []
    for addr, body in sites:
        if port and re.search(r"(?<!\d)" + re.escape(port) + r"(?!\d)", body):
            matched.append(addr)
    if not matched and len(sites) == 1:
        matched = [sites[0][0]]
    if len(matched) != 1:
        return ""
    return normalize_public_base(matched[0])

def resolve_link_base(peer, host, headers, listen_port):
    """分享链接的 https 根地址。

    原来的自动识别保留着：这次访问如果已经是 https，就用地址栏里的域名。
    访问本身看不出域名时，再沿用 Caddyfile 里已经配好的域名。
    两边都没有就返回空，页面继续用 location.origin。
    """
    forced = normalize_public_base(os.environ.get("SHARE_PUBLIC_BASE", ""))
    if forced:
        return forced
    headers = headers or {}
    if trusted_proxy(peer):
        visitor = headers.get("CF-Visitor") or ""
        proto = (headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        https = bool(re.search(r'"scheme"\s*:\s*"https"', visitor, re.I)) or proto == "https"
        if https:
            found = normalize_public_base("https://" + (host or "").strip())
            if found:
                return found
    return caddy_public_base(listen_port)

# ---------------- 数据库 ----------------
def db():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c

def setup_token_path():
    return os.path.join(DATA_DIR, "setup-token")

def init_db():
    os.makedirs(FILES_DIR, exist_ok=True)
    with db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
        c.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pw TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0,
            created INTEGER NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS sessions(
            token TEXT PRIMARY KEY, user_id INTEGER,
            created INTEGER, expires INTEGER)""")
        c.execute("""CREATE TABLE IF NOT EXISTS shares(
            id TEXT PRIMARY KEY, type TEXT, title TEXT,
            created INTEGER, expires INTEGER, owner_id INTEGER)""")
        c.execute("""CREATE TABLE IF NOT EXISTS files(
            id INTEGER PRIMARY KEY AUTOINCREMENT, share_id TEXT,
            filename TEXT, stored TEXT, size INTEGER, created INTEGER,
            owner_id INTEGER)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_files_share ON files(share_id)")
        # 兼容老版本数据库：补上新增的列
        for table, col, typ in (("sessions", "user_id", "INTEGER"),
                                ("shares", "owner_id", "INTEGER"),
                                ("users", "remark", "TEXT"),
                                ("users", "pw_plain", "TEXT"),
                                ("files", "owner_id", "INTEGER"),
                                ("files", "pinned", "INTEGER NOT NULL DEFAULT 0"),
                                ("files", "sort_order", "INTEGER")):
            cols = [r["name"] for r in c.execute(f"PRAGMA table_info({table})")]
            if col not in cols:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
        _migrate_to_multiuser(c)
        # Keep file ownership after a share is deleted. Old orphan files have no
        # reliable owner and remain accessible to administrators only.
        c.execute("""UPDATE files SET owner_id=(
            SELECT owner_id FROM shares WHERE shares.id=files.share_id)
            WHERE owner_id IS NULL AND EXISTS (
                SELECT 1 FROM shares WHERE shares.id=files.share_id)""")
    if has_users():
        try:
            os.unlink(setup_token_path())
        except FileNotFoundError:
            pass
    else:
        _ensure_setup_token()

def _ensure_setup_token():
    # Public installs listen on 0.0.0.0 before the owner opens /setup. Only
    # someone with access to the server should be able to claim the first admin.
    if os.path.exists(setup_token_path()):
        return
    token = secrets.token_hex(32)
    fd, tmp = tempfile.mkstemp(prefix=".setup-", dir=DATA_DIR)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as out:
            out.write(token + "\n")
            out.flush()
            os.fsync(out.fileno())
        try:
            os.link(tmp, setup_token_path())
        except FileExistsError:
            pass  # Another startup already created the token.
    finally:
        os.unlink(tmp)

def create_initial_admin(pw, setup_code):
    if len(pw) < 4:
        raise ValueError("密码至少 4 位")
    try:
        with open(setup_token_path(), encoding="ascii") as f:
            expected = f.read().strip()
    except FileNotFoundError:
        raise ValueError("初始化码不可用，请检查服务器 data/setup-token 文件")
    if len(setup_code) != 64 or not hmac.compare_digest(setup_code, expected):
        raise ValueError("初始化码错误")
    with db() as c:
        # The outer /setup check is only for routing. Serialize the actual
        # first-admin creation so two simultaneous requests cannot both win.
        c.execute("BEGIN IMMEDIATE")
        if c.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            return None
        now = int(time.time())
        cur = c.execute("INSERT INTO users(pw,pw_plain,is_admin,created) VALUES(?,?,?,?)",
                        (hash_pw(pw), pw, 1, now))
        admin = {"id": cur.lastrowid, "is_admin": True}
    try:
        os.unlink(setup_token_path())
    except FileNotFoundError:
        pass
    return admin

def _migrate_to_multiuser(c):
    # 老版本只有 meta.pw 一个密码：转成 users 表的第一条管理员记录，
    # 老分享全部归到管理员名下；旧会话没有 user_id，一律作废重登。
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
        return
    old = c.execute("SELECT v FROM meta WHERE k='pw'").fetchone()
    if not old:
        return  # 全新安装：/setup 会创建管理员账号
    now = int(time.time())
    c.execute("INSERT INTO users(pw,is_admin,created) VALUES(?,?,?)",
              (old["v"], 1, now))
    admin_id = c.execute("SELECT id FROM users WHERE is_admin=1").fetchone()["id"]
    c.execute("UPDATE shares SET owner_id=? WHERE owner_id IS NULL", (admin_id,))
    c.execute("DELETE FROM sessions")
    c.execute("DELETE FROM meta WHERE k='pw'")

def meta_get(k):
    with db() as c:
        r = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r["v"] if r else None

def meta_set(k, v):
    with db() as c:
        c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (k, v))

# ---------------- 密码与会话 ----------------
def hash_pw(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 200_000)
    return salt.hex() + "$" + h.hex()

def check_pw(pw, stored):
    try:
        salt_hex, _ = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        # 数据库里的哈希损坏（没有 $ 分隔、或 salt 不是合法 hex）：
        # 之前 bytes.fromhex 在 try 外面，直接抛 ValueError，
        # /login 会 500；损坏的哈希只能判为密码不对。
        return False
    return hmac.compare_digest(hash_pw(pw, salt), stored)

# ---------------- 多用户：密码即账号 ----------------
# 没有用户名，登录只输密码：不同的密码对应不同的账号。
# 账号只能由管理员添加，没有注册入口。

def has_users():
    with db() as c:
        return c.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0

def list_users():
    with db() as c:
        return c.execute(
            "SELECT id, is_admin, created, remark FROM users ORDER BY id").fetchall()

def create_user(pw, is_admin=False, remark=""):
    # 密码即账号身份：密码不能与现有任何账号重复，否则登录时无法区分。
    # remark 是管理员给账号的备注名（比如给了谁），仅展示用。
    # pw_plain 存明文：管理员要点"眼睛"查看用户密码（用户改密码时同步更新）。
    if len(pw) < 4:
        raise ValueError("密码至少 4 位")
    remark = (remark or "").strip()[:50]
    with db() as c:
        for r in c.execute("SELECT pw FROM users"):
            if check_pw(pw, r["pw"]):
                raise ValueError("这个密码已经被别的账号用了，换一个")
        now = int(time.time())
        cur = c.execute("INSERT INTO users(pw,pw_plain,is_admin,created,remark) VALUES(?,?,?,?,?)",
                        (hash_pw(pw), pw, 1 if is_admin else 0, now, remark))
        return {"id": cur.lastrowid, "is_admin": bool(is_admin)}

def get_user_pw(uid):
    # 取账号的明文密码（仅管理员调用；老版本迁移来的账号明文未知时返回 None）。
    with db() as c:
        r = c.execute("SELECT pw_plain FROM users WHERE id=?", (uid,)).fetchone()
        return r["pw_plain"] if r else None

def set_user_remark(uid, remark):
    # 管理员给账号改备注名：只展示用，不影响登录（登录只认密码）。
    with db() as c:
        c.execute("UPDATE users SET remark=? WHERE id=?",
                  ((remark or "").strip()[:50], uid))

def find_user_by_pw(pw):
    with db() as c:
        for r in c.execute("SELECT id, pw, is_admin FROM users"):
            if check_pw(pw, r["pw"]):
                return {"id": r["id"], "is_admin": bool(r["is_admin"])}
    return None

def get_user(uid):
    with db() as c:
        r = c.execute("SELECT id, is_admin FROM users WHERE id=?", (uid,)).fetchone()
        return {"id": r["id"], "is_admin": bool(r["is_admin"])} if r else None

def set_user_pw(uid, pw):
    if len(pw) < 4:
        raise ValueError("密码至少 4 位")
    with db() as c:
        for r in c.execute("SELECT id, pw FROM users WHERE id!=?", (uid,)):
            if check_pw(pw, r["pw"]):
                raise ValueError("这个密码已经被别的账号用了，换一个")
        # 同步更新明文：管理员点"眼睛"看到的永远是当前密码
        c.execute("UPDATE users SET pw=?, pw_plain=? WHERE id=?",
                  (hash_pw(pw), pw, uid))

def delete_user(uid):
    # 删账号：踢掉他的所有会话；他的分享链接失效（文件按现有规则保留，
    # 在"全部文件"里显示为"链接已删"，管理员可手动清理）。
    with db() as c:
        for r in c.execute("SELECT id FROM shares WHERE owner_id=?", (uid,)).fetchall():
            c.execute("DELETE FROM shares WHERE id=?", (r["id"],))
        c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        c.execute("DELETE FROM users WHERE id=?", (uid,))

def can_manage_share(user, share):
    # 管理员可操作任何分享；普通用户只能操作自己的
    return user["is_admin"] or share["owner_id"] == user["id"]

def new_session(user_id):
    tok = secrets.token_urlsafe(32)
    now = int(time.time())
    with db() as c:
        c.execute("INSERT INTO sessions(token,user_id,created,expires)"
                  " VALUES(?,?,?,?)",
                  (tok, user_id, now, now + SESSION_DAYS * 86400))
    return tok

def session_user(tok):
    # 会话对应的账号，不存在/过期返回 None
    if not tok:
        return None
    with db() as c:
        r = c.execute(
            "SELECT u.id, u.is_admin FROM sessions s"
            " JOIN users u ON s.user_id=u.id"
            " WHERE s.token=? AND s.expires>?", (tok, time.time())).fetchone()
    return {"id": r["id"], "is_admin": bool(r["is_admin"])} if r else None

def drop_session(tok):
    with db() as c:
        c.execute("DELETE FROM sessions WHERE token=?", (tok,))

def new_share_id():
    with db() as c:
        for _ in range(20):
            sid = secrets.token_urlsafe(6)[:8]
            if not c.execute("SELECT 1 FROM shares WHERE id=?", (sid,)).fetchone():
                return sid
    raise RuntimeError("cannot generate share id")

# ---------------- 分享记录 ----------------
def get_share(sid):
    with db() as c:
        return c.execute("SELECT * FROM shares WHERE id=?", (sid,)).fetchone()

def share_files(sid):
    with db() as c:
        return c.execute("SELECT * FROM files WHERE share_id=? ORDER BY "
                         "pinned DESC, sort_order IS NULL, sort_order, id", (sid,)).fetchall()

def arrange_share_file(sid, fid, action, user):
    if action not in ("up", "down", "pin", "unpin"):
        raise ValueError("排序操作无效")
    with db() as c:
        # Serialize read/modify/write, including permission and expiry checks.
        c.execute("BEGIN IMMEDIATE")
        share = c.execute("SELECT * FROM shares WHERE id=?", (sid,)).fetchone()
        if not share or share["type"] != "send" or is_expired(share):
            raise LookupError("分享不存在或已过期")
        if not can_manage_share(user, share):
            raise PermissionError("只能修改自己的分享")
        rows = c.execute("SELECT * FROM files WHERE share_id=? ORDER BY "
                         "pinned DESC, sort_order IS NULL, sort_order, id", (sid,)).fetchall()
        target = next((r for r in rows if r["id"] == fid), None)
        if target is None:
            raise LookupError("文件不存在")
        pinned = target["pinned"]
        group = [r["id"] for r in rows if r["pinned"] == pinned]
        if action in ("pin", "unpin"):
            desired = int(action == "pin")
            if desired == pinned:
                return
            pinned = desired
            group = [r["id"] for r in rows if r["pinned"] == pinned] + [fid]
            c.execute("UPDATE files SET pinned=? WHERE id=? AND share_id=?",
                      (pinned, fid, sid))
        else:
            pos = group.index(fid)
            other = pos + (-1 if action == "up" else 1)
            if not 0 <= other < len(group):
                return
            group[pos], group[other] = group[other], group[pos]
        c.executemany("UPDATE files SET sort_order=? WHERE id=? AND share_id=?",
                      [(pos, file_id, sid) for pos, file_id in enumerate(group)])

def is_expired(share):
    return share["expires"] and share["expires"] < time.time()

def delete_share(sid):
    # 只删除分享链接：文件保留在"全部文件"里，由用户手动删除。
    # 过期自动清理也走这里：链接失效，文件同样保留。
    with db() as c:
        c.execute("DELETE FROM shares WHERE id=?", (sid,))

def all_files(user):
    # 已过期的分享（每小时会被清理线程删掉）在删掉之前也不显示，
    # 否则控制台"全部文件"里会躺着打不开链接的幽灵文件。
    now = int(time.time())
    with db() as c:
        where = "" if user["is_admin"] else " AND f.owner_id=?"
        args = (now,) if user["is_admin"] else (now, user["id"])
        return c.execute(
            "SELECT f.id,f.share_id,f.filename,f.size,f.created,s.type,s.title,f.owner_id"
            " FROM files f LEFT JOIN shares s ON f.share_id=s.id"
            " WHERE (s.id IS NULL OR s.expires=0 OR s.expires>?)" + where +
            " ORDER BY f.id DESC", args).fetchall()

def delete_files(ids):
    removed = 0
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        for fid in ids:
            r = c.execute("SELECT stored FROM files WHERE id=?", (fid,)).fetchone()
            if r:
                try:
                    os.unlink(os.path.join(FILES_DIR, r["stored"]))
                except OSError:
                    pass
                c.execute("DELETE FROM files WHERE id=?", (fid,))
                removed += 1
    return removed

def add_existing_files(sid, ids, user):
    """把可见的已有文件加入发送分享，原文件及原分享保持独立。"""
    if not ids or len(ids) > 200 or len(set(ids)) != len(ids):
        raise ValueError("请选择 1 至 200 个不同的文件")
    created = []
    try:
        with db() as c:
            # 和删除文件、修改分享串行，避免验证之后原文件就被删掉。
            c.execute("BEGIN IMMEDIATE")
            share = c.execute("SELECT * FROM shares WHERE id=?", (sid,)).fetchone()
            if (not share or share["type"] != "send" or
                    (share["expires"] and share["expires"] <= time.time())):
                raise ValueError("发送分享不存在或已过期")
            if not can_manage_share(user, share):
                raise PermissionError("只能操作自己的分享")
            for fid in ids:
                row = c.execute("SELECT f.*, s.expires FROM files f"
                                " LEFT JOIN shares s ON s.id=f.share_id"
                                " WHERE f.id=?", (fid,)).fetchone()
                if (not row or (not user["is_admin"] and
                                row["owner_id"] != user["id"]) or
                        (row["expires"] and row["expires"] <= time.time())):
                    raise ValueError("所选文件不存在或不可访问")
                if row["share_id"] == sid:
                    raise ValueError("所选文件已在这个分享里")
                source = os.path.join(FILES_DIR, row["stored"])
                stored = secrets.token_hex(24)
                dest = os.path.join(FILES_DIR, stored)
                # 同目录硬链接不重复占用文件数据；两条目录项可分别删除。
                os.link(source, dest)
                created.append(dest)
                c.execute("INSERT INTO files(share_id,filename,stored,size,created,owner_id)"
                          " VALUES(?,?,?,?,?,?)",
                          (sid, row["filename"], stored, row["size"],
                           int(time.time()), share["owner_id"]))
    except Exception:
        # 数据库回滚后移除刚建的硬链接，不留下磁盘孤儿。
        for path in created:
            try:
                os.unlink(path)
            except OSError:
                pass
        raise
    return len(created)

def cleanup_expired():
    now = int(time.time())
    with db() as c:
        rows = c.execute("SELECT id FROM shares WHERE expires>0 AND expires<?", (now,)).fetchall()
    for r in rows:
        delete_share(r["id"])
    with db() as c:
        c.execute("DELETE FROM sessions WHERE expires<?", (now,))

def cleanup_loop():
    while True:
        time.sleep(3600)
        try:
            cleanup_expired()
        except Exception:
            pass


# ---------------- 流式 multipart 解析 ----------------
class UploadTooLarge(Exception):
    pass

class BadUpload(Exception):
    pass

# multipart 解析的前置快速拒绝只拦"明显超大"的请求体：信封本身
# （boundary/头，几百字节）不计入文件大小，精确的账在流式写文件时
# 按实际文件字节数扣（见 parse_multipart 里的 charge）。这样"页面上
# 显示的最大可上传"与"实际能传"严格一致：正好卡着上限的文件不会
# 因为信封多出几百字节就被 413。
_PRECHECK_SLACK = 1024 * 1024

# 单次上传请求里最多带多少个文件 part：每个文件 part 都会在磁盘上
# 建一个临时文件再写 DB，不设上限的话，攻击者可以用 10GB 的请求体塞
# 下几千万个空文件 part（每个只占一百多字节），把磁盘 inode 和
# SQLite 拖死。正常人一次传 200 个文件绰绰有余。
MAX_FILES_PER_REQUEST = 200

# 单次上传请求里最多带多少个纯字段 part：字段 part 不走文件额度的
# charge（只有文件字节才扣 budget），也不落盘，直接进内存 dict。
# 不限数量的话，攻击者可以用 10GB 请求体塞几千万个碎字段 part
#（每个几十字节），fields dict 的内存直接爆炸——文件 part 有
# MAX_FILES_PER_REQUEST 兜底，这里之前漏了。正常表单字段从不超过两位数。
MAX_FIELDS_PER_REQUEST = 100

# 接收链接无需登录。只限制字段数量和单个字段 1MB 时，一个请求仍可
# 累积约 100MB 的 fields dict，足以让低内存 VPS 的进程被 OOM 杀掉。
# 实际表单字段只是 title/expiry 等短文本，限制单项和累计大小。
MAX_FIELD_BYTES = 64 * 1024
MAX_FIELDS_TOTAL_BYTES = 256 * 1024
MAX_PART_NAME_BYTES = 256

# ---------------- 分片上传 ----------------
# 大文件一次 POST 传完，经过 Cloudflare 这类反代时很容易因为
# “单个请求耗时太长”被中间环节掐掉（用户看到的就是 请求失败(522)）。
# 切成小片逐个传：每个请求都很快完成，既避开超时，又能显示真实的
# 上传百分比；某片失败也只重传该片，不用整个文件重来。
CHUNK_SIZE = 4 * 1024 * 1024  # 每片 4MB
CHUNK_TTL = 2 * 3600  # 分片会话 2 小时没传完就清理临时文件

# 服务端同时存在的分片上传会话上限：每个会话占一个内存条目 + 磁盘上一个
# 临时文件。kind=upload 走接收链接，免登录、链接是公开分享的，不限数量
# 会被拿来刷爆内存和 inode（会话 2 小时才过期，刷的速度远快于过期速度）。
# 正常人同时传几十个文件顶天了，1000 是留足余量的上限。
MAX_CHUNK_SESSIONS = 1000

# 分片上传的前端通用函数：分享页“添加文件”、接收页“上传”、控制台
# “发送文件”三个上传入口共用。大文件切成 4MB 一片逐个 POST，每片请求
# 都很快完成，经过 Cloudflare 这类反代不会因“单个请求耗时太长”被掐
# （之前整文件一次 POST 大文件容易 请求失败(522)）；同时能显示真实的
# 上传百分比和“正在上传第几个/上传完成”，某片失败只重传该片。
CHUNK_JS = """
function escapeHtml(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
var CHUNK_SIZE=4*1024*1024;
// params: {sid, kind:'add'|'upload'}；ui: {prog, pct, stat}
// 成功 resolve()，失败 reject(Error)，错误信息可直接展示给用户。
function chunkUpload(params, files, ui){
  return new Promise(function(resolve, reject){
    var total=0, i;
    for(i=0;i<files.length;i++) total+=files[i].size;
    var sent=0;
    function paint(){
      var p=total>0?Math.floor(sent/total*100):100;
      ui.prog.value=p;
      if(ui.pct) ui.pct.textContent=p+'%';
    }
    function jpost(url, body){
      return fetch(url,{method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:body}).then(function(r){
          return r.json().catch(function(){return null;}).then(function(j){
            return {status:r.status, json:j};
          });
        });
    }
    function upFile(fi){
      if(fi>=files.length){ paint(); resolve(); return; }
      var f=files[fi], nchunks=Math.max(1, Math.ceil(f.size/CHUNK_SIZE));
      if(ui.stat) ui.stat.innerHTML='正在上传 <b>'+escapeHtml(f.name)+'</b>（'+(fi+1)+'/'+files.length+'）…';
      jpost('/api/chunk_init',
        'sid='+encodeURIComponent(params.sid)+'&kind='+params.kind+
        '&name='+encodeURIComponent(f.name)+'&size='+f.size+'&chunks='+nchunks
      ).then(function(r){
        if(!r.json||!r.json.ok) throw new Error((r.json&&r.json.error)||('请求失败('+r.status+')'));
        var up=r.json.up;
        function upChunk(c){
          if(c>=nchunks){
            jpost('/api/chunk_done','up='+encodeURIComponent(up)).then(function(r2){
              if(!r2.json||!r2.json.ok) throw new Error((r2.json&&r2.json.error)||('请求失败('+r2.status+')'));
              upFile(fi+1);
            }).catch(reject);
            return;
          }
          var blob=f.slice(c*CHUNK_SIZE,(c+1)*CHUNK_SIZE), tries=0;
          function retryOrFail(err){
            if(tries<3){ send(); }
            else{ reject(new Error(err.message+'（第'+(c+1)+'片，已重试3次仍失败）')); }
          }
          function send(){
            tries++;
            fetch('/api/chunk?up='+encodeURIComponent(up)+'&i='+c,{method:'POST',body:blob})
            .then(function(r3){
              return r3.json().catch(function(){return null;}).then(function(j3){
                if(j3&&j3.ok){ sent+=blob.size; paint(); upChunk(c+1); }
                else{ retryOrFail(new Error((j3&&j3.error)||('请求失败('+r3.status+')'))); }
              });
            }).catch(function(){ retryOrFail(new Error('网络错误')); });
          }
          send();
        }
        upChunk(0);
      }).catch(reject);
    }
    paint();
    upFile(0);
  });
}
"""

# urlencoded 表单最多解析多少个字段：1MB 的 body 全是 a0=1&a1=1… 这种
# 碎字段时，parse_qs 会造出十几万个 dict 条目（几十 MB 临时内存）。
# 我们的表单字段从不超过两位数，2000 是留足余量的上限。
# max_num_fields 参数是 Python 3.10.7+ 才有的，老版本没有就退回不限。
_MAX_FORM_FIELDS = 2000

def _fix_header_encoding(v):
    """HTTP 头是按 latin1 解码的；如果里面实际是 UTF-8 字节（如中文文件名），还原它。"""
    try:
        return v.encode("latin1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return v

def _split_params(disp):
    """按分号切 Content-Disposition 的参数，但双引号里的分号不算分隔符。
    直接 disp.split(";") 会把 filename="a;b.txt" 从中间切断，文件名被截成 "\"a"。"""
    parts, cur, quoted = [], [], False
    for ch in disp:
        if ch == '"':
            quoted = not quoted
            cur.append(ch)
        elif ch == ";" and not quoted:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts

def _disp_param(disp, key):
    """从 Content-Disposition 头取参数，支持 filename*=UTF-8''... 形式"""
    kl = key.lower()
    for part in _split_params(disp):
        p = part.strip()
        pl = p.lower()
        if pl.startswith(kl + "*="):
            v = p.split("=", 1)[1].strip()
            if "''" in v:
                enc, _, val = v.partition("''")
                try:
                    return unquote(val, encoding=enc or "utf-8", errors="replace")
                except (LookupError, ValueError):
                    # 编码名是客户端随便填的（如 filename*=GARBAGE''...）：
                    # unquote 对未知编码抛 LookupError。回退到 utf-8 解码，
                    # 畸形输入按普通文件名处理，不应 500。
                    return unquote(val, encoding="utf-8", errors="replace")
            return v.strip('"')
        if pl.startswith(kl + "="):
            v = p.split("=", 1)[1].strip()
            if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                v = v[1:-1]
            return _fix_header_encoding(v)
    return None

def _clean_filename(fn):
    # 去掉控制字符：恶意文件名里的 CR/LF 会污染下载响应头（响应拆分攻击）
    fn = re.sub(r"[\x00-\x1f\x7f]", "", fn)
    fn = os.path.basename(fn.replace("\\", "/")).strip() or "unnamed"
    return fn[:200]

def parse_multipart(rfile, content_length, boundary, max_bytes):
    """流式解析 multipart/form-data。
    文件 part 直接写入 FILES_DIR 下的随机文件名，不进内存。
    返回 (fields: dict, files: list[dict{name,filename,stored,size}])。
    出错时已落盘的临时文件会被清理。
    """
    try:
        total = int(content_length)
    except (TypeError, ValueError):
        raise BadUpload("bad content length")
    if total > max_bytes + _PRECHECK_SLACK:
        # 明显超大的直接拒掉，不必读完整个请求体
        raise UploadTooLarge()
    bnd = b"--" + boundary
    delim = b"\r\n" + bnd
    buf = bytearray()
    remaining = total
    fields, files = {}, []
    n_files = 0
    n_fields = 0
    fields_bytes = 0
    created_paths = []
    budget = max_bytes  # 实际文件字节的剩余额度（信封开销不计入）
    def charge(n):
        nonlocal budget
        budget -= n
        if budget < 0:
            raise UploadTooLarge()

    def fill(need=1):
        nonlocal remaining
        while remaining > 0 and len(buf) < need:
            data = rfile.read(min(CHUNK, remaining))
            if not data:
                break
            remaining -= len(data)
            buf.extend(data)
        return len(buf) >= need

    def drain():
        nonlocal remaining
        while remaining > 0:
            data = rfile.read(min(CHUNK, remaining))
            if not data:
                break
            remaining -= len(data)

    def read_headers():
        nonlocal remaining
        headers = {}
        while True:
            while True:
                eol = bytes(buf).find(b"\r\n")
                if eol != -1:
                    break
                if len(buf) > 65536:
                    raise BadUpload("header too long")
                # 注意：fill(4) 只保证"缓冲区至少有 4 字节"；当已有字节但
                # 找不到换行时它什么都不读，直接原地空转，曾导致真死循环。
                # 这里每轮必须真的多读一块；读完还没有就是报文被截断。
                if remaining == 0:
                    raise BadUpload("truncated headers")
                data = rfile.read(min(CHUNK, remaining))
                if not data:
                    raise BadUpload("truncated headers")
                remaining -= len(data)
                buf.extend(data)
            line = bytes(buf[:eol])
            del buf[:eol + 2]
            if not line:
                return headers
            k, _, v = line.decode("latin1").partition(":")
            headers[k.strip().lower()] = v.strip()

    def read_data_file(path):
        """流式写文件。返回 (size, ended)。消费 delimiter 及其后 2 字节。"""
        out = open(path, "wb")
        size = 0
        keep = len(delim) + 4
        try:
            while True:
                i = bytes(buf).find(delim)
                if i != -1:
                    if not fill(i + len(delim) + 2):
                        raise BadUpload("truncated data")
                    b = bytes(buf)
                    i = b.find(delim)
                    out.write(b[:i])
                    size += i
                    charge(i)
                    ended = b[i + len(delim):i + len(delim) + 2] == b"--"
                    del buf[:i + len(delim) + 2]
                    out.close()
                    return size, ended
                if len(buf) > keep:
                    n = len(buf) - keep
                    out.write(buf[:-keep])
                    size += n
                    charge(n)
                    del buf[:-keep]
                if not fill(keep + 1):
                    raise BadUpload("truncated data")
        except BaseException:
            try:
                out.close()
            except Exception:
                pass
            try:
                os.unlink(path)
            except OSError:
                pass
            raise

    def read_data_mem(limit):
        """字段 part 读入内存（有上限）。返回 (bytes, ended)。"""
        data = bytearray()
        keep = len(delim) + 4
        while True:
            i = bytes(buf).find(delim)
            if i != -1:
                if not fill(i + len(delim) + 2):
                    raise BadUpload("truncated data")
                b = bytes(buf)
                i = b.find(delim)
                data.extend(b[:i])
                ended = b[i + len(delim):i + len(delim) + 2] == b"--"
                del buf[:i + len(delim) + 2]
                if len(data) > limit:
                    raise BadUpload("field too large")
                return bytes(data), ended
            if len(buf) > keep:
                data.extend(buf[:-keep])
                del buf[:-keep]
                if len(data) > limit:
                    raise BadUpload("field too large")
            if not fill(keep + 1):
                raise BadUpload("truncated data")

    try:
        # 跳过 preamble，定位第一个 boundary
        while True:
            i = bytes(buf).find(bnd)
            if i != -1:
                del buf[:i]
                break
            if len(buf) > 1024 * 1024:
                raise BadUpload("preamble too long")
            # 同 read_headers：fill(len(bnd)+2) 在已有足够字节但没命中时
            # 不会再读，直接原地空转，曾导致真死循环。每轮必须真的多读一块。
            if remaining == 0:
                raise BadUpload("no boundary")
            data = rfile.read(min(CHUNK, remaining))
            if not data:
                raise BadUpload("no boundary")
            remaining -= len(data)
            buf.extend(data)
        # 消费第一个 boundary 行
        if not fill(len(bnd) + 2):
            raise BadUpload("truncated")
        if bytes(buf[len(bnd):len(bnd) + 2]) == b"--":
            drain()
            return fields, files
        del buf[:len(bnd) + 2]
        # 主循环：headers -> data -> ...
        while True:
            headers = read_headers()
            disp = headers.get("content-disposition", "")
            name = _disp_param(disp, "name") or ""
            name_bytes = len(name.encode("utf-8"))
            if name_bytes > MAX_PART_NAME_BYTES:
                raise BadUpload("part name too long")
            filename = _disp_param(disp, "filename")
            if filename:
                n_files += 1
                if n_files > MAX_FILES_PER_REQUEST:
                    # 已落盘的临时文件由外层 except BaseException 清理
                    raise BadUpload("too many files")
                filename = _clean_filename(filename)
                stored = secrets.token_hex(16)
                path = os.path.join(FILES_DIR, stored)
                created_paths.append(path)
                size, ended = read_data_file(path)
                files.append({"name": name, "filename": filename,
                              "stored": stored, "size": size})
            else:
                n_fields += 1
                if n_fields > MAX_FIELDS_PER_REQUEST:
                    # 已落盘的临时文件由外层 except BaseException 清理；
                    # 这里先计数再读：超限直接拒掉，不必把这个 part 读完
                    raise BadUpload("too many fields")
                if fields_bytes + name_bytes > MAX_FIELDS_TOTAL_BYTES:
                    raise BadUpload("fields too large")
                data, ended = read_data_mem(min(
                    MAX_FIELD_BYTES,
                    MAX_FIELDS_TOTAL_BYTES - fields_bytes - name_bytes))
                fields_bytes += name_bytes + len(data)
                fields[name] = data.decode("utf-8", "replace")
            if ended:
                break
        drain()
        return fields, files
    except BaseException:
        for p in created_paths:
            try:
                os.unlink(p)
            except OSError:
                pass
        try:
            drain()
        except Exception:
            pass
        raise

# ---------------- 页面模板 ----------------
# 设计：浅色为主，系统深色模式时自动切换；所有样式内联在页面里，
# 不依赖任何 CDN，裸 VPS 断网也能正常显示。
CSS = """
:root{--bg:#f4f6fa;--card:#fff;--text:#1f2937;--muted:#667085;--border:#e3e7ee;--line:#eef1f5;
--hover:#f3f5f9;--accent:#2563eb;--accent-h:#1d4ed8;--accent-soft:#eaf1ff;--accent-text:#1d4ed8;
--danger:#d92d20;--danger-soft:#fef3f2;--danger-line:#fbcfca;--ok:#067647;--ok-soft:#ecfdf3;--ok-line:#abefc6;
--warn:#b54708;--warn-soft:#fffaeb;--r:14px;--r-sm:10px;
--shadow:0 1px 2px rgba(16,24,40,.04),0 2px 12px rgba(16,24,40,.05);color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--card:#161a21;--text:#e7e9ee;--muted:#9aa4b2;
--border:#2a303b;--line:#212631;--hover:#1d222b;--accent:#2f6fed;--accent-h:#4a82f0;--accent-soft:#17233d;
--accent-text:#8db3ff;--danger:#f97066;--danger-soft:#2a1715;--danger-line:#5c2a25;--ok:#47cd89;
--ok-soft:#0f2519;--ok-line:#1f4d33;--warn:#fdb022;--warn-soft:#2a2111;--shadow:none;color-scheme:dark}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei","Noto Sans CJK SC",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.wrap{margin:0 auto;padding:20px 16px 88px}
.wrap-sm{max-width:440px}.wrap-md{max-width:760px}.wrap-lg{max-width:1080px}
h1{font-size:22px;line-height:1.35;margin:0 0 6px;letter-spacing:-.01em}
h2{font-size:17px;margin:0 0 4px;display:flex;align-items:center;gap:8px}
h3{font-size:15px;margin:0 0 10px}
p{margin:0 0 10px}
a{color:var(--accent-text);text-decoration:none}a:hover{text-decoration:underline}
.muted{color:var(--muted);font-size:13px}
small.muted{font-size:12px}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:20px;margin-bottom:16px;box-shadow:var(--shadow)}
.card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.card-head p{margin:0}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;align-items:start}
.grid2>.card{margin-bottom:0}
.stack{display:flex;flex-direction:column;gap:16px;margin-bottom:16px}
.stack>.card{margin-bottom:0}
label.fld{display:block;font-size:13px;color:var(--muted);margin:10px 0 4px}
input,select,textarea{font:inherit;font-size:15px;color:var(--text);background:var(--card);border:1px solid var(--border);
  border-radius:var(--r-sm);padding:10px 12px;width:100%;margin:6px 0;min-height:44px;transition:border-color .15s,box-shadow .15s}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 22%,transparent)}
input[type=checkbox]{width:18px;height:18px;min-height:0;margin:0;accent-color:var(--accent);flex:none;cursor:pointer}
button,.btn{font:inherit;font-size:14px;font-weight:600;display:inline-flex;align-items:center;justify-content:center;gap:6px;
  min-height:40px;padding:0 16px;border-radius:var(--r-sm);border:1px solid transparent;background:var(--accent);color:#fff;
  cursor:pointer;text-decoration:none;white-space:nowrap;transition:background .15s,border-color .15s,box-shadow .15s,transform .05s;
  -webkit-tap-highlight-color:transparent;vertical-align:middle;margin:0}
button:hover,.btn:hover{background:var(--accent-h);text-decoration:none}
button:active,.btn:active{transform:translateY(1px)}
button:focus-visible,.btn:focus-visible,a:focus-visible,summary:focus-visible{outline:3px solid color-mix(in srgb,var(--accent) 45%,transparent);outline-offset:2px}
button:disabled{opacity:.5;cursor:not-allowed;transform:none}
form>button,button.block,.btn.block{width:100%;min-height:46px;margin-top:10px;font-size:15px}
button.ghost,.btn.ghost{background:var(--card);color:var(--text);border-color:var(--border)}
button.ghost:hover,.btn.ghost:hover{background:var(--hover)}
button.danger,.btn.danger{background:var(--card);color:var(--danger);border-color:var(--danger-line)}
button.danger:hover,.btn.danger:hover{background:var(--danger-soft)}
button.sm,.btn.sm{min-height:32px;padding:0 10px;font-size:13px;font-weight:500;border-radius:8px}
button.icon-only{padding:0;width:40px}
.btn-view{min-height:44px;padding:0 20px;font-size:15px;box-shadow:0 2px 10px color-mix(in srgb,var(--accent) 35%,transparent)}
.ic{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex:none}
.sm .ic{width:15px;height:15px}
a.btnlink{display:inline-flex;text-decoration:none}
a.btnlink>button{pointer-events:none}
.linkbox{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--accent-soft);color:var(--accent-text);
  border:1px dashed color-mix(in srgb,var(--accent) 40%,transparent);border-radius:8px;padding:8px 12px;word-break:break-all;margin:8px 0}
.err,.ok{border-radius:var(--r-sm);padding:10px 12px;margin:8px 0;font-size:14px;border:1px solid}
.err{background:var(--danger-soft);border-color:var(--danger-line);color:var(--danger)}
.ok{background:var(--ok-soft);border-color:var(--ok-line);color:var(--ok)}
span.err,span.ok{display:inline-block}
progress{-webkit-appearance:none;appearance:none;width:100%;height:8px;border:0;border-radius:99px;background:var(--line);overflow:hidden;vertical-align:middle}
progress::-webkit-progress-bar{background:var(--line);border-radius:99px}
progress::-webkit-progress-value{background:var(--accent);border-radius:99px;transition:width .2s}
progress::-moz-progress-bar{background:var(--accent);border-radius:99px}
.prog{display:flex;align-items:center;gap:10px;margin:12px 0 4px}.prog .muted{min-width:3em;text-align:right;font-variant-numeric:tabular-nums}
.row{display:flex;gap:8px;flex-wrap:wrap}.row>*{flex:1 1 140px}
.badge{display:inline-flex;align-items:center;gap:3px;font-size:12px;font-weight:600;line-height:1;padding:4px 8px;border-radius:99px;
  background:var(--accent-soft);color:var(--accent-text);margin-right:6px;vertical-align:2px;white-space:nowrap}
.badge.recv{background:var(--ok-soft);color:var(--ok)}
.badge.pin{background:var(--warn-soft);color:var(--warn)}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin:4px 0 18px}
.brand{display:flex;align-items:center;gap:10px;font-size:20px;font-weight:700;margin:0;color:var(--text)}
.brand .logo{width:36px;height:36px;border-radius:10px;background:var(--accent);color:#fff;display:grid;place-items:center;font-size:19px;flex:none}
.userchip{display:flex;align-items:center;gap:10px;font-size:14px}
.userchip .who{background:var(--card);border:1px solid var(--border);border-radius:99px;padding:4px 12px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:14px 16px;box-shadow:var(--shadow)}
.stat b{display:block;font-size:22px;line-height:1.2;font-variant-numeric:tabular-nums}
.stat span{color:var(--muted);font-size:13px}
.drop{position:relative;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:4px;text-align:center;
  border:2px dashed var(--border);border-radius:var(--r);padding:22px 14px;margin:4px 0 6px;background:var(--hover);color:var(--muted);
  cursor:pointer;transition:border-color .15s,background .15s;min-height:120px}
.drop:hover,.drop.over{border-color:var(--accent);background:var(--accent-soft)}
.drop.has{border-style:solid;border-color:var(--accent)}
.drop input[type=file]{position:absolute;inset:0;width:100%;height:100%;opacity:0;cursor:pointer;margin:0;min-height:0}
.drop .ic{width:28px;height:28px;color:var(--accent)}
.drop b{color:var(--text);font-size:15px}
.drop-files{font-size:13px;color:var(--accent-text);word-break:break-all}
.drop-files:empty{display:none}
.file{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:14px 0;border-top:1px solid var(--line)}
.file:first-child{border-top:0}
.file b{word-break:break-word;overflow-wrap:anywhere}
.file>div:first-child{min-width:0;flex:1}
.acts{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end;flex:none;align-items:center}
.file.stacked{display:block}.file.stacked>.acts{justify-content:flex-start;margin-top:10px}
.file.stacked .linkbox{max-width:640px}
.edit-slot:empty{display:none}
.edit-slot{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-top:6px}
.edit-slot input,.edit-slot select{flex:1 1 180px;width:auto!important;margin:0;min-height:36px;padding:6px 10px}
.edit-slot button{min-height:36px}
.list-tools{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:6px}
.list-tools input[type=search]{flex:1 1 200px;width:auto;margin:0}
.ftable .fhead,.ftable .frow{display:grid;grid-template-columns:28px minmax(0,1fr) 90px 130px auto;gap:12px;align-items:center}
.ftable.nock .fhead,.ftable.nock .frow{grid-template-columns:minmax(0,1fr) 90px 130px auto}
.ftable .fhead{font-size:12px;color:var(--muted);font-weight:600;padding:8px 0;border-bottom:1px solid var(--border)}
.ftable .frow{padding:12px 0;border-top:1px solid var(--line)}
.ftable .fhead+.frow{border-top:0}
.frow .fname b{display:block;word-break:break-word;overflow-wrap:anywhere;font-weight:600}
.frow .c-size,.frow .c-time{font-size:13px;color:var(--muted);font-variant-numeric:tabular-nums}
.m-meta{display:none}
.empty{text-align:center;padding:28px 12px;color:var(--muted)}
.empty .big{font-size:40px;line-height:1;margin-bottom:8px;display:block}
details{border:1px solid var(--border);border-radius:var(--r-sm);padding:0 14px;margin-top:14px}
details>summary{cursor:pointer;padding:12px 0;font-weight:600;list-style:none;display:flex;align-items:center;gap:8px}
details>summary::-webkit-details-marker{display:none}
details>summary::before{content:"▸";color:var(--muted);transition:transform .15s}
details[open]>summary::before{transform:rotate(90deg)}
details[open]{padding-bottom:14px}
.existing-file{justify-content:flex-start;cursor:pointer;padding:10px 4px;gap:10px}
.existing-file:hover{background:var(--hover)}
input.fileck{margin:0}
.auth{margin-top:8vh}
.auth .brand{justify-content:center;margin-bottom:6px}
.auth h1{text-align:center;font-size:20px}
.auth .sub{text-align:center;color:var(--muted);font-size:14px;margin-bottom:16px}
.hero{display:flex;gap:14px;align-items:flex-start}
.hero .logo{width:48px;height:48px;border-radius:14px;background:var(--accent-soft);color:var(--accent);display:grid;place-items:center;font-size:24px;flex:none}
.hero h1{margin:2px 0 4px;word-break:break-word;overflow-wrap:anywhere}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{display:inline-flex;align-items:center;gap:4px;font-size:13px;color:var(--muted);background:var(--hover);border:1px solid var(--line);border-radius:99px;padding:3px 10px}
.chip b{color:var(--text);font-weight:600}
.note{background:var(--accent-soft);color:var(--accent-text);border-radius:var(--r-sm);padding:10px 12px;font-size:13px;margin-top:14px}
.sf{display:flex;align-items:center;gap:12px 14px;padding:14px 0;border-top:1px solid var(--line);flex-wrap:wrap;scroll-margin-top:16px}
.sf:first-child{border-top:0}
.sf:target{animation:flash 2s ease-out}
@keyframes flash{0%{background:var(--accent-soft)}100%{background:transparent}}
.sf-main{display:flex;align-items:center;gap:12px;flex:1 1 260px;min-width:0}
.sf-info{min-width:0}
.sf-name{font-weight:600;word-break:break-word;overflow-wrap:anywhere;line-height:1.45}
.sf-name .badge{margin:0 0 0 6px;vertical-align:1px}
.sf-meta{margin-top:2px}
.sf-acts{display:flex;gap:8px;flex:none;align-items:center}
.sf-manage{flex-basis:100%;display:flex;gap:6px;flex-wrap:wrap;padding-left:56px}
.ftile{width:44px;height:44px;border-radius:12px;display:flex;flex-direction:column;align-items:center;justify-content:center;flex:none;
  background:var(--hover);color:var(--muted);font-size:9px;font-weight:700;letter-spacing:.02em;line-height:1;gap:2px;text-transform:uppercase}
.ftile .ic{width:20px;height:20px}
.ftile.k-img{background:#e8f7ee;color:#067647}.ftile.k-vid{background:#f3ebff;color:#6d28d9}
.ftile.k-aud{background:#fff1e6;color:#c2410c}.ftile.k-pdf{background:#fdecec;color:#c01f1f}
.ftile.k-txt{background:#eaf1ff;color:#1d4ed8}
@media (prefers-color-scheme:dark){.ftile.k-img{background:#10261a;color:#6ce0a0}.ftile.k-vid{background:#221a36;color:#c4a6ff}
.ftile.k-aud{background:#2b1c10;color:#ffb27a}.ftile.k-pdf{background:#2d1515;color:#ff9a9a}.ftile.k-txt{background:#17233d;color:#8db3ff}}
.diskfoot{position:fixed;left:12px;bottom:12px;background:rgba(17,24,39,.86);color:#fff;font-size:12px;padding:7px 12px;border-radius:99px;
  z-index:1000;display:flex;align-items:center;gap:8px;box-shadow:0 4px 14px rgba(0,0,0,.18);-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px)}
.diskbar{width:90px;height:5px;border-radius:3px;background:rgba(255,255,255,.25);overflow:hidden}
.diskbar i{display:block;height:100%;background:#40c463;border-radius:3px}
.foot{text-align:center;color:var(--muted);font-size:12px;margin-top:8px}
html.pv-lock,html.pv-lock body{overflow:hidden}
.pv{position:fixed;inset:0;z-index:3000;display:flex;flex-direction:column;background:#0b0d12;color:#f2f4f7}
.pv[hidden]{display:none}
.pv-bar{display:flex;align-items:center;gap:8px;padding:10px 12px;padding-top:max(10px,env(safe-area-inset-top))}
.pv-title{flex:1;min-width:0}
.pv-name{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pv-meta{font-size:12px;color:#aab2c0}
.pv-btn,.pv-nav{background:rgba(255,255,255,.12);color:#fff;border:0}
.pv-btn:hover,.pv-nav:hover{background:rgba(255,255,255,.22)}
.pv-body{flex:1;min-height:0;position:relative;display:flex}
.pv-stage{flex:1;min-width:0;display:flex;align-items:center;justify-content:center;padding:0 12px 12px;padding-bottom:max(12px,env(safe-area-inset-bottom));overflow:auto}
.pv-stage img,.pv-stage video{max-width:100%;max-height:100%;object-fit:contain;border-radius:6px;background:#000;display:block}
.pv-stage img{cursor:zoom-in;background:transparent}
.pv-stage.zoom{align-items:flex-start;justify-content:flex-start}
.pv-stage.zoom img{max-width:none;max-height:none;cursor:zoom-out}
.pv-stage iframe{width:100%;height:100%;border:0;border-radius:8px;background:#fff}
.pv-stage pre{align-self:stretch;width:100%;max-width:980px;margin:0 auto;overflow:auto;background:var(--card);color:var(--text);padding:16px;
  border-radius:10px;font:13px/1.65 ui-monospace,SFMono-Regular,Menlo,Consolas,"PingFang SC","Microsoft YaHei",monospace;white-space:pre-wrap;word-break:break-word}
.pv-audio{background:rgba(255,255,255,.06);border-radius:16px;padding:28px 22px;text-align:center;width:min(480px,100%)}
.pv-audio .ic{width:48px;height:48px;color:#ffb27a;margin-bottom:8px}
.pv-audio audio{width:100%;margin-top:14px}
.pv-msg{text-align:center;max-width:440px;color:#d0d5dd;line-height:1.7}
.pv-msg .btn{margin:14px 4px 0}
.pv-nav{position:absolute;top:50%;margin-top:-24px;width:48px;height:48px;min-height:0;padding:0;border-radius:50%;z-index:2}
.pv-prev{left:14px}.pv-next{right:14px}
.pv[data-kind=txt] .pv-nav,.pv[data-kind=pdf] .pv-nav{background:rgba(17,24,39,.72)}
.pv-count{position:absolute;left:50%;transform:translateX(-50%);bottom:max(14px,env(safe-area-inset-bottom));font-size:12px;color:#aab2c0;
  background:rgba(0,0,0,.45);padding:2px 10px;border-radius:99px;pointer-events:none}
.pv-count:empty{display:none}
.pv-spin{width:38px;height:38px;border:3px solid rgba(255,255,255,.2);border-top-color:#fff;border-radius:50%;animation:spin .9s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
@media (max-width:700px){
  .wrap{padding:14px 12px 84px}
  .card{padding:16px;border-radius:12px}
  h1{font-size:20px}
  .stats{gap:8px}.stat{padding:10px 12px}.stat b{font-size:18px}
  .file{flex-wrap:wrap}.file>.acts{flex:1 1 100%;justify-content:flex-start}
  .ftable .fhead{display:none}
  .ftable .frow,.ftable.nock .frow{grid-template-columns:auto minmax(0,1fr);gap:6px 10px}
  .ftable.nock .frow{grid-template-columns:minmax(0,1fr)}
  .frow .c-size,.frow .c-time{display:none}
  .m-meta{display:inline}
  .frow .acts{grid-column:1/-1;justify-content:flex-start}
  .ftable:not(.nock) .frow .acts{padding-left:28px}
}
@media (max-width:560px){
  .sf-acts{flex:1 1 100%}
  .sf-acts .btn-view{flex:1 1 auto;min-height:48px;font-size:16px}
  .sf-acts .btn{min-height:48px}
  .sf-acts .btn:only-child{flex:1 1 auto}
  .sf-manage{padding-left:0}
  .pv-btn .lbl{display:none}
  .pv-btn{padding:0;width:42px}
  .pv-nav{width:40px;height:40px;margin-top:-20px}.pv-prev{left:6px}.pv-next{right:6px}
}
"""

# 线框图标（Feather 风格），直接内联 SVG，不依赖外部字体/CDN。
_ICON_PATHS = {
    "eye": '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    "play": '<polygon points="7 4 20 12 7 20 7 4" fill="currentColor"/>',
    "download": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
    "upload": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
    "x": '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    "left": '<polyline points="15 18 9 12 15 6"/>',
    "right": '<polyline points="9 18 15 12 9 6"/>',
    "external": '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
    "copy": '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
    "trash": '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>',
    "edit": '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15 14"/>',
    "file": '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>',
    "image": '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/>',
    "film": '<rect x="2" y="3" width="20" height="18" rx="2"/><path d="M7 3v18M17 3v18M2 12h20M2 7.5h5M2 16.5h5M17 7.5h5M17 16.5h5"/>',
    "music": '<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>',
    "text": '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="14" y2="17"/>',
    "up": '<polyline points="18 15 12 9 6 15"/>',
    "down": '<polyline points="6 9 12 15 18 9"/>',
    "pin": '<path d="M12 17v5"/><path d="M9 3h6l-1 6 4 4v2H6v-2l4-4z"/>',
    "logout": '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
    "open": '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
}

def icon(name):
    return ('<svg class="ic" viewBox="0 0 24 24" aria-hidden="true" focusable="false">'
            + _ICON_PATHS[name] + "</svg>")

_FAVICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E"
            "%3Crect width='64' height='64' rx='16' fill='%232563eb'/%3E"
            "%3Cpath d='M16 22a4 4 0 0 1 4-4h9l4 5h11a4 4 0 0 1 4 4v15a4 4 0 0 1-4 4H20a4 4 0 0 1-4-4z' fill='white'/%3E%3C/svg%3E")

def page(title, body, size="md"):
    # size: sm（登录/提示）、md（分享页/接收页）、lg（控制台）
    return ("<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1,viewport-fit=cover'>"
            "<meta name='color-scheme' content='light dark'>"
            "<meta name='theme-color' content='#f4f6fa' media='(prefers-color-scheme: light)'>"
            "<meta name='theme-color' content='#0e1116' media='(prefers-color-scheme: dark)'>"
            f"<link rel='icon' href=\"{_FAVICON}\">"
            f"<title>{html.escape(title)}</title><style>{CSS}</style></head>"
            f"<body><main class='wrap wrap-{size}'>{body}</main></body></html>").encode("utf-8")

def brand(tag="div"):
    return f"<{tag} class='brand'><span class='logo' aria-hidden='true'>🗂️</span>文件分享</{tag}>"

def hsize(n):
    n = int(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.1f}{u}" if u != "B" else f"{n}B"
        n /= 1024

def htime(ts):
    if not ts:
        return "永久"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))

def disk_usage():
    try:
        st = os.statvfs(DATA_DIR)
        total = st.f_frsize * st.f_blocks
        free = st.f_frsize * st.f_bavail
        return max(total - free, 0), total
    except OSError:
        return 0, 0

def disk_foot():
    used, total = disk_usage()
    if total <= 0:
        # statvfs 失败、磁盘大小未知：不能显示"剩余 0B"，那是误导。
        return "<div class='diskfoot'>💾 磁盘信息不可用</div>"
    free = max(total - used, 0)
    pct = min(used * 100 // total, 100) if total else 0
    return (f"<div class='diskfoot'>💾 剩余 {hsize(free)} / 已用 {hsize(used)}"
            f"<span class='diskbar'><i style='width:{pct}%'></i></span></div>")

def upload_limit():
    # 实际可上传的最大字节数：配置上限与磁盘剩余空间取小者。
    # 磁盘快满时，MAX_UPLOAD 再大也传不上去，页面上就该直接告诉对方真实数字。
    # 返回 (上限字节数, 磁盘剩余字节数)：statvfs 失败、磁盘大小未知时剩余为
    # None（未知），绝不能按"剩余 0"处理，否则一次失败的 statvfs 会让所有
    # 上传直接 413、整个上传功能被误杀。
    used, total = disk_usage()
    if total <= 0:
        return MAX_UPLOAD, None
    free = max(total - used, 0)
    return min(MAX_UPLOAD, free), free

def too_large_msg():
    # 413 时的错误文案：区分"磁盘满了"和"文件超配置上限"，
    # 否则磁盘满时用户会对着几 MB 的文件困惑"到底哪里大了"。
    # 磁盘剩余未知（statvfs 失败）时不能谎称"剩余 0B"，给通用文案。
    _, free = upload_limit()
    if free is not None and free < MAX_UPLOAD:
        return "磁盘剩余空间不足（剩余 %s），无法上传" % hsize(free)
    return "文件太大，超出上限"

def _auth_card(inner):
    return f"<div class='auth'><div class='card'>{inner}</div></div>"

def setup_page(err=""):
    e = f"<div class='err'>{html.escape(err)}</div>" if err else ""
    return page("初始设置", _auth_card(f"""{brand()}
<h1>欢迎使用</h1><p class='sub'>首次使用，请输入服务器安装时显示的初始化码，并设置管理员密码。初始化码也可在服务器的 data/setup-token 文件中查看。</p>{e}
<form method='post' action='/setup'>
<label class='fld' for='setup_code'>初始化码</label>
<input type='text' id='setup_code' name='setup_code' placeholder='64 位初始化码' required autocomplete='off' spellcheck='false'>
<label class='fld' for='pw1'>管理员密码</label>
<input type='password' id='pw1' name='pw1' placeholder='设置密码（至少 4 位）' required minlength='4' autocomplete='new-password'>
<input type='password' name='pw2' placeholder='再次输入' required minlength='4' autocomplete='new-password' aria-label='再次输入密码'>
<button>完成设置</button></form>"""), "sm")

def login_page(err=""):
    e = f"<div class='err' role='alert'>{html.escape(err)}</div>" if err else ""
    return page("登录", _auth_card(f"""{brand()}
<p class='sub'>输入密码登录控制台</p>{e}
<form method='post' action='/login'>
<input type='password' name='pw' placeholder='密码' required autofocus autocomplete='current-password' aria-label='密码'>
<button>登录</button></form>
<p class='muted' style='margin:14px 0 0;text-align:center'>没有用户名：不同的密码对应不同的账号，找管理员要你的密码。</p>"""), "sm")

_EXPIRY_OPTIONS = ("<option value='7'>7 天后过期</option><option value='1'>1 天后过期</option>"
                   "<option value='30'>30 天后过期</option><option value='0'>永久有效</option>")

def _drop_zone(input_attrs, hint=""):
    # 整块区域都是 <input type=file>（透明覆盖），点击或把文件拖进来都能选；
    # 选中后由 UI_JS 显示文件名和总大小。
    return (f"<label class='drop'>{icon('upload')}<b>点击选择文件，或拖到这里</b>"
            f"<span class='muted'>{hint or '支持多选，大文件自动分片上传'}</span>"
            f"<span class='drop-files' aria-live='polite'></span>"
            f"<input type='file' {input_attrs} aria-label='选择文件'></label>")

def dash_page(shares, user, public_base=""):
    is_admin = user["is_admin"]
    base = normalize_public_base(public_base)
    pub_js = json.dumps(base)
    items = []
    for s in shares:
        files = share_files(s["id"])
        total = sum(f["size"] or 0 for f in files)
        typ = "发送" if s["type"] == "send" else "接收"
        cls = "" if s["type"] == "send" else "recv"
        path = f"/{'s' if s['type']=='send' else 'r'}/{s['id']}"
        link = public_link(path, base)
        # 管理员看全部分享：标出归属；普通用户只看得到自己的分享
        owner = ""
        if is_admin and s["owner_id"] is not None:
            owner = ("<span class='badge'>我的</span>" if s["owner_id"] == user["id"]
                     else f"<span class='badge recv'>用户#{s['owner_id']}</span>")
        items.append(f"""<div class='file stacked'><div>
<span class='badge {cls}'>{typ}</span>{owner}<b id='ttl-{s['id']}'>{html.escape(s['title'] or '(无备注)')}</b>
<div class='muted'>{len(files)} 个文件 · {hsize(total)} · 到期：{htime(s['expires'])}</div>
<div class='edit-slot' id='ex-{s['id']}'></div>
<div class='linkbox' id='lk-{s['id']}'>{html.escape(link)}</div><div class='edit-slot' id='ti-{s['id']}'></div></div>
<div class='acts'>
<button class='ghost sm' onclick="copyLink('{s['id']}','{path}')">{icon('copy')}复制链接</button>
<a class='btn ghost sm' href='{path}' target='_blank' rel='noopener'>{icon('external')}打开</a>
<button class='ghost sm' onclick="editTitle('{s['id']}')">{icon('edit')}改备注</button>
<button class='ghost sm' onclick="editExpiry('{s['id']}')">{icon('clock')}改过期</button>
<button class='danger sm' onclick="delShare('{s['id']}')">{icon('trash')}删除链接</button>
</div></div>""")
    frows = []
    total_size = 0
    for fr in all_files(user):
        fid, fn, fsz, fct = fr["id"], fr["filename"], fr["size"], fr["created"]
        total_size += fsz or 0
        stype, stitle, sowner = fr["type"], fr["title"], fr["owner_id"]
        if stype is None:
            # 归属的分享链接已被删除，文件仍保留在这里等待手动清理
            ftyp, fcls, fsrc = "链接已删", "recv", "分享链接已删除"
        else:
            ftyp = "发送" if stype == "send" else "接收"
            fcls = "" if stype == "send" else "recv"
            fsrc = f"{ftyp}「{html.escape(stitle or '(无备注)')}」"
        # 管理员看全部文件时标出归属；删文件的复选框和按钮只有管理员可见
        ownermk = ""
        if is_admin and sowner is not None:
            ownermk = (" <span class='badge'>我的</span>" if sowner == user["id"]
                       else f" <span class='badge recv'>用户#{sowner}</span>")
        ck = (f"<input type='checkbox' class='fileck' value='{fid}' aria-label='选择 {html.escape(fn)}'>"
              if is_admin else "")
        delbtn = (f"<button class='danger sm' onclick=\"delOneFile({fid})\">删除</button>"
                  if is_admin else "")
        dlbtn = f"<a class='btnlink' href='/dl/{fid}'><button class='ghost sm' tabindex='-1'>下载</button></a> "
        frows.append(f"""<div class='frow'>{"<div>" + ck + "</div>" if is_admin else ""}
<div class='fname'><b>{html.escape(fn)}</b>
<div class='muted'><span class='badge {fcls}'>{ftyp}</span>{ownermk}来自{fsrc}<span class='m-meta'> · {hsize(fsz)} · {htime(fct)}</span></div></div>
<div class='c-size'>{hsize(fsz)}</div><div class='c-time'>{htime(fct)}</div>
<div class='acts'>{dlbtn}{delbtn}</div></div>""")
    nock = "" if is_admin else " nock"
    if frows:
        flist = (f"<div class='ftable{nock}' id='fileTable'><div class='fhead'>"
                 + ("<div></div>" if is_admin else "")
                 + "<div>文件名</div><div>大小</div><div>上传时间</div><div></div></div>"
                 + "".join(frows) + "</div>"
                 + "<p class='empty' id='fileNoMatch' hidden>没有匹配的文件</p>")
    else:
        flist = "<div class='empty'><span class='big'>📂</span>还没有任何文件</div>"
    lst = ("".join(items) if items else
           "<div class='empty'><span class='big'>🔗</span>还没有分享，来创建一个吧 👆</div>")
    role = "👑 管理员" if is_admin else "👤 普通用户"
    share_title = "📋 分享链接（全部用户）" if is_admin else "📋 我的分享"
    file_title = "📁 全部文件" if is_admin else "📁 我的文件"
    filehint = ("发送和接收的所有文件都在这里。删除为彻底删除，不经过回收站。"
                if is_admin else "你的文件都在这里。你没有删除文件的权限。")
    search = ("<input type='search' id='fileSearch' placeholder='搜索文件名 / 来源' aria-label='搜索文件'>"
              if frows else "")
    fileops = ("""<button class='ghost sm' onclick="toggleAllFiles()">全选 / 取消全选</button>
<button class='danger sm' onclick="delFiles()">删除选中</button>""") if is_admin and frows else ""
    tools = f"<div class='list-tools'>{search}{fileops}</div>" if (search or fileops) else ""
    users_card = ""
    # 眼睛：普通用户的明文密码直接嵌进本页（仅管理员可见），点眼睛本地即时显示，
    # 不再为每次点击发一次网络请求（之前慢就慢在这一次往返上）。
    upw_json = "{}"
    if is_admin:
        urows = []
        pw_map = {}
        with db() as c:
            for r in c.execute("SELECT id, pw_plain FROM users WHERE is_admin=0"):
                pw_map[str(r["id"])] = r["pw_plain"] or ""
        # json 转义后是合法的 JS 字面量；< 转成 \u003c 防止密码里有 </script> 跳出脚本块
        upw_json = json.dumps(pw_map, ensure_ascii=False).replace("<", "\\u003c")
        for u in list_users():
            remark = (u["remark"] or "").strip()
            rmk = (f"<span class='badge' id='rmk-{u['id']}'>{html.escape(remark)}</span> "
                   if remark else f"<span class='muted' id='rmk-{u['id']}'></span>")
            if u["is_admin"]:
                mark, who = "<span class='badge'>管理员</span>", "管理员"
                ops = ("<span class='muted'>这是你，改密码请用「修改密码」</span>"
                       if u["id"] == user["id"] else "")
            else:
                mark, who = f"<span class='badge recv'>用户#{u['id']}</span>", "普通用户"
                ops = (f"<button class='ghost sm' onclick=\"togglePw({u['id']},this)\" title='查看密码' aria-label='查看密码'>👁</button> "
                       f"<button class='ghost sm' onclick=\"editRemark({u['id']})\">改备注</button> "
                       f"<button class='ghost sm' onclick=\"resetPw({u['id']})\">重设密码</button> "
                       f"<button class='danger sm' onclick=\"userDel({u['id']})\">删除用户</button>")
            urows.append(f"""<div class='file stacked'><div>
{mark}<b>{who}</b> {rmk}
<div class='muted'>创建于 {htime(u['created'])}</div><div class='edit-slot' id='urp-{u['id']}'></div><div class='edit-slot' id='urm-{u['id']}'></div><div class='edit-slot' id='upw-{u['id']}'></div></div>
<div class='acts'>{ops}</div></div>""")
        users_card = f"""<div class='card'><div class='card-head'><div><h2>👥 用户管理</h2>
<p class='muted'>没有注册入口，账号只能由你添加。登录没有用户名：不同的密码就是不同的账号。备注名只给你自己看（比如这个账号给了谁），不影响登录。</p></div></div>
{''.join(urows)}
<form id='userAddForm' style='margin-top:12px;border-top:1px solid var(--line);padding-top:12px'>
<h3>添加用户</h3>
<div class='row'>
<input type='password' name='pw1' placeholder='新用户密码（至少4位）' required minlength='4' autocomplete='new-password' aria-label='新用户密码'>
<input type='password' name='pw2' placeholder='再次输入' required minlength='4' autocomplete='new-password' aria-label='再次输入'>
</div>
<input type='text' name='remark' placeholder='备注名（可选，如：张三）' maxlength='50' aria-label='备注名'>
<button class='ghost' style='width:100%'>添加用户</button></form><div id='userRes'></div></div>
"""
    stats = (f"<div class='stats'><div class='stat'><b>{len(shares)}</b><span>有效分享</span></div>"
             f"<div class='stat'><b>{len(frows)}</b><span>文件</span></div>"
             f"<div class='stat'><b>{hsize(total_size)}</b><span>文件总大小</span></div></div>")
    return page("控制台", f"""<header class='topbar'>{brand('h1')}
<div class='userchip'><span class='who'>{role}</span><a href='/logout' class='btn ghost sm'>{icon('logout')}退出登录</a></div></header>
{stats}
<div class='grid2' style='margin-bottom:16px'>
<div class='card'><div class='card-head'><div><h2>📤 发送文件</h2><p class='muted'>上传后生成分享链接，对方打开即可在线查看或下载。</p></div></div>
<form id='sendForm'>
{_drop_zone("name='file' multiple required")}
<input type='text' name='title' placeholder='备注（可选）' maxlength='100' aria-label='备注'>
<select name='expiry' aria-label='有效期'>{_EXPIRY_OPTIONS}</select>
<button id='sendBtn'>{icon('upload')}上传并生成分享链接</button>
<div id='sendProgWrap' class='prog' style='display:none'><progress id='sendProg' value='0' max='100'></progress>
 <span id='sendPct' class='muted'>0%</span></div>
<div id='sendStat' class='muted'></div>
</form><div id='sendRes'></div></div>
<div class='card'><div class='card-head'><div><h2>📥 创建接收链接</h2>
<p class='muted'>把链接发给对方，对方打开网页上传文件，文件会存到你的服务器上。</p></div></div>
<form id='recvForm'>
<input type='text' name='title' placeholder='备注（可选，如：请小王传合同）' maxlength='100' aria-label='备注'>
<select name='expiry' aria-label='有效期'>{_EXPIRY_OPTIONS}</select>
<button>{icon('open')}生成接收链接</button></form><div id='recvRes'></div></div>
</div>
<div class='card'><div class='card-head'><h2>{share_title}</h2><span class='muted'>{len(shares)} 个</span></div>{lst}</div>
<div class='card'><div class='card-head'><div><h2>{file_title}</h2>
<p class='muted'>{filehint}</p></div></div>
{tools}
{flist}
<div id='fileRes'></div></div>
<div class='grid2'>{users_card}<div class='card'><h2>🔑 修改密码</h2>
<p class='muted'>修改后，其他设备上的登录会失效。</p>
<form id='pwForm'>
<input type='password' name='new1' placeholder='新密码' required minlength='4' autocomplete='new-password' aria-label='新密码'>
<input type='password' name='new2' placeholder='重复新密码' required minlength='4' autocomplete='new-password' aria-label='重复新密码'>
<button class='ghost' style='width:100%'>修改密码</button></form><div id='pwRes'></div></div></div>
<script>
""" + CHUNK_JS + UI_JS + DASH_JS + f"""
var _UPW={upw_json};
var PUBLIC_BASE = {pub_js};
function fullLink(p){{
  // 有已识别的 https 根地址就用它；没有就保持原来的自动识别：跟地址栏走。
  if (/^https?:\\/\\//i.test(p)) return p;
  var b = PUBLIC_BASE || location.origin;
  return String(b).replace(/\\/$/, "") + p;
}}
function fillShareLinks(){{
  var boxes = document.querySelectorAll("div.linkbox[id^='lk-']"), i;
  for (i = 0; i < boxes.length; i++) boxes[i].textContent = fullLink(boxes[i].textContent.trim());
}}
fillShareLinks();
function copyText(t, box){{
  // 剪贴板 API 只在安全上下文（HTTPS / localhost）可用；默认用
  // http://IP:端口 打开时 navigator.clipboard 是 undefined，
  // 直接调用会抛 TypeError，按钮点了没任何反应。先判断再调，
  // 不可用时明确告诉用户手动复制，链接一直可见。
  function fail(){{
    box.innerHTML = '<span class="err">浏览器不允许自动复制，请手动复制：</span>'
      + '<div class="linkbox">' + t + '</div>';
  }}
  if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(t).then(function(){{
      box.innerHTML = '<span class="ok">已复制到剪贴板</span>';
    }}, fail);
  }} else {{ fail(); }}
}}
function copyLink(id, p){{
  var el = document.getElementById('lk-'+id);
  var t = fullLink(p);
  el.textContent = t;
  copyText(t, el);
}}
function delShare(id){{
  if(!confirm('确定删除这个分享链接吗？文件会保留，可在「全部文件」里手动删除。')) return;
  apiPost('/api/delete','id='+encodeURIComponent(id));
}}
function toggleAllFiles(){{
  var cks=document.querySelectorAll('.fileck'), all=true, i;
  for(i=0;i<cks.length;i++){{if(!cks[i].checked)all=false;}}
  for(i=0;i<cks.length;i++){{cks[i].checked=!all;}}
}}
function delOneFile(id){{delFilesByIds([id]);}}
function delFiles(){{
  var ids=[], cks=document.querySelectorAll('.fileck:checked'), i;
  for(i=0;i<cks.length;i++){{ids.push(cks[i].value);}}
  if(!ids.length){{alert('请先勾选要删除的文件');return;}}
  delFilesByIds(ids);
}}
function delFilesByIds(ids){{
  if(!confirm('确定彻底删除选中的 '+ids.length+' 个文件吗？删除后无法恢复。'))return;
  apiPost('/api/del_files','ids='+encodeURIComponent(ids.join(',')));
}}
function editExpiry(id){{
  var box=document.getElementById('ex-'+id);
  box.innerHTML='';
  var sel=document.createElement('select'); sel.id='exs-'+id;
  [['1','1 天后过期'],['7','7 天后过期'],['30','30 天后过期'],
   ['0','永久有效']].forEach(function(item){{
    var opt=document.createElement('option'); opt.value=item[0];
    opt.textContent=item[1]; sel.appendChild(opt);
  }});
  sel.value='7';
  var ok=document.createElement('button'); ok.className='ghost';
  ok.textContent='确定'; ok.onclick=function(){{saveExpiry(id);}};
  var no=document.createElement('button'); no.className='ghost';
  no.textContent='取消'; no.onclick=function(){{cancelExpiry(id);}};
  box.appendChild(sel); box.appendChild(document.createTextNode(' '));
  box.appendChild(ok); box.appendChild(document.createTextNode(' '));
  box.appendChild(no);
}}
function cancelExpiry(id){{document.getElementById('ex-'+id).innerHTML="";}}
function editTitle(id){{
  var box=document.getElementById('ti-'+id);
  box.innerHTML='';
  var cur=document.getElementById('ttl-'+id).textContent;
  if(cur=='(无备注)')cur='';
  var inp=document.createElement('input');
  inp.id='tin-'+id;inp.maxLength=100;inp.style.width='60%';inp.value=cur;
  inp.placeholder='输入备注名，留空则清除';
  var ok=document.createElement('button');ok.className='ghost';ok.textContent='确定';
  ok.onclick=function(){{saveTitle(id);}};
  var no=document.createElement('button');no.className='ghost';no.textContent='取消';
  no.onclick=function(){{cancelTitle(id);}};
  box.appendChild(inp);box.appendChild(document.createTextNode(' '));
  box.appendChild(ok);box.appendChild(document.createTextNode(' '));box.appendChild(no);
  inp.focus();
}}
function cancelTitle(id){{document.getElementById('ti-'+id).innerHTML='';}}
function saveTitle(id){{
  var v=document.getElementById('tin-'+id).value.trim();
  apiPost('/api/title','id='+encodeURIComponent(id)+'&title='+encodeURIComponent(v));
}}
function saveExpiry(id){{
  var v=document.getElementById('exs-'+id).value;
  apiPost('/api/expiry','id='+encodeURIComponent(id)+'&expiry='+encodeURIComponent(v));
}}
function bindXhr(fid, url, resId, progId, okText){{
  var f=document.getElementById(fid);
  f.addEventListener('submit', function(ev){{
    ev.preventDefault();
    var res=document.getElementById(resId), prog=document.getElementById(progId);
    res.innerHTML=''; if(prog){{prog.style.display='block';prog.value=0;}}
    var xhr=new XMLHttpRequest(); xhr.open('POST', url);
    xhr.upload.onprogress=function(e){{if(e.lengthComputable&&prog)prog.value=e.loaded/e.total*100;}};
    xhr.onload=function(){{
      if(prog)prog.style.display='none';
      try{{var j=JSON.parse(xhr.responseText);
        if(j.ok){{res.innerHTML="<div class='ok'>"+okText+"</div><div class='linkbox'>"+fullLink(j.link)+"</div><button class='ghost' onclick='copyText(this.previousElementSibling.textContent,this.previousElementSibling)'>复制链接</button>";
          setTimeout(()=>location.reload(), 1500);
        }}else{{res.innerHTML="<div class='err'>"+(j.error||'失败')+"</div>";}}
      }}catch(e){{res.innerHTML="<div class='err'>请求失败("+xhr.status+")</div>";}}
    }};
    xhr.onerror=function(){{if(prog)prog.style.display='none';res.innerHTML="<div class='err'>网络错误</div>";}};
    xhr.send(new FormData(f));
  }});
}}
bindXhr('recvForm','/api/receive','recvRes',null,'接收链接已生成：');
// 控制台“发送文件”走分片上传：先建分享拿 sid，再把文件一片片传上去。
// 大文件不再整文件一次 POST，不会被反代掐（请求失败(522)），
// 还有实时百分比和“上传完成”提示。
document.getElementById('sendForm').addEventListener('submit', function(ev){{
  ev.preventDefault();
  var form=ev.target, res=document.getElementById('sendRes'),
      prog=document.getElementById('sendProg'), pct=document.getElementById('sendPct'),
      stat=document.getElementById('sendStat'), btn=document.getElementById('sendBtn'),
      wrap=document.getElementById('sendProgWrap');
  var files=form.querySelector("input[type=file]").files;
  if(!files.length) return;
  res.innerHTML=''; btn.disabled=true;
  wrap.style.display='flex'; prog.value=0; pct.textContent='0%';
  stat.textContent='创建分享…';
  var title=form.querySelector("input[name=title]").value,
      expiry=form.querySelector("select[name=expiry]").value,
      createdLink=null;
  fetch('/api/share_create',{{method:'POST',
    headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
    body:'title='+encodeURIComponent(title)+'&expiry='+encodeURIComponent(expiry)}})
  .then(function(r){{return r.json().then(function(j){{return {{s:r.status,j:j}};}});}})
  .then(function(x){{
    if(!x.j.ok) throw new Error(x.j.error||('请求失败('+x.s+')'));
    stat.textContent='准备上传…';
    createdLink=x.j.link;
    return chunkUpload({{sid:x.j.id, kind:'add'}}, files,
      {{prog:prog, pct:pct, stat:stat}}).then(function(){{return x.j.link;}});
  }})
  .then(function(link){{
    prog.value=100; pct.textContent='100%';
    stat.innerHTML="<b style='color:var(--ok)'>上传完成 ✅</b>";
    res.innerHTML="<div class='ok'>上传成功，分享链接：</div><div class='linkbox'>"+fullLink(link)+"</div><button class='ghost' onclick='copyText(this.previousElementSibling.textContent,this.previousElementSibling)'>复制链接</button>";
    setTimeout(()=>location.reload(), 1500);
  }})
  .catch(function(err){{
    btn.disabled=false; stat.textContent='';
    var html="<div class='err'>"+escapeHtml(err.message||'失败')+"</div>";
    if(createdLink){{
      html+="<div class='ok'>已上传的文件已保留，分享链接：</div><div class='linkbox'>"
        +fullLink(createdLink)+"</div><button class='ghost' onclick='copyText(this.previousElementSibling.textContent,this.previousElementSibling)'>复制链接</button>";
    }}
    res.innerHTML=html;
  }});
}});
// 表单 POST 通用封装：手动拼 application/x-www-form-urlencoded，
// 不依赖 new FormData 迭代；提交时按钮禁用并显示“处理中”，
// 任何失败（HTTP 错误、返回非 JSON、网络错误）都在页面上明确提示，
// 不会“点了没反应”。
function postForm(url, form, resId, okHtml){{
  var res=document.getElementById(resId);
  var btn=form.querySelector('button');
  var parts=[], els=form.elements, i, el;
  for(i=0;i<els.length;i++){{
    el=els[i];
    if(!el.name||el.disabled)continue;
    if((el.type=='checkbox'||el.type=='radio')&&!el.checked)continue;
    parts.push(encodeURIComponent(el.name)+'='+encodeURIComponent(el.value));
  }}
  var oldT=btn?btn.textContent:'';
  if(btn){{btn.disabled=true;btn.textContent='处理中…';}}
  res.innerHTML="<div class='muted'>处理中…</div>";
  return fetch(url,{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
    body:parts.join('&')}})
  .then(function(r){{
    // 先读文本：HTTP 错误时也尽量把服务端返回的 error 文案展示出来，
    // 而不是只显示一个干巴巴的 HTTP 状态码。
    return r.text().then(function(t){{
      var j=null;try{{j=JSON.parse(t);}}catch(e){{}}
      if(!r.ok)throw new Error((j&&j.error)||('HTTP '+r.status));
      if(!j)throw new Error('服务器返回异常');
      return j;
    }});
  }})
  .then(function(j){{
    if(j.ok){{res.innerHTML=okHtml;}}
    else{{res.innerHTML="<div class='err'>"+(j.error||'失败')+"</div>";}}
    return j;
  }})
  .catch(function(e){{
    res.innerHTML="<div class='err'>请求失败："+(e&&e.message?e.message:'网络错误')+"</div>";
    return {{ok:false}};
  }})
  .then(function(j){{
    if(btn){{btn.disabled=false;btn.textContent=oldT;}}
    return j;
  }});
}}
// 简单 POST 通用封装（删分享/删文件/改备注/改过期/用户管理等操作）：
// 任何失败（HTTP 错误、返回非 JSON、网络错误）都弹明确提示，
// 不会“点了没反应”。成功则刷新页面。
function apiPost(url, body){{
  return fetch(url,{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
    body:body}})
  .then(function(r){{
    // 先读文本：HTTP 错误时也尽量把服务端返回的 error 文案展示出来，
    // 而不是只显示一个干巴巴的 HTTP 状态码。
    return r.text().then(function(t){{
      var j=null;try{{j=JSON.parse(t);}}catch(e){{}}
      if(!r.ok)throw new Error((j&&j.error)||('HTTP '+r.status));
      if(!j)throw new Error('服务器返回异常');
      return j;
    }});
  }})
  .then(function(j){{
    if(j.ok){{location.reload();}}
    else{{alert('操作失败：'+(j.error||'未知错误'));}}
  }})
  .catch(function(e){{
    alert('请求失败：'+(e&&e.message?e.message:'网络错误')+'，请检查网络后重试');
  }});
}}
document.getElementById('pwForm').addEventListener('submit', function(ev){{
  ev.preventDefault();
  postForm('/api/chpw', this, 'pwRes', "<div class='ok'>密码已修改</div>");
}});
function userDel(id){{
  if(!confirm('确定删除这个用户吗？他的分享链接会失效，文件会保留在「全部文件」里。'))return;
  apiPost('/api/user_del','id='+encodeURIComponent(id));
}}
function resetPw(id){{
  var box=document.getElementById('urp-'+id);
  box.innerHTML='';
  var a=document.createElement('input'); a.type='password'; a.id='rp1-'+id;
  a.placeholder='新密码'; a.minLength=4;
  var b=document.createElement('input'); b.type='password'; b.id='rp2-'+id;
  b.placeholder='再次输入'; b.minLength=4;
  var ok=document.createElement('button'); ok.className='ghost';
  ok.textContent='确定'; ok.onclick=function(){{saveResetPw(id);}};
  var no=document.createElement('button'); no.className='ghost';
  no.textContent='取消'; no.onclick=function(){{cancelResetPw(id);}};
  [a,b,ok,no].forEach(function(el){{box.appendChild(el); box.appendChild(document.createTextNode(' '));}});
}}
function cancelResetPw(id){{document.getElementById('urp-'+id).innerHTML='';}}
function saveResetPw(id){{
  var a=document.getElementById('rp1-'+id).value, b=document.getElementById('rp2-'+id).value;
  apiPost('/api/user_resetpw','id='+encodeURIComponent(id)+'&pw1='+encodeURIComponent(a)+'&pw2='+encodeURIComponent(b));
}}
// 备注名：只给管理员自己看（比如这个账号给了谁），不影响登录（登录只认密码）。
function editRemark(id){{
  var box=document.getElementById('urm-'+id);
  box.innerHTML='';
  var cur=document.getElementById('rmk-'+id);
  cur=cur?cur.textContent:'';
  var inp=document.createElement('input');
  inp.id='rmi-'+id; inp.maxLength=50; inp.style.width='60%';
  inp.placeholder='备注名，如：张三（留空则清除）'; inp.value=cur;
  var ok=document.createElement('button'); ok.className='ghost'; ok.textContent='确定';
  ok.onclick=function(){{saveRemark(id);}};
  var no=document.createElement('button'); no.className='ghost'; no.textContent='取消';
  no.onclick=function(){{cancelRemark(id);}};
  box.appendChild(inp); box.appendChild(document.createTextNode(' '));
  box.appendChild(ok); box.appendChild(document.createTextNode(' ')); box.appendChild(no);
  inp.focus();
}}
function cancelRemark(id){{document.getElementById('urm-'+id).innerHTML='';}}
function saveRemark(id){{
  var v=document.getElementById('rmi-'+id).value.trim();
  apiPost('/api/user_remark','id='+encodeURIComponent(id)+'&remark='+encodeURIComponent(v));
}}
// 眼睛：管理员查看某个账号的当前密码。只在管理员的"用户管理"里有这个按钮，
// 普通用户登录后根本看不到这一整块，所以用户本人不会知道。
function togglePw(id, btn){{
  var box=document.getElementById('upw-'+id);
  if(box.dataset.open==='1'){{box.innerHTML='';box.dataset.open='';btn.textContent='👁';return;}}
  // 密码已随页面下发（var _UPW），本地直接显示，不发请求，点开即现
  var pw=(_UPW||{{}})[String(id)];
  box.dataset.open='1'; btn.textContent='👁‍🗨';
  box.innerHTML='';
  var t=document.createElement('span');
  t.className='muted'; t.textContent='密码：';
  var b=document.createElement('b');
  b.textContent=pw||'（老账号，明文未知，改一次密码后可见）';
  var cp=document.createElement('button');
  cp.className='ghost'; cp.textContent='复制'; cp.style.marginLeft='8px';
  cp.onclick=function(){{
    var done=function(){{cp.textContent='已复制';}};
    if(navigator.clipboard&&navigator.clipboard.writeText){{
      navigator.clipboard.writeText(pw).then(done,function(){{cp.textContent='复制失败';}});
    }}else{{
      var ta=document.createElement('textarea');ta.value=pw;document.body.appendChild(ta);
      ta.select();try{{document.execCommand('copy');done();}}catch(e){{cp.textContent='复制失败';}}
      document.body.removeChild(ta);
    }}
  }};
  box.appendChild(t); box.appendChild(b);
  if(pw)box.appendChild(cp);
}}
var _uaf=document.getElementById('userAddForm');
if(_uaf){{_uaf.addEventListener('submit', function(ev){{
  ev.preventDefault();
  postForm('/api/user_add', this, 'userRes', "<div class='ok'>用户已添加，记得把密码告诉他</div>")
  .then(function(j){{if(j.ok)setTimeout(function(){{location.reload();}},1200);}});
}});}}
</script>{disk_foot()}""")

# 上传区域的小交互：显示已选文件名/总大小、拖拽高亮。三个上传入口共用。
UI_JS = r"""
function fmtSize(n){var u=['B','KB','MB','GB','TB'],i=0;n=+n||0;while(n>=1024&&i<u.length-1){n/=1024;i++;}return i?n.toFixed(1)+u[i]:n+'B';}
function bindDrop(input){
  var zone=input.closest('.drop'); if(!zone) return;
  var label=zone.querySelector('.drop-files');
  function show(){
    var fs=input.files||[], n=fs.length, t=0, names=[], i;
    for(i=0;i<n;i++){t+=fs[i].size; if(i<3) names.push(fs[i].name);}
    zone.classList.toggle('has', n>0);
    label.textContent=n?('已选择 '+n+' 个文件（'+fmtSize(t)+'）：'+names.join('、')+(n>3?' 等':'')):'';
  }
  input.addEventListener('change', show);
  ['dragenter','dragover'].forEach(function(t){zone.addEventListener(t,function(){zone.classList.add('over');});});
  ['dragleave','drop'].forEach(function(t){zone.addEventListener(t,function(){zone.classList.remove('over');setTimeout(show,0);});});
  if(input.form) input.form.addEventListener('reset', function(){setTimeout(show,0);});
}
Array.prototype.forEach.call(document.querySelectorAll('.drop input[type=file]'), bindDrop);
"""

# 控制台“全部文件”的本地搜索（只过滤已渲染的行，不发请求）。
DASH_JS = r"""
(function(){
  var q=document.getElementById('fileSearch'); if(!q) return;
  q.addEventListener('input', function(){
    var v=q.value.trim().toLocaleLowerCase(), rows=document.querySelectorAll('#fileTable .frow'), shown=0, i;
    for(i=0;i<rows.length;i++){
      var hit=!v||rows[i].textContent.toLocaleLowerCase().indexOf(v)>=0;
      rows[i].style.display=hit?'':'none'; if(hit) shown++;
    }
    document.getElementById('fileNoMatch').hidden=shown>0;
  });
})();
"""

# 分享页“查看”：页面上不预先加载任何媒体，点了“查看”才在弹层里创建
# 图片/视频/音频/PDF/文本预览元素。Esc 或返回键关闭，左右键切换文件。
PREVIEW_JS = r"""
(function(){
  var items=Array.prototype.slice.call(document.querySelectorAll('.btn-view'));
  var pv=document.getElementById('pv'); if(!pv||!items.length) return;
  var stage=document.getElementById('pvStage'), nameEl=document.getElementById('pvName'),
      metaEl=document.getElementById('pvMeta'), openA=document.getElementById('pvOpen'),
      dlA=document.getElementById('pvDl'), closeB=document.getElementById('pvClose'),
      prevB=document.getElementById('pvPrev'), nextB=document.getElementById('pvNext'),
      countEl=document.getElementById('pvCount');
  var cur=-1, pushed=false, lastFocus=null, token=0, TEXT_LIMIT=1024*1024, tx=null;
  function el(tag, cls, text){var e=document.createElement(tag); if(cls) e.className=cls; if(text!=null) e.textContent=text; return e;}
  function clear(){
    token++;
    var m=stage.querySelectorAll('video,audio'), i;
    for(i=0;i<m.length;i++){try{m[i].pause();}catch(e){} m[i].removeAttribute('src'); try{m[i].load();}catch(e){}}
    stage.classList.remove('zoom'); stage.textContent='';
  }
  function spinner(){var s=el('div','pv-spin'); s.setAttribute('role','status'); s.setAttribute('aria-label','加载中'); stage.appendChild(s); return s;}
  function fail(text){
    stage.textContent='';
    var box=el('div','pv-msg'); box.appendChild(el('div','',text));
    var a=el('a','btn','下载文件'); a.href=items[cur].dataset.dl; a.setAttribute('download',''); box.appendChild(a);
    var o=el('a','btn ghost','新窗口打开'); o.href=items[cur].dataset.src; o.target='_blank'; o.rel='noopener'; box.appendChild(o);
    stage.appendChild(box);
  }
  function decode(buf, truncated){
    var u8=new Uint8Array(buf);
    try{return new TextDecoder('utf-8',{fatal:true}).decode(u8,{stream:truncated});}catch(e){}
    try{return new TextDecoder('gb18030').decode(u8);}catch(e){}
    return new TextDecoder('utf-8').decode(u8);
  }
  function render(i){
    clear(); cur=i;
    var b=items[i], kind=b.dataset.kind, src=b.dataset.src, name=b.dataset.name, my=token;
    nameEl.textContent=name; metaEl.textContent=b.dataset.meta||'';
    openA.href=src; dlA.href=b.dataset.dl;
    prevB.hidden=nextB.hidden=items.length<2;
    countEl.textContent=items.length>1?(i+1)+' / '+items.length:'';
    pv.setAttribute('data-kind', kind);
    if(kind==='img'){
      var sp=spinner(), img=new Image();
      img.alt=name; img.decoding='async';
      img.onload=function(){if(my!==token)return; sp.remove(); stage.appendChild(img);};
      img.onerror=function(){if(my!==token)return; fail('图片加载失败，可以下载后查看。');};
      img.addEventListener('click', function(){stage.classList.toggle('zoom');});
      img.src=src;
    }else if(kind==='vid'){
      var v=document.createElement('video');
      v.controls=true; v.playsInline=true; v.setAttribute('playsinline',''); v.setAttribute('webkit-playsinline','');
      v.preload='metadata';
      v.onerror=function(){if(my!==token)return; fail('浏览器无法播放这个视频格式（常见于 MKV/AVI/HEVC），可以下载后用播放器打开。');};
      v.src=src; stage.appendChild(v);
      var p=v.play(); if(p&&p.catch) p.catch(function(){});
    }else if(kind==='aud'){
      var box=el('div','pv-audio');
      box.innerHTML='<svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>';
      box.appendChild(el('div','',name));
      var a=document.createElement('audio'); a.controls=true; a.preload='metadata';
      a.onerror=function(){if(my!==token)return; fail('浏览器无法播放这个音频格式，可以下载后播放。');};
      a.src=src; box.appendChild(a); stage.appendChild(box);
      var pa=a.play(); if(pa&&pa.catch) pa.catch(function(){});
    }else if(kind==='pdf'){
      if(navigator.pdfViewerEnabled===false||(navigator.pdfViewerEnabled===undefined&&/Android|iPhone|iPad|Mobile/i.test(navigator.userAgent))){
        fail('这个浏览器不能在页面内显示 PDF，请点“新窗口打开”或下载。');
      }else{
        var f=document.createElement('iframe'); f.title=name; f.src=src; stage.appendChild(f);
      }
    }else if(kind==='txt'){
      var sp2=spinner();
      fetch(src,{headers:{'Range':'bytes=0-'+(TEXT_LIMIT-1)}}).then(function(r){
        if(r.status===416) return {buf:new ArrayBuffer(0),total:0};  // 空文件
        if(!r.ok) throw new Error('HTTP '+r.status);
        var total=0, cr=r.headers.get('Content-Range');
        if(cr){var m=/\/(\d+)$/.exec(cr); if(m) total=+m[1];}
        return r.arrayBuffer().then(function(buf){return {buf:buf,total:total};});
      }).then(function(x){
        if(my!==token) return;
        var cut=x.total>x.buf.byteLength;
        sp2.remove();
        var pre=el('pre','', decode(x.buf, cut)+(cut?'\n\n…… 文件较大，只显示前 1MB，完整内容请下载。':''));
        pre.tabIndex=0; stage.appendChild(pre);
      }).catch(function(){if(my!==token)return; fail('文本加载失败，可以下载后查看。');});
    }else{
      fail('这个文件不支持在线查看。');
    }
  }
  function focusables(){return Array.prototype.filter.call(pv.querySelectorAll('a[href],button,video,audio,iframe,pre'),function(e){return !e.hidden&&e.offsetParent!==null;});}
  function open(i){
    lastFocus=document.activeElement;
    pv.hidden=false; document.documentElement.classList.add('pv-lock');
    render(i);
    if(!pushed){try{history.pushState({pv:1},''); pushed=true;}catch(e){}}
    closeB.focus();
  }
  function hide(){
    clear(); cur=-1; pv.hidden=true; document.documentElement.classList.remove('pv-lock');
    if(lastFocus&&lastFocus.focus) lastFocus.focus();
  }
  function close(){ if(pushed){history.back();} else {hide();} }
  function step(d){ if(items.length>1&&cur>=0) render((cur+d+items.length)%items.length); }
  window.addEventListener('popstate', function(){ if(pushed){pushed=false; hide();} });
  items.forEach(function(b,i){ b.addEventListener('click', function(ev){ev.preventDefault(); open(i);}); });
  closeB.addEventListener('click', close);
  prevB.addEventListener('click', function(){step(-1);});
  nextB.addEventListener('click', function(){step(1);});
  stage.addEventListener('click', function(ev){ if(ev.target===stage) close(); });
  document.addEventListener('keydown', function(ev){
    if(pv.hidden) return;
    if(ev.key==='Escape'){ev.preventDefault(); close(); return;}
    var t=ev.target&&ev.target.tagName;
    if(t!=='VIDEO'&&t!=='AUDIO'&&t!=='PRE'){
      if(ev.key==='ArrowLeft'){ev.preventDefault(); step(-1); return;}
      if(ev.key==='ArrowRight'){ev.preventDefault(); step(1); return;}
    }
    if(ev.key==='Tab'){
      var f=focusables(); if(!f.length) return;
      var first=f[0], last=f[f.length-1];
      if(ev.shiftKey&&document.activeElement===first){ev.preventDefault(); last.focus();}
      else if(!ev.shiftKey&&document.activeElement===last){ev.preventDefault(); first.focus();}
    }
  });
  stage.addEventListener('touchstart', function(e){ tx=(e.touches.length===1&&pv.getAttribute('data-kind')==='img'&&!stage.classList.contains('zoom'))?e.touches[0].clientX:null; }, {passive:true});
  stage.addEventListener('touchend', function(e){ if(tx===null) return; var dx=e.changedTouches[0].clientX-tx; tx=null; if(Math.abs(dx)>50) step(dx<0?1:-1); });
})();
"""

# 能安全在线查看的文件类型（按扩展名判断）。
# svg 故意不算图片：内联打开时 SVG 里的脚本会在本站域名下执行，有风险，只给下载。
# html 同理只给下载。pdf：浏览器自带的 PDF 阅读器打开是安全的（不会执行页面脚本）。
# 文本：按 text/plain 返回，由页面脚本读出来放进 <pre> 里显示，不会被当成网页执行。
IMG_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".avif"}
VID_EXTS = {".mp4", ".webm", ".ogg", ".ogv", ".mov", ".m4v", ".mkv"}
AUD_EXTS = {".mp3", ".m4a", ".aac", ".wav", ".flac", ".oga", ".opus"}
PDF_EXTS = {".pdf"}
TXT_EXTS = {".txt", ".md", ".markdown", ".log", ".csv", ".tsv", ".json", ".yaml", ".yml",
            ".ini", ".conf", ".cfg", ".toml", ".srt", ".vtt", ".lrc", ".py", ".js", ".ts",
            ".css", ".sh", ".bat", ".ps1", ".c", ".h", ".cpp", ".hpp", ".java", ".go",
            ".rs", ".rb", ".php", ".sql", ".diff", ".patch"}
TEXT_PREVIEW_LIMIT = 1024 * 1024

def _view_kind(filename):
    """返回 'img' / 'vid' / 'aud' / 'pdf' / 'txt'，不能在线查看的返回 None。"""
    ext = os.path.splitext(filename)[1].lower()
    if ext in IMG_EXTS:
        return "img"
    if ext in VID_EXTS:
        return "vid"
    if ext in AUD_EXTS:
        return "aud"
    if ext in PDF_EXTS:
        return "pdf"
    if ext in TXT_EXTS:
        return "txt"
    return None

_KIND_ICON = {"img": "image", "vid": "film", "aud": "music", "pdf": "file", "txt": "text"}

def _preview_modal():
    return f"""<div class='pv' id='pv' hidden role='dialog' aria-modal='true' aria-labelledby='pvName'>
<div class='pv-bar'><div class='pv-title'><div class='pv-name' id='pvName'></div><div class='pv-meta' id='pvMeta'></div></div>
<a class='btn pv-btn' id='pvOpen' href='#' target='_blank' rel='noopener' title='在新窗口打开'>{icon('external')}<span class='lbl'>新窗口</span></a>
<a class='btn pv-btn' id='pvDl' href='#' download title='下载'>{icon('download')}<span class='lbl'>下载</span></a>
<button type='button' class='pv-btn icon-only' id='pvClose' aria-label='关闭预览（Esc）' title='关闭（Esc）'>{icon('x')}</button></div>
<div class='pv-body'><div class='pv-stage' id='pvStage'></div>
<button type='button' class='pv-nav pv-prev' id='pvPrev' aria-label='上一个'>{icon('left')}</button>
<button type='button' class='pv-nav pv-next' id='pvNext' aria-label='下一个'>{icon('right')}</button>
<div class='pv-count' id='pvCount'></div></div></div>"""

def _looks_utf8(path):
    """文本预览的编码判断：开头 64KB 是合法 UTF-8 就声明 utf-8，否则不声明，让浏览器自己猜。"""
    try:
        with open(path, "rb") as f:
            data = f.read(65536)
    except OSError:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError as e:
        # 只是在 64KB 边界切断了一个多字节字符
        return len(data) == 65536 and e.start >= len(data) - 3

def share_page(sid, share, files, user=None):
    # user 能管理这个分享（本人或管理员）时，页面上可以追加和删除文件
    manage = user is not None and can_manage_share(user, share)
    rows = []
    pinned_flags = [bool(dict(f).get("pinned", 0)) for f in files]
    total = 0
    for index, f in enumerate(files):
        fd = dict(f)
        total += fd.get("size") or 0
        name = html.escape(f["filename"])
        kind = _view_kind(f["filename"])
        ext = os.path.splitext(f["filename"])[1][1:5]
        meta = hsize(fd.get("size")) + (f" · {htime(fd['created'])}" if fd.get("created") else "")
        dl = f"/s/{sid}/f/{f['id']}"
        # 图片和视频都不在页面里直接内联显示：没点"查看"就不加载任何媒体内容。
        # 点"查看"由 PREVIEW_JS 在弹层里创建预览元素。
        view_btn = ""
        if kind:
            view_btn = (f"<button type='button' class='btn-view' data-kind='{kind}' "
                        f"data-src='/s/{sid}/v/{f['id']}' data-dl='{dl}' data-name='{name}' "
                        f"data-meta='{html.escape(meta)}' aria-label='查看 {name}'>"
                        f"{icon('play' if kind in ('vid', 'aud') else 'eye')}查看</button>")
        dl_cls = "btn ghost" if kind else "btn"
        dl_btn = (f"<a class='{dl_cls}' href='{dl}' download aria-label='下载 {name}'>"
                  f"{icon('download')}下载</a>")
        badge = " <span class='badge pin'>📌 置顶</span>" if pinned_flags[index] else ""
        tile = (f"<div class='ftile k-{kind or 'other'}' aria-hidden='true'>"
                f"{icon(_KIND_ICON.get(kind, 'file'))}<span>{html.escape(ext)}</span></div>")
        manage_row = ""
        if manage:
            action, label = ("unpin", "取消置顶") if pinned_flags[index] else ("pin", "置顶")
            up_disabled = " disabled" if index == 0 or pinned_flags[index-1] != pinned_flags[index] else ""
            down_disabled = " disabled" if index == len(files)-1 or pinned_flags[index+1] != pinned_flags[index] else ""
            manage_row = f"""<div class='sf-manage'>
<button class='ghost sm order-btn'{up_disabled} onclick='arrangeFile({f['id']},"up")' aria-label='上移 {name}'>{icon('up')}上移</button>
<button class='ghost sm order-btn'{down_disabled} onclick='arrangeFile({f['id']},"down")' aria-label='下移 {name}'>{icon('down')}下移</button>
<button class='ghost sm order-btn' onclick='arrangeFile({f['id']},"{action}")'>{icon('pin')}{label}</button>
<button class='danger sm' onclick='delShareFile({f['id']},this)'>{icon('trash')}删除</button></div>"""
        rows.append(f"""<div class='sf' id='file-{f['id']}'><div class='sf-main'>{tile}
<div class='sf-info'><div class='sf-name'>{name}{badge}</div><div class='muted sf-meta'>{meta}</div></div></div>
<div class='sf-acts'>{view_btn}{dl_btn}</div>{manage_row}</div>""")
    add_form = ""
    if manage:
        candidates = []
        for f in all_files(user):
            if f["share_id"] == sid:
                continue
            owner = (f" · 用户#{f['owner_id']}" if user["is_admin"] and
                     f["owner_id"] != user["id"] else "")
            candidates.append(f"<label class='file existing-file'><input type='checkbox' "
                              f"value='{f['id']}'> <span>📄 {html.escape(f['filename'])}"
                              f"<small class='muted'> · {hsize(f['size'])}{owner}</small>"
                              "</span></label>")
        existing_picker = ("""<details><summary>从全部文件中添加</summary>
<p class='muted'>选择已上传的文件，原分享中的文件仍会保留。</p>
<input id='existingSearch' type='search' placeholder='搜索文件名' aria-label='搜索文件名'>
<div id='existingList' style='max-height:300px;overflow:auto'>""" +
                           "".join(candidates) + """</div>
<button id='existingBtn' class='ghost block' type='button'>添加选中文件</button>
<div id='existingRes' class='muted'></div></details>""" if candidates else
                           "<p class='muted' style='margin-top:12px'>全部文件中暂无其他可添加的文件</p>")
        add_form = ("""<div class='card'>
<h2>➕ 添加文件</h2><p class='muted'>只有你（分享者或管理员）能看到这一块。</p>
<form id='addForm'>""" + _drop_zone("name='file' multiple required") + """
<button id='addBtn'>""" + icon('upload') + """上传</button>
<div id='addProgWrap' class='prog' style='display:none'><progress id='addProg' value='0' max='100'></progress>
 <span id='addPct' class='muted'>0%</span></div>
<div id='addStat' class='muted'></div></form>
<div id='addRes'></div>""" + existing_picker + """</div>
<script>
var arrangingFile=false;
function arrangeFile(fid, action){
  if(arrangingFile)return;
  arrangingFile=true;
  var buttons=Array.from(document.querySelectorAll('.order-btn'));
  var states=buttons.map(function(b){return b.disabled;});
  buttons.forEach(function(b){b.disabled=true;});
  var status=document.getElementById('orderStatus');
  status.textContent='正在保存…';
  fetch('/api/share_file_order',{method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'sid='+encodeURIComponent('""" + sid + """')+'&id='+fid+'&action='+action})
  .then(function(r){return r.json().then(function(j){
    if(!r.ok||!j.ok)throw new Error(j.error||'保存失败');
  });})
  .then(function(){location.hash='file-'+fid;location.reload();})
  .catch(function(e){
    status.textContent='保存失败：'+(e.message||'网络错误')+'，请刷新页面确认后重试';
    buttons.forEach(function(b,i){b.disabled=states[i];});
    arrangingFile=false;
  });
}
function delShareFile(fid, el){
  if(!confirm('确定删除这个文件吗？')) return;
  el.disabled = true;
  fetch('/api/share_file_del', {method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'sid='+encodeURIComponent('""" + sid + """')+'&id='+fid})
  .then(function(r){return r.json();})
  .then(function(j){
    if(j.ok) location.reload();
    else { el.disabled = false; alert(j.error || '删除失败'); }
  })
  .catch(function(){ el.disabled = false; alert('请求失败'); });
}
""" + CHUNK_JS + UI_JS + """
var existingSearch=document.getElementById('existingSearch');
if(existingSearch){
  existingSearch.addEventListener('input',function(){
    var q=this.value.trim().toLocaleLowerCase();
    document.querySelectorAll('.existing-file').forEach(function(row){
      row.style.display=row.textContent.toLocaleLowerCase().indexOf(q)>=0?'':'none';
    });
  });
  document.getElementById('existingBtn').addEventListener('click',function(){
    var btn=this, res=document.getElementById('existingRes');
    var ids=Array.from(document.querySelectorAll('.existing-file input:checked'))
      .map(function(el){return el.value;});
    if(!ids.length){res.textContent='请先选择文件';return;}
    if(ids.length>200){res.textContent='一次最多添加 200 个文件';return;}
    btn.disabled=true; res.textContent='正在添加…';
    fetch('/api/share_file_existing',{method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'sid='+encodeURIComponent('""" + sid + """')+'&ids='+encodeURIComponent(ids.join(','))})
    .then(function(r){return r.text().then(function(t){
      var j=JSON.parse(t); if(!r.ok||!j.ok)throw new Error(j.error||'添加失败');
      return j;
    });})
    .then(function(){location.reload();})
    .catch(function(e){res.textContent='添加失败：'+(e.message||'网络错误');
      btn.disabled=false;});
  });
}
document.getElementById('addForm').addEventListener('submit', function(ev){
  ev.preventDefault();
  var res=document.getElementById('addRes'), prog=document.getElementById('addProg'),
      pct=document.getElementById('addPct'), stat=document.getElementById('addStat'),
      btn=document.getElementById('addBtn'), wrap=document.getElementById('addProgWrap');
  var files=ev.target.querySelector("input[type=file]").files;
  if(!files.length) return;
  res.innerHTML=''; btn.disabled=true;
  wrap.style.display='flex'; prog.value=0; pct.textContent='0%';
  stat.textContent='准备上传…';
  // 大文件自动分片上传：每片 4MB，单片请求很快完成，不会像以前整文件
  // 一次 POST 那样被反代掐掉（请求失败(522)）；进度条+百分比实时显示。
  chunkUpload({sid:'""" + sid + """', kind:'add'}, files,
    {prog:prog, pct:pct, stat:stat}).then(function(){
      prog.value=100; pct.textContent='100%';
      stat.innerHTML="<b style='color:var(--ok)'>上传完成 ✅</b>";
      setTimeout(function(){location.reload();}, 900);
    }).catch(function(err){
      btn.disabled=false; stat.textContent='';
      res.innerHTML="<div class='err'>"+escapeHtml(err.message||'上传失败')+"</div>";
    });
});
</script>""")
    title = html.escape(share['title'] or '文件分享')
    manage_note = ("<div class='note'>你是这个分享的管理者：可以调整顺序、置顶、删除或添加文件。"
                   "置顶数量不限；上移、下移在各自分组内生效，自动保存。新置顶或取消置顶的文件排到对应组末尾。</div>"
                   "<div id='orderStatus' class='muted' role='status' aria-live='polite' style='margin-top:6px'></div>"
                   if manage else "")
    listing = ("".join(rows) if rows else
               "<div class='empty'><span class='big'>📭</span>文件都被删除啦</div>")
    preview = (_preview_modal() + "<script>" + PREVIEW_JS + "</script>") if rows else ""
    return page("下载文件", f"""<div class='card'><div class='hero'><div class='logo' aria-hidden='true'>📦</div>
<div style='min-width:0'><h1>{title}</h1>
<div class='chips'><span class='chip'>共 <b>{len(files)}</b> 个文件</span><span class='chip'>{hsize(total)}</span>
<span class='chip'>到期：<b>{htime(share['expires'])}</b></span></div></div></div>{manage_note}</div>
<div class='card' style='padding-top:6px;padding-bottom:6px'>{listing}</div>
{add_form}{preview}
<p class='foot'>图片、视频、音频、PDF 和文本可点「查看」在线预览，其他文件请下载。</p>""")

def receive_page(sid, share):
    limit, _ = upload_limit()
    up_script = ("""<script>
""" + CHUNK_JS + UI_JS + """
document.getElementById('upForm').addEventListener('submit', function(ev){
  ev.preventDefault();
  var form=ev.target, res=document.getElementById('res'), prog=document.getElementById('prog'),
      pct=document.getElementById('upPct'), stat=document.getElementById('upStat'),
      btn=document.getElementById('upBtn'), wrap=document.getElementById('upProgWrap');
  var files=form.querySelector("input[type=file]").files;
  if(!files.length) return;
  res.innerHTML=''; btn.disabled=true;
  wrap.style.display='flex'; prog.value=0; pct.textContent='0%';
  stat.textContent='准备上传…';
  // 大文件自动分片上传：每片 4MB，单片请求很快完成，不会像以前整文件
  // 一次 POST 那样被反代掐掉（请求失败(522)）；进度条+百分比实时显示。
  chunkUpload({sid:'""" + sid + """', kind:'upload'}, files,
    {prog:prog, pct:pct, stat:stat}).then(function(){
      prog.value=100; pct.textContent='100%';
      stat.innerHTML="<b style='color:var(--ok)'>上传完成 ✅</b>";
      res.innerHTML="<div class='ok'>上传成功，对方已可收到 ✅ 还可以继续选择文件上传。</div>";
      btn.disabled=false; form.reset();
    }).catch(function(err){
      btn.disabled=false; stat.textContent='';
      res.innerHTML="<div class='err'>"+escapeHtml(err.message||'上传失败')+"</div>";
    });
});
</script>""")
    return page("上传文件", f"""<div class='card'><div class='hero'><div class='logo' aria-hidden='true'>📤</div>
<div style='min-width:0'><h1>{html.escape(share['title'] or '文件接收')}</h1>
<p class='muted' style='margin:0 0 8px'>选择文件上传，上传完成后对方即可收到。</p>
<div class='chips'><span class='chip'>📦最大可上传 <b>{hsize(limit)}</b>文件</span>
<span class='chip'>到期：<b>{htime(share['expires'])}</b></span></div></div></div>
<form id='upForm' style='margin-top:16px'>{_drop_zone("name='file' multiple required")}
<button id='upBtn'>{icon('upload')}开始上传</button>
<div id='upProgWrap' class='prog' style='display:none'><progress id='prog' value='0' max='100'></progress>
 <span id='upPct' class='muted'>0%</span></div>
<div id='upStat' class='muted'></div></form>
<div id='res'></div></div>
""" + up_script)

# 所有文件响应（下载和除 PDF 外的在线查看）都带这个 CSP：即使文件内容是网页
# 或脚本，被浏览器打开时也只能在无来源的沙箱里，不能读写本站数据。
FILE_CSP = "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'"

# HTML 页面的安全头：禁止被别的网站用 iframe 嵌入（防点击劫持），禁止插件，
# 表单只能提交回本站。页面内联脚本较多，脚本来源不做限制。
PAGE_CSP = "frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'"

def content_disposition(kind, filename):
    """带中文文件名的 Content-Disposition。filename* 给现代浏览器；
    filename= 给老客户端一个 ASCII 兜底（非 ASCII 和引号换成 _）。"""
    fallback = "".join(ch if 32 <= ord(ch) < 127 and ch not in '"\\;' else "_"
                       for ch in filename) or "download"
    return "%s; filename=\"%s\"; filename*=UTF-8''%s" % (
        kind, fallback, quote(filename, safe=""))

def not_found():
    return page("不存在", "<div class='auth'><div class='card empty'><span class='big'>😅</span>"
                "<h1>链接不存在或已过期</h1><p class='muted'>请检查链接是否正确，或联系分享者。</p></div></div>", "sm")

def error_page():
    return page("出错", "<div class='auth'><div class='card empty'><span class='big'>😵</span>"
                "<h1>出错了</h1><p class='muted'>服务器处理请求时出错，请稍后重试。</p></div></div>", "sm")

# ---------------- HTTP 服务 ----------------
class Handler(BaseHTTPRequestHandler):
    server_version = "minishare/" + VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def address_string(self):
        # 直接返回客户端 IP，不做反向 DNS 查询：
        # 默认的 address_string() 会查 PTR 记录，某些 IP 查不到时
        # 整个请求会卡在 send_response 之前，客户端一直收不到任何字节
        return self.client_address[0]

    # ---- 小工具 ----
    def _cookie(self):
        c = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                c[k.strip()] = v.strip()
        return c

    def _user(self):
        # 当前登录的账号：{"id","is_admin"}，未登录返回 None
        return session_user(self._cookie().get("sid"))

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        # 页面和接口都是动态内容；控制台页面里还有管理员能看的用户密码，
        # 不让浏览器或中间代理缓存。
        self.send_header("Cache-Control", "no-store")
        if ctype.startswith("text/html"):
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", PAGE_CSP)
            self.send_header("Referrer-Policy", "same-origin")
        if self.close_connection:
            # 出错路径（请求体没读完）会关连接：明确告诉客户端不要复用，
            # 否则它会把残留的请求体当成下一个请求的响应来读。
            self.send_header("Connection", "close")
        self.end_headers()
        if getattr(self, "_head_only", False):
            return
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False),
                   "application/json; charset=utf-8")

    def _fail_close(self, obj, code):
        # 请求体没读完就报错（超大上传/超大表单）：必须关连接，否则残留的
        # 请求体会被当成同一 keep-alive 连接上的下一个 HTTP 请求来解析。
        self.close_connection = True
        return self._json(obj, code)

    def _close_if_body_pending(self):
        # 调用方不打算读请求体时用：如果客户端发了 body，
        # 关掉这个 keep-alive 连接，否则残留的 body 会被当成
        # 同一连接上的下一个 HTTP 请求来解析（实测曾因此返回 501）。
        try:
            pending = int(self.headers.get("Content-Length") or 0) > 0
        except (TypeError, ValueError):
            pending = True
        if pending:
            self.close_connection = True

    def _require_auth(self):
        # API 鉴权：通过返回账号字典；未登录回 401，
        # 且 body 没读时关连接（同 _close_if_body_pending 的道理）。
        user = self._user()
        if user:
            return user
        self._close_if_body_pending()
        self._json({"ok": False, "error": "未登录"}, 401)
        return None

    # ---- 登录限流（防暴力破解）----
    # 登录是"密码即账号"（无用户名），天然是暴力破解目标；而且每次尝试
    # 都要做 20 万轮 pbkdf2，不限流会被拿来烧 CPU。规则：同一 IP 10 分钟
    # 内密码错误超过 20 次，该 IP 的登录请求回 429；登录成功清零。
    _LOGIN_FAIL_LIMIT = 20
    _LOGIN_FAIL_WINDOW = 600

    def _rate_key(self):
        return client_rate_key(self.client_address[0],
                               self.headers.get("CF-Connecting-IP"))

    def _https_request(self):
        # 只有可信反代可以声明这次访问是 https。页面直接用 http://IP 打开时不设 Secure。
        if not trusted_proxy(self.client_address[0]):
            return False
        visitor = self.headers.get("CF-Visitor") or ""
        if re.search(r'"scheme"\s*:\s*"https"', visitor, re.I):
            return True
        proto = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        return proto == "https"

    def _link_base(self):
        return resolve_link_base(self.client_address[0], self.headers.get("Host"),
                                 self.headers, PORT)

    def _login_allowed(self):
        ip = self._rate_key()
        now = time.time()
        with self.server._login_lock:
            fails = self.server._login_fail
            # 顺手清理过期记录，dict 不会无限增长
            for k in [k for k, ts in fails.items()
                      if not ts or now - ts[-1] >= self._LOGIN_FAIL_WINDOW]:
                del fails[k]
            ts = [t for t in fails.get(ip, [])
                  if now - t < self._LOGIN_FAIL_WINDOW]
            fails[ip] = ts
            return len(ts) < self._LOGIN_FAIL_LIMIT

    def _login_failed(self):
        ip = self._rate_key()
        with self.server._login_lock:
            self.server._login_fail.setdefault(ip, []).append(time.time())

    def _login_ok(self):
        ip = self._rate_key()
        with self.server._login_lock:
            self.server._login_fail.pop(ip, None)

    def _require_admin(self):
        # 仅管理员：通过返回账号字典，否则 401/403
        user = self._require_auth()
        if not user:
            return None
        if not user["is_admin"]:
            # 管理员接口的请求体还没读（如 /api/del_files 的表单）：
            # 关连接，防残留 body 污染同一 keep-alive 连接上的下一个请求。
            self._close_if_body_pending()
            self._json({"ok": False, "error": "需要管理员权限"}, 403)
            return None
        return user

    def _redirect(self, loc):
        self.send_response(302)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()

    def _set_sid(self, tok):
        secure = "; Secure" if self._https_request() else ""
        self.send_response(302)
        self.send_header("Set-Cookie",
                         f"sid={tok}; HttpOnly; Path=/; SameSite=Lax; "
                         f"Max-Age={SESSION_DAYS * 86400}{secure}")
        self.send_header("Location", "/dash")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _clear_sid(self):
        tok = self._cookie().get("sid")
        if tok:
            drop_session(tok)
        self.send_response(302)
        self.send_header("Set-Cookie", "sid=; HttpOnly; Path=/; Max-Age=0")
        self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()

    def _form(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            # Content-Length 填了垃圾值：之前 int() 直接抛 ValueError，
            # 走通用 except 变成 500；畸形请求应 400。
            raise BadUpload("bad content length")
        if n < 0 or n > 1_000_000:
            raise BadUpload("form too large")
        raw = self.rfile.read(n) if n > 0 else b""
        try:
            d = parse_qs(raw.decode("utf-8", "replace"),
                         max_num_fields=_MAX_FORM_FIELDS)
        except TypeError:
            # Python < 3.10.7 没有 max_num_fields 参数：退回不限
            d = parse_qs(raw.decode("utf-8", "replace"))
        except ValueError:
            # 字段数超过上限（碎字段 DoS）：畸形请求应 400
            raise BadUpload("too many fields")
        return {k: v[0] for k, v in d.items()}

    def _multipart(self, cap=None):
        ctype = self.headers.get("Content-Type", "")
        m = re.search(r"boundary=([^;]+)", ctype)
        if not m:
            raise BadUpload("no boundary")
        try:
            boundary = m.group(1).strip().strip('"').encode("latin1")
        except UnicodeEncodeError:
            raise BadUpload("bad boundary")
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            # 同 _form：垃圾 Content-Length 应 400 而不是 500
            raise BadUpload("bad content length")
        if not n:
            raise BadUpload("empty body")
        # 注：BaseHTTPRequestHandler 在收到 Expect: 100-continue 时已自动
        # 回过 100，这里不再手动发，避免重复的 interim 响应。
        # 实际生效的上限默认是 min(配置上限, 磁盘剩余空间)，与接收页面上
        # 显示给对方的数字一致：超过剩余空间的上传直接 413 拒绝，
        # 而不是让对方传一半才遇到 500。
        # /api/receive（只创建接收链接、不收文件）传 cap=MAX_UPLOAD：
        # 建链接这个动作本身不占磁盘，不该被磁盘剩余空间卡住。
        limit = cap if cap is not None else upload_limit()[0]
        return parse_multipart(self.rfile, n, boundary, limit)

    # ---- 分片上传 ----
    def _chunk_state(self):
        st = getattr(self.server, "_chunk", None)
        if st is None:
            # 防御：极少数情况下 Handler 没走 Server.__init__
            # （比如单测直接调方法），现场补一个。
            self.server._chunk = {}
            self.server._chunk_lock = threading.Lock()
            st = self.server._chunk
        return st, self.server._chunk_lock

    def _chunk_sweep(self, now):
        # 清理过期没传完的会话与其临时文件
        st, lock = self._chunk_state()
        with lock:
            dead = [t for t, e in st.items() if e["expires"] <= now]
            for t in dead:
                e = st.pop(t)
                try:
                    os.unlink(e["tmp"])
                except OSError:
                    pass

    def _chunk_finalize(self, e):
        # 分片收齐后落盘入库：与普通上传走同样的 files 表结构。
        # 传的过程中分享可能过期/被删：这时文件不能入库，删临时文件。
        want = "send" if e["kind"] == "add" else "receive"
        share = self._valid_share(e["sid"], want)
        if not share:
            try:
                os.unlink(e["tmp"])
            except OSError:
                pass
            return self._json({"ok": False, "error": "分享不存在或已过期"}, 404)
        stored = secrets.token_hex(16)
        try:
            os.rename(e["tmp"], os.path.join(FILES_DIR, stored))
        except OSError:
            try:
                os.unlink(e["tmp"])
            except OSError:
                pass
            return self._json({"ok": False, "error": "保存失败，请重试"}, 500)
        now = int(time.time())
        try:
            with db() as c:
                c.execute("INSERT INTO files(share_id,filename,stored,size,created,owner_id)"
                          " VALUES(?,?,?,?,?,?)",
                          (e["sid"], e["filename"], stored, e["size"], now,
                           share["owner_id"]))
        except Exception:
            try:
                os.unlink(os.path.join(FILES_DIR, stored))
            except OSError:
                pass
            raise
        return self._json({"ok": True})

    def _parse_range(self, size):
        """解析 Range 头。返回 (start, end, status)：
        status 200 表示忽略 Range 返回整个文件（没有 Range、格式不对、多段 Range
        都按 RFC 9110 允许的方式忽略），206 表示分段，416 表示范围超出文件。"""
        rh = (self.headers.get("Range") or "").strip()
        if not rh:
            return 0, size - 1, 200
        # 数字位数限制：超长数字 int() 会抛 ValueError（Python 的位数上限），
        # 之前直接 500。18 位足够表示任何真实文件大小。
        m = re.fullmatch(r"bytes=(\d{0,18})-(\d{0,18})", rh)
        if not m or (not m.group(1) and not m.group(2)):
            return 0, size - 1, 200
        if m.group(1):
            start = int(m.group(1))
            if m.group(2) and int(m.group(2)) < start:
                return 0, size - 1, 200  # 语法无效（尾在头前面）：忽略
            end = int(m.group(2)) if m.group(2) else size - 1
        else:
            # bytes=-N：文件最后 N 字节
            start = max(size - int(m.group(2)), 0)
            end = size - 1
            if int(m.group(2)) == 0:
                start = size
        end = min(end, size - 1)
        if start >= size:
            return start, end, 416
        return start, end, 206

    def _stream_file(self, path, filename, ctype, disposition, extra_headers=()):
        size = os.path.getsize(path)
        start, end, status = self._parse_range(size)
        if status == 416:
            self.send_response(416)
            self.send_header("Content-Range", "bytes */%d" % size)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        length = end - start + 1 if size else 0
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        # 下载也支持 Range：大文件下载中断后浏览器/下载工具可以续传
        self.send_header("Accept-Ranges", "bytes")
        if status == 206:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
        self.send_header("Content-Disposition", content_disposition(disposition, filename))
        # 防 MIME 嗅探：浏览器只能按声明的 Content-Type 处理
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        if getattr(self, "_head_only", False):
            return
        with open(path, "rb") as f:
            f.seek(start)
            remaining = length
            while remaining > 0:
                chunk = f.read(min(CHUNK, remaining))
                if not chunk:
                    break
                try:
                    self.wfile.write(chunk)
                except (ConnectionResetError, BrokenPipeError):
                    # 客户端提前关了（比如只预读了视频开头）
                    break
                remaining -= len(chunk)

    def _send_file(self, path, filename):
        ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        # 下载的文件即使被人直接在地址栏打开（或浏览器无视 attachment），
        # sandbox 也让里面的脚本不能以本站身份运行。
        return self._stream_file(path, filename, ctype, "attachment",
                                 (("Content-Security-Policy", FILE_CSP),))

    def _send_file_inline(self, path, filename):
        """在线查看：Content-Disposition: inline + 支持 Range 分片（视频拖进度条需要）。
        能否内联只看扩展名白名单（_view_kind），不看猜出来的 MIME 前缀：
        之前 image/svg+xml 以 image/ 开头也被内联，SVG 里的脚本能在本站域名下执行。"""
        kind = _view_kind(filename)
        if not kind:
            # 不在白名单：不内联，退回普通下载（防 MIME 混淆）
            return self._send_file(path, filename)
        extra = (("Content-Security-Policy", FILE_CSP),)
        if kind == "pdf":
            # Chrome 的 PDF 阅读器在 sandbox 里会被拦截，PDF 不加 sandbox；
            # PDF 里的脚本只在阅读器自己的沙箱里运行，碰不到本站页面。
            ctype, extra = "application/pdf", ()
        elif kind == "txt":
            # 文本预览一律按 text/plain 返回，浏览器只会当纯文本显示。
            ctype = "text/plain; charset=utf-8" if _looks_utf8(path) else "text/plain"
        else:
            ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
            if ctype.split("/")[0] not in ("image", "video", "audio"):
                return self._send_file(path, filename)
            # 白名单里的位图/音视频本身不能执行脚本，不加 sandbox：sandbox 会让
            # 浏览器的媒体页变成无来源，"新窗口打开"的视频就加载不出来了。
            extra = ()
        return self._stream_file(path, filename, ctype, "inline", extra)

    def _valid_share(self, sid, want_type=None):
        s = get_share(sid)
        if not s:
            return None
        if is_expired(s):
            delete_share(sid)
            return None
        if want_type and s["type"] != want_type:
            return None
        return s

    def do_HEAD(self):
        # 原来没有 HEAD，Cloudflare 和浏览器探活会拿到 501。
        self._head_only = True
        try:
            self.do_GET()
        finally:
            self._head_only = False

    # ---- GET ----
    def do_GET(self):
        try:
            # 本应用的 GET 接口都不读请求体：带 body 的 GET 直接标记关连接，
            # 否则残留 body 会污染同一 keep-alive 连接上的下一个请求。
            self._close_if_body_pending()
            p = urlparse(self.path).path
            if p == "/healthz":
                # Check SQLite too: a listening socket alone does not mean the app works.
                with db() as c:
                    c.execute("SELECT 1")
                return self._json({"service": "minishare", "ok": True})
            if not has_users():
                if p in ("/", "/setup"):
                    return self._send(200, setup_page())
                return self._redirect("/")
            if p == "/":
                return self._redirect("/dash" if self._user() else "/login")
            if p == "/login":
                if self._user():
                    return self._redirect("/dash")
                return self._send(200, login_page())
            if p == "/logout":
                return self._clear_sid()
            if p == "/dash":
                user = self._user()
                if not user:
                    return self._redirect("/login")
                # 已过期的分享不列出来（每小时会被清理线程删掉，
                # 在删掉之前访问链接已经是 404，这里保持一致）。
                # 管理员看全部分享，普通用户只看自己的。
                with db() as c:
                    if user["is_admin"]:
                        shares = c.execute(
                            "SELECT * FROM shares WHERE expires=0 OR expires>?"
                            " ORDER BY created DESC",
                            (int(time.time()),)).fetchall()
                    else:
                        shares = c.execute(
                            "SELECT * FROM shares WHERE owner_id=?"
                            " AND (expires=0 OR expires>?)"
                            " ORDER BY created DESC",
                            (user["id"], int(time.time()))).fetchall()
                return self._send(200, dash_page(shares, user, self._link_base()))

            m = re.fullmatch(r"/dl/(\d{1,18})", p)
            if m:
                # 控制台下载必须与文件列表使用同一归属规则；普通用户不能
                # 猜测递增的文件 ID 下载其他账号（包括已删链接的文件）。
                user = self._user()
                if not user:
                    return self._redirect("/login")
                with db() as c:
                    f = c.execute("SELECT f.*, s.expires FROM files f"
                                  " LEFT JOIN shares s ON s.id=f.share_id"
                                  " WHERE f.id=?",
                                  (int(m.group(1)),)).fetchone()
                if not f or (not user["is_admin"] and
                             f["owner_id"] != user["id"]):
                    return self._send(404, not_found())
                if f["expires"] and f["expires"] < time.time():
                    # 所属分享已过期（清理线程每小时才跑一轮）：跟控制台
                    # "全部文件"隐藏过期分享保持一致，这里也 404，同时把
                    # 过期分享删掉。分享已删的孤儿文件 expires 为 NULL，
                    # 不受影响，照样能下。
                    delete_share(f["share_id"])
                    return self._send(404, not_found())
                path = os.path.join(FILES_DIR, f["stored"])
                if not os.path.isfile(path):
                    return self._send(404, not_found())
                return self._send_file(path, f["filename"])

            m = re.fullmatch(r"/s/([A-Za-z0-9_\-]{1,16})", p)
            if m:
                sid = m.group(1)
                s = self._valid_share(sid)
                if not s:
                    return self._send(404, not_found())
                if s["type"] == "receive":
                    return self._redirect(f"/r/{sid}")
                return self._send(200, share_page(sid, s, share_files(sid),
                                                  self._user()))

            m = re.fullmatch(r"/s/([A-Za-z0-9_\-]{1,16})/f/(\d{1,18})", p)
            if m:
                sid, fid = m.group(1), int(m.group(2))
                s = self._valid_share(sid, "send")
                if not s:
                    return self._send(404, not_found())
                with db() as c:
                    f = c.execute(
                        "SELECT * FROM files WHERE id=? AND share_id=?",
                        (fid, sid)).fetchone()
                if not f:
                    return self._send(404, not_found())
                path = os.path.join(FILES_DIR, f["stored"])
                if not os.path.isfile(path):
                    return self._send(404, not_found())
                return self._send_file(path, f["filename"])

            m = re.fullmatch(r"/s/([A-Za-z0-9_\-]{1,16})/v/(\d{1,18})", p)
            if m:
                # 在线查看：图片直接显示，视频用 <video> 播放
                sid, fid = m.group(1), int(m.group(2))
                s = self._valid_share(sid, "send")
                if not s:
                    return self._send(404, not_found())
                with db() as c:
                    f = c.execute(
                        "SELECT * FROM files WHERE id=? AND share_id=?",
                        (fid, sid)).fetchone()
                if not f:
                    return self._send(404, not_found())
                path = os.path.join(FILES_DIR, f["stored"])
                if not os.path.isfile(path):
                    return self._send(404, not_found())
                return self._send_file_inline(path, f["filename"])

            m = re.fullmatch(r"/r/([A-Za-z0-9_\-]{1,16})", p)
            if m:
                sid = m.group(1)
                s = self._valid_share(sid)
                if not s:
                    return self._send(404, not_found())
                if s["type"] == "send":
                    return self._redirect(f"/s/{sid}")
                return self._send(200, receive_page(sid, s))

            return self._send(404, not_found())
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            self.log_message("GET %s error: %s", self.path, e)
            # 出错时请求体不一定读完了，关连接防污染同一连接的下一个请求
            self.close_connection = True
            try:
                self._send(500, error_page())
            except Exception:
                pass

    def _cross_site_post(self):
        """浏览器发来的跨站 POST（CSRF）。SameSite=Lax 挡不住同站的其他子域名，
        也挡不住不支持 SameSite 的老浏览器，这里再按浏览器自带的来源头判断一次。
        没有这些头的请求（curl、脚本）不是浏览器 CSRF，照常处理。"""
        site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if site:
            return site not in ("same-origin", "none")
        origin = (self.headers.get("Origin") or "").strip()
        if not origin:
            return False
        if origin == "null":
            return True
        try:
            netloc = urlparse(origin).netloc.lower()
        except ValueError:
            return True
        hosts = {(self.headers.get("Host") or "").strip().lower()}
        if trusted_proxy(self.client_address[0]):
            # 反代改写了 Host 时，以反代转来的原始域名为准
            hosts.add((self.headers.get("X-Forwarded-Host") or "").split(",")[0].strip().lower())
        return netloc not in hosts

    # ---- POST ----
    def do_POST(self):
        try:
            p = urlparse(self.path).path
            if self._cross_site_post():
                self._close_if_body_pending()
                return self._json({"ok": False, "error": "拒绝跨站请求，请在本站页面操作"}, 403)
            if p == "/setup" and not has_users():
                f = self._form()
                pw1, pw2 = f.get("pw1", ""), f.get("pw2", "")
                if len(pw1) < 4:
                    return self._send(200, setup_page("密码至少 4 位"))
                if pw1 != pw2:
                    return self._send(200, setup_page("两次输入不一致"))
                try:
                    admin = create_initial_admin(pw1, f.get("setup_code", ""))
                except ValueError as e:
                    return self._send(403, setup_page(str(e)))
                if admin is None:
                    return self._redirect("/login")
                return self._set_sid(new_session(admin["id"]))

            if p == "/login" and has_users():
                f = self._form()
                if not self._login_allowed():
                    # body 已经由 _form() 读完，直接回登录页（带 429 状态），
                    # 不用关连接
                    return self._send(429, login_page("密码试错太多次，10 分钟后再试"))
                user = find_user_by_pw(f.get("pw", ""))
                if user:
                    self._login_ok()
                    return self._set_sid(new_session(user["id"]))
                self._login_failed()
                return self._send(200, login_page("密码错误"))

            if p == "/logout":
                # 退出链接是 GET，一般没 body；但有人 POST 带 body 时也要
                # 关连接，防残留污染同一 keep-alive 连接上的下一个请求。
                self._close_if_body_pending()
                return self._clear_sid()

            m = re.fullmatch(r"/s/([A-Za-z0-9_\-]{1,16})/add", p)
            if m:
                # 给已创建的分享追加文件：本人或管理员才能操作
                user = self._require_auth()
                if not user:
                    return
                sid = m.group(1)
                s = self._valid_share(sid, "send")
                if not s:
                    # 请求体还没读：关连接，防残留 body 污染同一 keep-alive
                    # 连接上的下一个请求（同 /r/<sid>/upload 的 404 路径）。
                    self._close_if_body_pending()
                    return self._json({"ok": False, "error": "分享不存在"}, 404)
                if not can_manage_share(user, s):
                    self._close_if_body_pending()
                    return self._json({"ok": False, "error": "只能操作自己的分享"}, 403)
                try:
                    _, files = self._multipart()
                except UploadTooLarge:
                    return self._fail_close({"ok": False, "error": too_large_msg()}, 413)
                except BadUpload as e:
                    return self._fail_close({"ok": False, "error": f"上传解析失败: {e}"}, 400)
                except OSError as oe:
                    if oe.errno == errno.ENOSPC:
                        # 写盘中途磁盘满：parse_multipart 已清理已落盘的临时文件。
                        # 请求体没读完，关连接防污染（同 UploadTooLarge 路径）。
                        return self._fail_close(
                            {"ok": False, "error": "服务器磁盘空间不足，上传失败"}, 507)
                    raise
                if not files:
                    return self._json({"ok": False, "error": "没有收到文件"}, 400)
                now = int(time.time())
                try:
                    with db() as c:
                        for fo in files:
                            c.execute("INSERT INTO files(share_id,filename,stored,size,created,owner_id)"
                                      " VALUES(?,?,?,?,?,?)",
                                      (sid, fo["filename"], fo["stored"], fo["size"], now,
                                       s["owner_id"]))
                except Exception:
                    for fo in files:
                        try:
                            os.unlink(os.path.join(FILES_DIR, fo["stored"]))
                        except OSError:
                            pass
                    raise
                return self._json({"ok": True, "count": len(files)})

            if p == "/api/share_file_del":
                # 删除分享里的单个文件：本人或管理员才能操作
                user = self._require_auth()
                if not user:
                    return
                f = self._form()
                sid = f.get("sid", "")
                fid = f.get("id", "")
                if not re.fullmatch(r"[0-9]{1,18}", fid or ""):
                    return self._json({"ok": False, "error": "参数错误"}, 400)
                s = self._valid_share(sid)
                if not s:
                    return self._json({"ok": False, "error": "分享不存在或已过期"}, 404)
                if not can_manage_share(user, s):
                    return self._json({"ok": False, "error": "只能操作自己的分享"}, 403)
                with db() as c:
                    row = c.execute("SELECT id FROM files WHERE id=? AND share_id=?",
                                    (int(fid), sid)).fetchone()
                if not row:
                    return self._json({"ok": False, "error": "文件不存在"}, 404)
                delete_files([int(fid)])
                return self._json({"ok": True})

            if p == "/api/share_file_order":
                user = self._require_auth()
                if not user:
                    return
                f = self._form()
                sid, fid = f.get("sid", ""), f.get("id", "")
                if (not re.fullmatch(r"[A-Za-z0-9_\-]{1,16}", sid) or
                        not re.fullmatch(r"[0-9]{1,19}", fid) or
                        int(fid) > 9223372036854775807):
                    return self._json({"ok": False, "error": "参数错误"}, 400)
                try:
                    arrange_share_file(sid, int(fid), f.get("action", ""), user)
                except PermissionError as e:
                    return self._json({"ok": False, "error": str(e)}, 403)
                except LookupError as e:
                    return self._json({"ok": False, "error": str(e)}, 404)
                except ValueError as e:
                    return self._json({"ok": False, "error": str(e)}, 400)
                return self._json({"ok": True})

            if p == "/api/share_file_existing":
                user = self._require_auth()
                if not user:
                    return
                f = self._form()
                sid = f.get("sid", "")
                raw_ids = (f.get("ids") or "").split(",")
                if (not re.fullmatch(r"[A-Za-z0-9_\-]{1,16}", sid) or
                        any(not re.fullmatch(r"[0-9]{1,18}", x) for x in raw_ids)):
                    return self._json({"ok": False, "error": "参数错误"}, 400)
                try:
                    count = add_existing_files(sid, [int(x) for x in raw_ids], user)
                except PermissionError as e:
                    return self._json({"ok": False, "error": str(e)}, 403)
                except ValueError as e:
                    return self._json({"ok": False, "error": str(e)}, 400)
                except OSError:
                    return self._json({"ok": False, "error": "读取已有文件失败，请检查文件是否仍在服务器上"}, 500)
                return self._json({"ok": True, "count": count})

            if p == "/api/share":
                user = self._require_auth()
                if not user:
                    return
                try:
                    fields, files = self._multipart()
                except UploadTooLarge:
                    return self._fail_close({"ok": False, "error": too_large_msg()}, 413)
                except BadUpload as e:
                    # 解析失败时请求体可能没读完（如 Content-Type 里没 boundary）：
                    # 必须关连接，否则残留的请求体会污染同一 keep-alive 连接上
                    # 的下一个请求（实测：服务端曾把残留 body 当成新请求解析）。
                    return self._fail_close({"ok": False, "error": f"上传解析失败: {e}"}, 400)
                except OSError as oe:
                    if oe.errno == errno.ENOSPC:
                        return self._fail_close(
                            {"ok": False, "error": "服务器磁盘空间不足，上传失败"}, 507)
                    raise
                if not files:
                    return self._json({"ok": False, "error": "没有收到文件"}, 400)
                title = (fields.get("title") or "").strip()[:100]
                days = _expiry_days(fields.get("expiry"))
                now = int(time.time())
                try:
                    sid = new_share_id()
                    with db() as c:
                        c.execute("INSERT INTO shares(id,type,title,created,expires,owner_id)"
                                  " VALUES(?,?,?,?,?,?)",
                                  (sid, "send", title, now, now + days * 86400 if days else 0,
                                   user["id"]))
                        for fo in files:
                            c.execute("INSERT INTO files(share_id,filename,stored,size,created,owner_id)"
                                      " VALUES(?,?,?,?,?,?)",
                                      (sid, fo["filename"], fo["stored"], fo["size"], now,
                                       user["id"]))
                except Exception:
                    # 入库失败（如磁盘满）：删掉已落盘的文件，不能留孤儿占空间
                    for fo in files:
                        try:
                            os.unlink(os.path.join(FILES_DIR, fo["stored"]))
                        except OSError:
                            pass
                    raise
                return self._json({"ok": True, "link": f"/s/{sid}", "id": sid})

            if p == "/api/share_create":
                # 分片上传配套：先只建分享（不收文件），返回 sid；
                # 前端随后用 /api/chunk_init?kind=add 把文件一片片传上来。
                # （控制台“发送文件”大文件走这个流程，避免整文件一次
                # POST 被反代掐掉。）
                user = self._require_auth()
                if not user:
                    return
                f = self._form()
                title = (f.get("title") or "").strip()[:100]
                days = _expiry_days(f.get("expiry"))
                now = int(time.time())
                sid = new_share_id()
                with db() as c:
                    c.execute("INSERT INTO shares(id,type,title,created,expires,owner_id)"
                              " VALUES(?,?,?,?,?,?)",
                              (sid, "send", title, now,
                               now + days * 86400 if days else 0, user["id"]))
                return self._json({"ok": True, "link": f"/s/{sid}", "id": sid})

            if p == "/api/receive":
                user = self._require_auth()
                if not user:
                    return
                try:
                    fields, files = self._multipart(MAX_UPLOAD)
                except UploadTooLarge:
                    # 建链接不收文件：用配置上限解析，不受磁盘剩余空间限制
                    return self._fail_close({"ok": False, "error": "文件太大，超出上限"}, 413)
                except BadUpload as e:
                    return self._fail_close({"ok": False, "error": str(e)}, 400)
                if files:
                    # 创建接收链接不需要传文件：删掉已落盘的孤儿文件，
                    # 不能让它们留在磁盘上谁也看不见、也清不掉。
                    for fo in files:
                        try:
                            os.unlink(os.path.join(FILES_DIR, fo["stored"]))
                        except OSError:
                            pass
                    return self._json({"ok": False, "error": "创建接收链接不需要上传文件"}, 400)
                title = (fields.get("title") or "").strip()[:100]
                days = _expiry_days(fields.get("expiry"))
                now = int(time.time())
                sid = new_share_id()
                with db() as c:
                    c.execute("INSERT INTO shares(id,type,title,created,expires,owner_id)"
                              " VALUES(?,?,?,?,?,?)",
                              (sid, "receive", title, now, now + days * 86400 if days else 0,
                               user["id"]))
                return self._json({"ok": True, "link": f"/r/{sid}", "id": sid})

            if p == "/api/delete":
                user = self._require_auth()
                if not user:
                    return
                f = self._form()
                sid = f.get("id", "")
                # 用 _valid_share：过期的分享在这里直接 404（并顺手删掉），
                # 与 /api/share_file_del 等接口保持一致
                s = self._valid_share(sid)
                if not s:
                    return self._json({"ok": False, "error": "分享不存在或已过期"}, 404)
                # 普通用户只能取消自己的分享链接，管理员可以取消任何人的
                if not can_manage_share(user, s):
                    return self._json({"ok": False, "error": "只能删除自己的分享"}, 403)
                delete_share(sid)
                return self._json({"ok": True})

            if p == "/api/del_files":
                # 删文件只有管理员可以，普通用户没有任何删除文件的权限
                if not self._require_admin():
                    return
                f = self._form()
                # 注意：str.isdigit() 对 "²" 这类 Unicode 数字也返回 True，
                # 但 int() 转不了，会抛 ValueError 变成 500。用 ASCII 数字校验。
                ids = [int(x) for x in (f.get("ids") or "").split(",")
                       if re.fullmatch(r"[0-9]{1,18}", x.strip() or "")]
                removed = delete_files(ids)
                return self._json({"ok": True, "deleted": removed})

            if p == "/api/expiry":
                # 手动调整已创建分享的过期时间（延长或缩短）：
                # 普通用户只能改自己的，管理员可以改任何人的
                user = self._require_auth()
                if not user:
                    return
                f = self._form()
                sid = f.get("id", "")
                # 必须查有效期：之前直接查库不看过期，已过期的分享在清理线程
                # 跑之前还能调这个接口把过期时间改到未来，等于"复活"。
                s = self._valid_share(sid)
                if not s:
                    return self._json({"ok": False, "error": "分享不存在或已过期"}, 404)
                if not can_manage_share(user, s):
                    return self._json({"ok": False, "error": "只能修改自己的分享"}, 403)
                days = _expiry_days(f.get("expiry"))
                now = int(time.time())
                with db() as c:
                    c.execute("UPDATE shares SET expires=? WHERE id=?",
                              (now + days * 86400 if days else 0, sid))
                return self._json({"ok": True})

            if p == "/api/title":
                # 改分享的备注名（发送/接收通用），空字符串表示清除备注：
                # 普通用户只能改自己的，管理员可以改任何人的
                user = self._require_auth()
                if not user:
                    return
                f = self._form()
                sid = f.get("id", "")
                title = (f.get("title", "") or "").strip()[:100]
                if not re.fullmatch(r"[A-Za-z0-9_\-]{1,16}", sid):
                    return self._json({"ok": False, "error": "bad id"}, 400)
                # 同 /api/expiry：过期分享在清理前不许再改（之前直接查库不看过期）
                s = self._valid_share(sid)
                if not s:
                    return self._json({"ok": False, "error": "分享不存在或已过期"}, 404)
                if not can_manage_share(user, s):
                    return self._json({"ok": False, "error": "只能修改自己的分享"}, 403)
                with db() as c:
                    c.execute("UPDATE shares SET title=? WHERE id=?", (title, sid))
                return self._json({"ok": True})

            if p == "/api/chpw":
                # 改自己的密码（管理员和普通用户都走这里，改的是当前登录的账号）
                user = self._require_auth()
                if not user:
                    return
                f = self._form()
                if len(f.get("new1", "")) < 4 or f.get("new1") != f.get("new2"):
                    return self._json({"ok": False, "error": "新密码至少4位且两次一致"})
                try:
                    set_user_pw(user["id"], f["new1"])
                except ValueError as e:
                    return self._json({"ok": False, "error": str(e)}, 400)
                # 改密码很可能是因为旧密码泄露：让这个账号在其他设备/浏览器上
                # 的旧会话立即失效，只保留当前这一个会话不断线。
                # 注意只踢掉自己的会话，不能影响别的账号。
                me = self._cookie().get("sid")
                with db() as c:
                    if me:
                        c.execute("DELETE FROM sessions WHERE user_id=? AND token!=?",
                                  (user["id"], me))
                    else:
                        c.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
                return self._json({"ok": True})

            # ---- 用户管理（仅管理员；账号没有注册入口，只能由管理员添加） ----
            if p == "/api/user_add":
                if not self._require_admin():
                    return
                f = self._form()
                if f.get("pw1", "") != f.get("pw2", ""):
                    return self._json({"ok": False, "error": "两次输入不一致"}, 400)
                try:
                    u = create_user(f.get("pw1", ""), is_admin=False,
                                    remark=f.get("remark", ""))
                except ValueError as e:
                    return self._json({"ok": False, "error": str(e)}, 400)
                return self._json({"ok": True, "id": u["id"]})

            if p == "/api/user_remark":
                # 管理员给账号改备注名（比如这个账号给了谁）：只展示用，
                # 不影响登录，登录永远只认密码。
                if not self._require_admin():
                    return
                f = self._form()
                uid = _small_int(f.get("id", ""))
                if uid is None:
                    return self._json({"ok": False, "error": "bad id"}, 400)
                if not get_user(uid):
                    return self._json({"ok": False, "error": "用户不存在"}, 404)
                set_user_remark(uid, f.get("remark", ""))
                return self._json({"ok": True})

            if p == "/api/user_pw":
                # 管理员点"眼睛"查看某个账号的当前密码。
                # 只有管理员能调（普通用户看不到眼睛按钮）；用户改密码/
                # 管理员重设密码时明文会同步更新，所以看到的永远是当前密码。
                # 老版本迁移来的账号明文未知：返回空，让他改一次密码后就能看。
                if not self._require_admin():
                    return
                f = self._form()
                uid = _small_int(f.get("id", ""))
                if uid is None:
                    return self._json({"ok": False, "error": "bad id"}, 400)
                target = get_user(uid)
                if not target:
                    return self._json({"ok": False, "error": "用户不存在"}, 404)
                if target["is_admin"]:
                    return self._json({"ok": False, "error": "这是管理员账号"}, 403)
                return self._json({"ok": True, "pw": get_user_pw(uid) or ""})

            if p == "/api/user_del":
                if not self._require_admin():
                    return
                f = self._form()
                uid = _small_int(f.get("id", ""))
                if uid is None:
                    return self._json({"ok": False, "error": "bad id"}, 400)
                target = get_user(uid)
                if not target:
                    return self._json({"ok": False, "error": "用户不存在"}, 404)
                if target["is_admin"]:
                    return self._json({"ok": False, "error": "不能删除管理员账号"}, 403)
                delete_user(uid)
                return self._json({"ok": True})

            if p == "/api/user_resetpw":
                # 管理员给普通用户重设密码（管理员改自己的密码走"修改密码"）
                if not self._require_admin():
                    return
                f = self._form()
                uid = _small_int(f.get("id", ""))
                if uid is None:
                    return self._json({"ok": False, "error": "bad id"}, 400)
                target = get_user(uid)
                if not target:
                    return self._json({"ok": False, "error": "用户不存在"}, 404)
                if target["is_admin"]:
                    return self._json({"ok": False, "error": "管理员请用修改密码"}, 403)
                if f.get("pw1", "") != f.get("pw2", ""):
                    return self._json({"ok": False, "error": "两次输入不一致"}, 400)
                try:
                    set_user_pw(uid, f.get("pw1", ""))
                except ValueError as e:
                    return self._json({"ok": False, "error": str(e)}, 400)
                # 密码被重置后，踢掉该账号的所有会话
                with db() as c:
                    c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
                return self._json({"ok": True})

            m = re.fullmatch(r"/r/([A-Za-z0-9_\-]{1,16})/upload", p)
            if m:
                sid = m.group(1)
                s = self._valid_share(sid, "receive")
                if not s:
                    self._close_if_body_pending()
                    return self._json({"ok": False, "error": "链接不存在或已过期"}, 404)
                try:
                    _, files = self._multipart()
                except UploadTooLarge:
                    return self._fail_close({"ok": False, "error": too_large_msg()}, 413)
                except BadUpload as e:
                    # 同 /api/share：解析失败可能没读完请求体，关连接防污染
                    return self._fail_close({"ok": False, "error": f"上传解析失败: {e}"}, 400)
                except OSError as oe:
                    if oe.errno == errno.ENOSPC:
                        return self._fail_close(
                            {"ok": False, "error": "服务器磁盘空间不足，上传失败"}, 507)
                    raise
                if not files:
                    return self._json({"ok": False, "error": "没有收到文件"}, 400)
                now = int(time.time())
                try:
                    with db() as c:
                        for fo in files:
                            c.execute("INSERT INTO files(share_id,filename,stored,size,created,owner_id)"
                                      " VALUES(?,?,?,?,?,?)",
                                      (sid, fo["filename"], fo["stored"], fo["size"], now,
                                       s["owner_id"]))
                except Exception:
                    # 入库失败（如磁盘满）：删掉已落盘的文件，不能留孤儿占空间
                    for fo in files:
                        try:
                            os.unlink(os.path.join(FILES_DIR, fo["stored"]))
                        except OSError:
                            pass
                    raise
                return self._json({"ok": True, "count": len(files)})

            if p == "/api/chunk_init":
                # 分片上传第 1 步：建会话。kind=add 给分享追加文件（要登录且
                # 是本人/管理员），kind=upload 走接收链接（免登录）。
                # _form() 已经把小 body 读完，后面 early return 不用关连接。
                f = self._form()
                sid = f.get("sid", "")
                kind = f.get("kind", "")
                name = _clean_filename(f.get("name", ""))
                try:
                    size = int(f.get("size", "-1"))
                    chunks = int(f.get("chunks", "0"))
                except (TypeError, ValueError):
                    return self._json({"ok": False, "error": "参数错误"}, 400)
                if kind == "add":
                    user = self._require_auth()
                    if not user:
                        return
                    s = self._valid_share(sid, "send")
                    if not s:
                        return self._json({"ok": False, "error": "分享不存在"}, 404)
                    if not can_manage_share(user, s):
                        return self._json({"ok": False, "error": "只能操作自己的分享"}, 403)
                elif kind == "upload":
                    s = self._valid_share(sid, "receive")
                    if not s:
                        return self._json({"ok": False, "error": "链接不存在或已过期"}, 404)
                else:
                    return self._json({"ok": False, "error": "参数错误"}, 400)
                # 片数必须与大小自洽：防止客户端谎报
                expect = (size + CHUNK_SIZE - 1) // CHUNK_SIZE if size > 0 else 1
                if size < 0 or chunks != expect:
                    return self._json({"ok": False, "error": "参数错误"}, 400)
                limit = upload_limit()[0]
                if size > limit:
                    return self._json({"ok": False, "error": too_large_msg()}, 413)
                now = int(time.time())
                self._chunk_sweep(now)
                st, lock = self._chunk_state()
                with lock:
                    if len(st) >= MAX_CHUNK_SESSIONS:
                        # _form() 已经把小 body 读完，直接回 429，不用关连接。
                        # 检查必须在建临时文件之前：被拒的请求不能留下
                        # 无会话的 chunk_* 空文件（sweep 只清有会话的）。
                        return self._json(
                            {"ok": False, "error": "服务器上传任务太多，请稍后再试"}, 429)
                    token = secrets.token_hex(16)
                    tmp = os.path.join(FILES_DIR, "chunk_" + token)
                    try:
                        open(tmp, "wb").close()
                    except OSError as oe:
                        if oe.errno == errno.ENOSPC:
                            return self._json(
                                {"ok": False, "error": "服务器磁盘空间不足，上传失败"}, 507)
                        return self._json({"ok": False, "error": "服务器错误"}, 500)
                    st[token] = {"sid": sid, "kind": kind, "filename": name,
                                 "size": size, "chunks": chunks, "next": 0,
                                 "recvd": 0, "tmp": tmp,
                                 "expires": now + CHUNK_TTL}
                return self._json({"ok": True, "up": token})

            if p == "/api/chunk":
                # 分片上传第 2 步：收一片。body 就是分片的原始字节，
                # 不是 multipart，解析开销最小。
                try:
                    q = parse_qs(urlparse(self.path).query,
                                 max_num_fields=10)
                except TypeError:
                    # Python < 3.10.7 没有 max_num_fields 参数：退回不限。
                    # query 里只有 up/i 两个参数，请求行最长 64KB，
                    # 老版本上可放大的上限有限，风险可接受。
                    q = parse_qs(urlparse(self.path).query)
                except ValueError:
                    # 碎字段 query（DoS）：body 还没读，关连接防污染
                    self._close_if_body_pending()
                    return self._json({"ok": False, "error": "参数错误"}, 400)
                token = (q.get("up") or [""])[0]
                idx_s = (q.get("i") or [""])[0]
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                    idx = int(idx_s)
                except (TypeError, ValueError):
                    self._close_if_body_pending()
                    return self._json({"ok": False, "error": "参数错误"}, 400)
                st, lock = self._chunk_state()
                now = time.time()
                with lock:
                    e = st.get(token)
                    live = e is not None and e["expires"] > now
                    # 正常收片：序号必须等于 next，且不能超出总片数。
                    # 另允许重发上一片：客户端某片成功后若没收到响应会重传
                    # 该片，直接回成功（不重复写盘），否则一次丢包就导致
                    # 整个文件重传。
                    dup = (live and idx >= 0 and e["next"] > 0
                           and idx == e["next"] - 1
                           and n == e.get("last_n", -1))
                    if live and not dup and idx == e["next"] and idx < e["chunks"]:
                        expect_n = min(CHUNK_SIZE, e["size"] - e["recvd"])
                    else:
                        expect_n = -1
                if not live or (not dup and (n != expect_n or n < 0 or n > CHUNK_SIZE)):
                    # 序号/大小对不上：不读 body，直接关连接，客户端
                    # 重传这一片即可（body 最多 4MB，但恶意请求可能谎报
                    # 超大 Content-Length，不能无脑读完）。
                    return self._fail_close(
                        {"ok": False, "error": "分片已失效，请重新上传"}, 400)
                try:
                    # 先把 body 读进内存（不持锁，网络读可能慢），再持锁
                    # 校验+写盘：杜绝两个并发请求带同序号导致重复追加。
                    buf = bytearray()
                    remain = n
                    while remain > 0:
                        data = self.rfile.read(min(65536, remain))
                        if not data:
                            raise BadUpload("truncated chunk")
                        buf += data
                        remain -= len(data)
                except BadUpload:
                    return self._fail_close(
                        {"ok": False, "error": "分片接收失败，请重试"}, 400)
                with lock:
                    e2 = st.get(token)
                    if e2 is None or e2["expires"] <= time.time():
                        return self._json(
                            {"ok": False, "error": "分片已失效，请重新上传"}, 400)
                    redup = (idx >= 0 and e2["next"] > 0
                             and idx == e2["next"] - 1
                             and n == e2.get("last_n", -1))
                    if idx == e2["next"] and idx < e2["chunks"]:
                        try:
                            with open(e2["tmp"], "ab") as out:
                                out.write(buf)
                        except OSError as oe:
                            # 写盘失败（最常见是磁盘满了）：整个上传会话作废，
                            # 删临时文件，给明确提示而不是笼统的服务器错误。
                            # 会话已 pop，sweep 也不会再碰它。
                            st.pop(token, None)
                            try:
                                os.unlink(e2["tmp"])
                            except OSError:
                                pass
                            if oe.errno == errno.ENOSPC:
                                return self._json(
                                    {"ok": False,
                                     "error": "服务器磁盘空间不足，上传失败"}, 507)
                            raise
                        e2["recvd"] += n
                        e2["next"] += 1
                        e2["last_n"] = n
                    elif not redup:
                        return self._json(
                            {"ok": False, "error": "分片已失效，请重新上传"}, 400)
                    # 每片成功都顺延过期时间：大文件传得慢也不怕 2 小时不够
                    e2["expires"] = time.time() + CHUNK_TTL
                    recvd = e2["recvd"]
                return self._json({"ok": True, "recvd": recvd})

            if p == "/api/chunk_done":
                # 分片上传第 3 步：收齐确认，落盘入库
                f = self._form()
                token = f.get("up", "")
                if not re.fullmatch(r"[0-9a-f]{32}", token or ""):
                    return self._json({"ok": False, "error": "上传会话无效"}, 400)
                st, lock = self._chunk_state()
                with lock:
                    e = st.pop(token, None)
                if (e is None or e["expires"] <= time.time()
                        or e["recvd"] != e["size"]):
                    if e is not None:
                        try:
                            os.unlink(e["tmp"])
                        except OSError:
                            pass
                    return self._json({"ok": False, "error": "上传不完整，请重新上传"}, 400)
                if e["kind"] == "add":
                    # 完成阶段重新鉴权：初始化时有权限，不代表传完时还有。
                    # 用户可能被删、会话可能失效、分享可能易主——这时不能入库。
                    # 注意：会话已从内存 pop，无论鉴权成败都要删临时文件，
                    # 否则 sweep 也清不到，会永久占磁盘。
                    user = self._require_auth()
                    if not user:
                        try:
                            os.unlink(e["tmp"])
                        except OSError:
                            pass
                        return
                    s = self._valid_share(e["sid"], "send")
                    if not s or not can_manage_share(user, s):
                        try:
                            os.unlink(e["tmp"])
                        except OSError:
                            pass
                        return self._json({"ok": False, "error": "无权限或分享已失效"}, 403)
                return self._chunk_finalize(e)

            # 未知路径：body 没读的话关连接，防残留污染 keep-alive
            self._close_if_body_pending()
            return self._json({"ok": False, "error": "unknown"}, 404)
        except BadUpload as e:
            # 表单/分块解析失败（超大、缺 boundary 等）统一 400，各接口内部的
            # except BadUpload 会先捕获，这里只处理漏网的。请求体可能没读完，
            # 关连接防污染。
            self._fail_close({"ok": False, "error": str(e) or "请求无效"}, 400)
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            self.log_message("POST %s error: %s", self.path, e)
            # 出错时请求体不一定读完了，关连接是最稳妥的
            self.close_connection = True
            try:
                self._json({"ok": False, "error": "服务器错误"}, 500)
            except Exception:
                pass


def _small_int(v):
    """表单里的数据库 id：只收 1~18 位 ASCII 数字，超出 SQLite 整数范围的
    （之前会抛 OverflowError 变成 500）和其他垃圾值都返回 None。"""
    v = (v or "").strip()
    return int(v) if re.fullmatch(r"[0-9]{1,18}", v) else None

def _expiry_days(v):
    try:
        d = int(v or 7)
    except (TypeError, ValueError):
        d = 7
    return max(0, min(d, 365))


# ---------------- 主程序 ----------------
class Server(ThreadingHTTPServer):
    def __init__(self, server_address, handler, bind_and_activate=True):
        self.address_family = (socket.AF_INET6 if ":" in server_address[0]
                               else socket.AF_INET)
        # 登录失败计数（防暴力破解）：ip -> [失败时间戳]。
        # 放 Server 实例上而不是模块全局：每个 Server 独立计数，测试里
        # 每个用例起一个新 Server 就不会互相污染。
        self._login_fail = {}
        self._login_lock = threading.Lock()
        # 分片上传会话：token -> {sid,kind,filename,size,chunks,next,
        # recvd,tmp,expires}。放 Server 实例上，测试里每个 Server 互不干扰。
        self._chunk = {}
        self._chunk_lock = threading.Lock()
        super().__init__(server_address, handler, bind_and_activate)

    def get_request(self):
        # 每个连接设 120 秒无数据超时：客户端只建连不发数据（或发一半
        # 就停住）时，工作线程不会永远卡在 rfile.read() 里。线程数无上限，
        # 不设超时一个慢连接就能永久占住一个线程直到耗尽内存。
        # 超时按"连续无数据"计算，正常传大文件不受影响。
        conn, addr = super().get_request()
        conn.settimeout(120)
        return conn, addr

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            # Match the selected IP version consistently across Linux/BSD.
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        # 在 listen 之前钳住 MSS：所有 accept 出来的子连接都会继承，
        # 服务端只发小包。用于穿越 PMTU 黑洞链路（大包被中间环节静
        # 默丢弃、ICMP 分片通知又回不来时，连接会一直卡住）。
        # 注意：accept 之后再设 TCP_MAXSEG 是无效的，必须在 listen 前。
        if MSS > 0:
            try:
                self.socket.setsockopt(socket.IPPROTO_TCP,
                                       socket.TCP_MAXSEG, MSS)
            except (OSError, AttributeError):
                pass
        super().server_bind()


def check_server(host, port, attempts=10):
    host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(host, host)
    error = "no response"
    for attempt in range(attempts):
        conn = HTTPConnection(host, port, timeout=2)
        try:
            conn.request("GET", "/healthz")
            response = conn.getresponse()
            body = response.read(4096)
            if response.status == 200 and json.loads(body) == {"service": "minishare", "ok": True}:
                print("minishare 本机 HTTP 和数据库检查通过", flush=True)
                return 0
            error = "unexpected HTTP response: %s" % response.status
        except (OSError, ValueError, HTTPException) as exc:
            error = str(exc)
        finally:
            conn.close()
        if attempt + 1 < attempts:
            time.sleep(1)
    print("minishare 本机检查失败：%s" % error, file=sys.stderr)
    return 1


def _sweep_startup_files():
    # 启动时清理上次异常退出留下的分片临时文件：内存里的上传会话
    # 已丢失，这些 chunk_* 文件永远不会被认领，不清会一直占磁盘。
    # 另外清理"孤儿文件"：_chunk_finalize 里 rename 成功、但 INSERT 入库前
    # 进程崩溃，或者 multipart 上传文件已落盘、但入库事务没提交就崩溃，
    # 都会留下一个有文件、无 DB 行的孤儿。启动时没有任何上传在进行中，
    # FILES_DIR 里非 chunk_ 前缀、且 DB 里没有对应行的文件一定是孤儿，
    # 可以删。
    try:
        with db() as c:
            known = {r[0] for r in c.execute("SELECT stored FROM files")}
        for fn in os.listdir(FILES_DIR):
            # chunk_*：分片临时文件，内存会话已丢失，永远不会被认领，删；
            # 非 chunk_ 但 DB 无对应行：崩溃留下的孤儿文件，删；
            # DB 有行的正常文件：保留。
            if not fn.startswith("chunk_") and fn in known:
                continue
            try:
                os.unlink(os.path.join(FILES_DIR, fn))
            except OSError:
                pass
    except OSError:
        pass


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--check":
        sys.exit(check_server(sys.argv[2], int(sys.argv[3])))
    init_db()
    _sweep_startup_files()
    cleanup_expired()
    threading.Thread(target=cleanup_loop, daemon=True).start()
    srv = Server((HOST, PORT), Handler)
    srv.daemon_threads = True
    url_host = f"[{HOST}]" if ":" in HOST else HOST
    print(f"minishare v{VERSION} 启动：http://{url_host}:{PORT}  数据目录={DATA_DIR} MSS={MSS}",
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
