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
import re
import json
import time
import hmac
import html
import socket
import mimetypes
import hashlib
import secrets
import sqlite3
import threading
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote, unquote

# ---------------- 配置 ----------------
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

# ---------------- 数据库 ----------------
def db():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c

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
            filename TEXT, stored TEXT, size INTEGER, created INTEGER)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_files_share ON files(share_id)")
        # 兼容老版本数据库：补上新增的列
        for table, col, typ in (("sessions", "user_id", "INTEGER"),
                                ("shares", "owner_id", "INTEGER"),
                                ("users", "remark", "TEXT"),
                                ("users", "pw_plain", "TEXT")):
            cols = [r["name"] for r in c.execute(f"PRAGMA table_info({table})")]
            if col not in cols:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
        _migrate_to_multiuser(c)

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
        return c.execute("SELECT * FROM files WHERE share_id=? ORDER BY id", (sid,)).fetchall()

def is_expired(share):
    return share["expires"] and share["expires"] < time.time()

def delete_share(sid):
    # 只删除分享链接：文件保留在"全部文件"里，由用户手动删除。
    # 过期自动清理也走这里：链接失效，文件同样保留。
    with db() as c:
        c.execute("DELETE FROM shares WHERE id=?", (sid,))

def all_files():
    # 已过期的分享（每小时会被清理线程删掉）在删掉之前也不显示，
    # 否则控制台"全部文件"里会躺着打不开链接的幽灵文件。
    now = int(time.time())
    with db() as c:
        return c.execute(
            "SELECT f.id,f.filename,f.size,f.created,s.type,s.title,s.owner_id"
            " FROM files f LEFT JOIN shares s ON f.share_id=s.id"
            " WHERE s.id IS NULL OR s.expires=0 OR s.expires>?"
            " ORDER BY f.id DESC", (now,)).fetchall()

def delete_files(ids):
    removed = 0
    with db() as c:
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
                data, ended = read_data_mem(1024 * 1024)
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
CSS = """
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  max-width:720px;margin:0 auto;padding:16px;background:#f2f4f8;color:#222;-webkit-text-size-adjust:100%}
.card{background:#fff;border-radius:12px;padding:18px;margin-bottom:14px;box-shadow:0 1px 3px rgba(0,0,0,.07)}
h1{font-size:22px;margin:4px 0 14px}h2{font-size:17px;margin:0 0 10px}h3{font-size:15px;margin:14px 0 8px}
input,select,textarea{font-size:15px;padding:10px 12px;border-radius:8px;border:1px solid #d9d9d9;width:100%;margin:6px 0;background:#fff}
button{font-size:15px;padding:10px 12px;border-radius:8px;border:none;background:#1677ff;color:#fff;width:100%;margin:6px 0;cursor:pointer}
button.ghost{background:#fff;color:#333;border:1px solid #d9d9d9;width:auto;padding:8px 14px;margin:2px 4px 2px 0}
button.danger{background:#fff;color:#e5484d;border:1px solid #f3c2c4;width:auto;padding:8px 14px;margin:2px 4px 2px 0}
a{color:#1677ff;text-decoration:none}
.file{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:10px 0;border-bottom:1px solid #f0f0f0}
.file:last-child{border-bottom:none}
.muted{color:#8a8f99;font-size:13px}
.linkbox{background:#f6f8fb;border:1px dashed #b9c6d8;border-radius:8px;padding:10px;word-break:break-all;font-size:14px;margin:8px 0}
.err{background:#fff1f0;border:1px solid #ffa39e;color:#cf1322;border-radius:8px;padding:10px;margin:8px 0;font-size:14px}
.ok{background:#f6ffed;border:1px solid #b7eb8f;color:#389e0d;border-radius:8px;padding:10px;margin:8px 0;font-size:14px}
progress{width:100%;height:10px;margin:6px 0}
.row{display:flex;gap:8px}.row>*{flex:1}
.badge{display:inline-block;font-size:12px;padding:2px 8px;border-radius:20px;background:#eef4ff;color:#1677ff;margin-right:6px}
.badge.recv{background:#f6ffed;color:#389e0d}
input.fileck{width:auto;margin:0 8px 2px 0;vertical-align:-2px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.diskfoot{position:fixed;left:12px;bottom:12px;background:rgba(30,34,40,.82);color:#fff;font-size:12px;
  padding:7px 12px;border-radius:20px;z-index:1000;display:flex;align-items:center;gap:8px;box-shadow:0 2px 8px rgba(0,0,0,.15)}
.diskbar{width:90px;height:5px;border-radius:3px;background:rgba(255,255,255,.25);overflow:hidden}
.diskbar i{display:block;height:100%;background:#40c463;border-radius:3px}
"""

def page(title, body):
    return ("<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{CSS}</style></head>"
            f"<body>{body}</body></html>").encode("utf-8")

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

def setup_page(err=""):
    e = f"<div class='err'>{html.escape(err)}</div>" if err else ""
    return page("初始设置", f"""<div class='card' style='max-width:420px;margin:40px auto'>
<h1>🗂️ 文件分享</h1><p class='muted'>首次使用，请设置管理员密码。</p>{e}
<form method='post' action='/setup'>
<input type='password' name='pw1' placeholder='设置密码' required minlength='4'>
<input type='password' name='pw2' placeholder='再次输入' required minlength='4'>
<button>完成设置</button></form></div>""")

def login_page(err=""):
    e = f"<div class='err'>{html.escape(err)}</div>" if err else ""
    return page("登录", f"""<div class='card' style='max-width:420px;margin:40px auto'>
<h1>🗂️ 文件分享</h1>{e}
<form method='post' action='/login'>
<input type='password' name='pw' placeholder='密码' required autofocus>
<button>登录</button></form>
<p class='muted'>没有用户名：不同的密码对应不同的账号，找管理员要你的密码。</p></div>""")

def dash_page(shares, user):
    is_admin = user["is_admin"]
    items = []
    for s in shares:
        files = share_files(s["id"])
        total = sum(f["size"] for f in files)
        typ = "发送" if s["type"] == "send" else "接收"
        cls = "" if s["type"] == "send" else "recv"
        link = f"/{'s' if s['type']=='send' else 'r'}/{s['id']}"
        # 管理员看全部分享：标出归属；普通用户只看得到自己的分享
        owner = ""
        if is_admin and s["owner_id"] is not None:
            owner = ("<span class='badge'>我的</span>" if s["owner_id"] == user["id"]
                     else f"<span class='badge recv'>用户#{s['owner_id']}</span>")
        items.append(f"""<div class='file'><div>
<span class='badge {cls}'>{typ}</span>{owner}<b id='ttl-{s['id']}'>{html.escape(s['title'] or '(无备注)')}</b>
<div class='muted'>{len(files)} 个文件 · {hsize(total)} · 到期：{htime(s['expires'])} <span id='ex-{s['id']}'></span></div>
<div class='linkbox' id='lk-{s['id']}'>{link}</div><div id='ti-{s['id']}'></div></div>
<div style='white-space:nowrap'>
<button class='ghost' onclick="copyLink('{s['id']}','{link}')">复制链接</button>
<button class='ghost' onclick="editTitle('{s['id']}')">改备注</button>
<button class='ghost' onclick="editExpiry('{s['id']}')">改过期</button>
<button class='danger' onclick="delShare('{s['id']}')">删除链接</button>
</div></div>""")
    frows = []
    for fr in all_files():
        fid, fn, fsz, fct = fr["id"], fr["filename"], fr["size"], fr["created"]
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
        ck = f"<input type='checkbox' class='fileck' value='{fid}'>" if is_admin else ""
        delbtn = (f"<button class='danger' onclick=\"delOneFile({fid})\">删除</button>"
                  if is_admin else "")
        dlbtn = f"<a href='/dl/{fid}'><button class='ghost'>下载</button></a> "
        frows.append(f"""<div class='file'><div>
{ck}<span class='badge {fcls}'>{ftyp}</span>{ownermk}<b>{html.escape(fn)}</b>
<div class='muted'>{hsize(fsz)} · 来自{fsrc} · {htime(fct)}</div>
</div>
<div style='white-space:nowrap'>{dlbtn}{delbtn}</div></div>""")
    flist = "".join(frows) if frows else "<p class='muted'>还没有任何文件</p>"
    lst = "".join(items) if items else "<p class='muted'>还没有分享，来创建一个吧 👆</p>"
    role = "👑 管理员" if is_admin else "👤 普通用户"
    share_title = "📋 分享链接（全部用户）" if is_admin else "📋 我的分享"
    filehint = ("发送和接收的所有文件都在这里。删除为彻底删除，不经过回收站。"
                if is_admin else "所有用户的文件都在这里。你没有删除文件的权限。")
    fileops = ("""<div class='row' style='margin-top:8px'>
<button class='ghost' onclick="toggleAllFiles()">全选 / 取消全选</button>
<button class='danger' onclick="delFiles()">删除选中</button>
</div>""") if is_admin else ""
    users_card = ""
    if is_admin:
        urows = []
        for u in list_users():
            remark = (u["remark"] or "").strip()
            rmk = (f"<span class='badge' id='rmk-{u['id']}'>{html.escape(remark)}</span> "
                   if remark else f"<span class='muted' id='rmk-{u['id']}'></span>")
            if u["is_admin"]:
                mark, who = "<span class='badge'>管理员</span>", "管理员"
                ops = ("<span class='muted'>这是你，改密码请用下面的「修改密码」</span>"
                       if u["id"] == user["id"] else "")
            else:
                mark, who = f"<span class='badge recv'>用户#{u['id']}</span>", "普通用户"
                ops = (f"<button class='ghost' onclick=\"togglePw({u['id']},this)\" title='查看密码'>👁</button> "
                       f"<button class='ghost' onclick=\"editRemark({u['id']})\">改备注</button> "
                       f"<button class='ghost' onclick=\"resetPw({u['id']})\">重设密码</button> "
                       f"<button class='danger' onclick=\"userDel({u['id']})\">删除用户</button>")
            urows.append(f"""<div class='file'><div>
{mark}<b>{who}</b> {rmk}
<div class='muted'>创建于 {htime(u['created'])}</div><div id='urp-{u['id']}'></div><div id='urm-{u['id']}'></div><div id='upw-{u['id']}'></div></div>
<div style='white-space:nowrap'>{ops}</div></div>""")
        users_card = f"""<div class='card'><h2>👥 用户管理</h2>
<p class='muted'>没有注册入口，账号只能由你添加。登录没有用户名：不同的密码就是不同的账号。备注名只给你自己看（比如这个账号给了谁），不影响登录。</p>
{''.join(urows)}
<form id='userAddForm'>
<input type='password' name='pw1' placeholder='新用户密码（至少4位）' required minlength='4'>
<input type='password' name='pw2' placeholder='再次输入' required minlength='4'>
<input type='text' name='remark' placeholder='备注名（可选，如：张三）' maxlength='50'>
<button class='ghost' style='width:100%'>添加用户</button></form><div id='userRes'></div></div>
"""
    return page("控制台", f"""<div class='topbar'><h1>🗂️ 文件分享</h1>
<div><span class='muted'>{role}</span>　<a href='/logout' class='muted'>退出登录</a></div></div>
<div class='card'><h2>📤 发送文件</h2>
<form id='sendForm'>
<input type='file' name='file' multiple required>
<input type='text' name='title' placeholder='备注（可选）' maxlength='100'>
<div class='row'><select name='expiry'>
<option value='7'>7 天后过期</option><option value='1'>1 天后过期</option>
<option value='30'>30 天后过期</option><option value='0'>永久有效</option>
</select></div>
<button>上传并生成分享链接</button>
<progress id='sendProg' value='0' max='100' style='display:none'></progress>
</form><div id='sendRes'></div></div>
<div class='card'><h2>📥 创建接收链接</h2>
<p class='muted'>把链接发给对方，对方打开网页上传文件，文件会存到你的服务器上。</p>
<form id='recvForm'>
<input type='text' name='title' placeholder='备注（可选，如：请小王传合同）' maxlength='100'>
<select name='expiry'><option value='7'>7 天后过期</option><option value='1'>1 天后过期</option>
<option value='30'>30 天后过期</option><option value='0'>永久有效</option></select>
<button>生成接收链接</button></form><div id='recvRes'></div></div>
<div class='card'><h2>{share_title}</h2>{lst}</div>
<div class='card'><h2>📁 全部文件</h2>
<p class='muted'>{filehint}</p>
{flist}
{fileops}<div id='fileRes'></div></div>
{users_card}<div class='card'><h2>🔑 修改密码</h2>
<form id='pwForm'>
<input type='password' name='new1' placeholder='新密码' required minlength='4'>
<input type='password' name='new2' placeholder='重复新密码' required minlength='4'>
<button class='ghost' style='width:100%'>修改密码</button></form><div id='pwRes'></div></div>
<script>
function fullLink(p){{return location.origin + p;}}
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
  fetch('/api/delete',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
    body:'id='+encodeURIComponent(id)}}).then(r=>r.json()).then(()=>location.reload());
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
  fetch('/api/del_files',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
    body:'ids='+encodeURIComponent(ids.join(','))}})
    .then(r=>r.json()).then(j=>{{if(j.ok)location.reload();else alert(j.error||'删除失败');}});
}}
function editExpiry(id){{
  var box=document.getElementById('ex-'+id);
  box.innerHTML="<select id='exs-"+id+"'><option value='1'>1 天后过期</option>"
    +"<option value='7' selected>7 天后过期</option><option value='30'>30 天后过期</option>"
    +"<option value='0'>永久有效</option></select> "
    +"<button class='ghost' onclick=\\\"saveExpiry('\\\"+id+\\\"')\\\">确定</button>"
    +"<button class='ghost' onclick=\\\"cancelExpiry('\\\"+id+\\\"')\\\">取消</button>";
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
  fetch('/api/title',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
    body:'id='+encodeURIComponent(id)+'&title='+encodeURIComponent(v)}})
  .then(function(r){{return r.json().then(function(d){{return {{s:r.status,d:d}};}});}})
  .then(function(x){{
    if(x.d.ok){{location.reload();}}else{{alert('保存失败：'+(x.d.error||x.s));}}
  }});
}}
function saveExpiry(id){{
  var v=document.getElementById('exs-'+id).value;
  fetch('/api/expiry',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
    body:'id='+encodeURIComponent(id)+'&expiry='+encodeURIComponent(v)}})
    .then(r=>r.json()).then(j=>{{if(j.ok)location.reload();else alert(j.error||'修改失败');}});
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
        if(j.ok){{res.innerHTML="<div class='ok'>"+okText+"</div><div class='linkbox'>"+fullLink(j.link)+"</div><button class='ghost' onclick=\\"copyText(fullLink('"+j.link+"'),this.previousElementSibling)\\">复制链接</button>";
          setTimeout(()=>location.reload(), 1500);
        }}else{{res.innerHTML="<div class='err'>"+(j.error||'失败')+"</div>";}}
      }}catch(e){{res.innerHTML="<div class='err'>请求失败("+xhr.status+")</div>";}}
    }};
    xhr.onerror=function(){{if(prog)prog.style.display='none';res.innerHTML="<div class='err'>网络错误</div>";}};
    xhr.send(new FormData(f));
  }});
}}
bindXhr('sendForm','/api/share','sendRes','sendProg','上传成功，分享链接：');
bindXhr('recvForm','/api/receive','recvRes',null,'接收链接已生成：');
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
document.getElementById('pwForm').addEventListener('submit', function(ev){{
  ev.preventDefault();
  postForm('/api/chpw', this, 'pwRes', "<div class='ok'>密码已修改</div>");
}});
function userDel(id){{
  if(!confirm('确定删除这个用户吗？他的分享链接会失效，文件会保留在「全部文件」里。'))return;
  fetch('/api/user_del',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
    body:'id='+encodeURIComponent(id)}})
    .then(r=>r.json()).then(j=>{{if(j.ok)location.reload();else alert(j.error||'删除失败');}});
}}
function resetPw(id){{
  var box=document.getElementById('urp-'+id);
  box.innerHTML="<input type='password' id='rp1-"+id+"' placeholder='新密码' minlength='4'> "
    +"<input type='password' id='rp2-"+id+"' placeholder='再次输入' minlength='4'> "
    +"<button class='ghost' onclick=\\\"saveResetPw('\\\"+id+\\\"')\\\">确定</button> "
    +"<button class='ghost' onclick=\\\"cancelResetPw('\\\"+id+\\\"')\\\">取消</button>";
}}
function cancelResetPw(id){{document.getElementById('urp-'+id).innerHTML='';}}
function saveResetPw(id){{
  var a=document.getElementById('rp1-'+id).value, b=document.getElementById('rp2-'+id).value;
  fetch('/api/user_resetpw',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
    body:'id='+encodeURIComponent(id)+'&pw1='+encodeURIComponent(a)+'&pw2='+encodeURIComponent(b)}})
    .then(r=>r.json()).then(j=>{{if(j.ok)location.reload();else alert(j.error||'重设失败');}});
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
  fetch('/api/user_remark',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
    body:'id='+encodeURIComponent(id)+'&remark='+encodeURIComponent(v)}})
    .then(r=>r.json()).then(j=>{{if(j.ok)location.reload();else alert(j.error||'保存失败');}});
}}
// 眼睛：管理员查看某个账号的当前密码。只在管理员的"用户管理"里有这个按钮，
// 普通用户登录后根本看不到这一整块，所以用户本人不会知道。
function togglePw(id, btn){{
  var box=document.getElementById('upw-'+id);
  if(box.dataset.open==='1'){{box.innerHTML='';box.dataset.open='';btn.textContent='👁';return;}}
  fetch('/api/user_pw',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
    body:'id='+encodeURIComponent(id)}})
    .then(r=>r.json()).then(j=>{{
      if(!j.ok){{alert(j.error||'查看失败');return;}}
      box.dataset.open='1'; btn.textContent='👁‍🗨';
      box.innerHTML='';
      var t=document.createElement('span');
      t.className='muted'; t.textContent='密码：';
      var b=document.createElement('b');
      b.textContent=j.pw||'（老账号，明文未知，改一次密码后可见）';
      var cp=document.createElement('button');
      cp.className='ghost'; cp.textContent='复制'; cp.style.marginLeft='8px';
      cp.onclick=function(){{
        var done=function(){{cp.textContent='已复制';}};
        if(navigator.clipboard&&navigator.clipboard.writeText){{
          navigator.clipboard.writeText(j.pw).then(done,function(){{cp.textContent='复制失败';}});
        }}else{{
          var ta=document.createElement('textarea');ta.value=j.pw;document.body.appendChild(ta);
          ta.select();try{{document.execCommand('copy');done();}}catch(e){{cp.textContent='复制失败';}}
          document.body.removeChild(ta);
        }}
      }};
      box.appendChild(t); box.appendChild(b);
      if(j.pw)box.appendChild(cp);
    }});
}}
var _uaf=document.getElementById('userAddForm');
if(_uaf){{_uaf.addEventListener('submit', function(ev){{
  ev.preventDefault();
  postForm('/api/user_add', this, 'userRes', "<div class='ok'>用户已添加，记得把密码告诉他</div>")
  .then(function(j){{if(j.ok)setTimeout(function(){{location.reload();}},1200);}});
}});}}
</script>{disk_foot()}""")

# 能安全在线查看的文件类型（按扩展名判断）。
# svg 故意不算图片：内联打开时 SVG 里的脚本会在本站域名下执行，有风险，只给下载。
# pdf 单独一种：浏览器自带的 PDF 阅读器打开是安全的（不会执行页面脚本），
# 所以给"查看"按钮；但分享列表里不内联嵌入（整文件嵌进去太重），只给按钮。
IMG_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
VID_EXTS = {".mp4", ".webm", ".ogg", ".ogv", ".mov", ".m4v", ".mkv"}
PDF_EXTS = {".pdf"}

def _view_kind(filename):
    """返回 'img' / 'vid' / 'pdf'，不能在线查看的返回 None。"""
    ext = os.path.splitext(filename)[1].lower()
    if ext in IMG_EXTS:
        return "img"
    if ext in VID_EXTS:
        return "vid"
    if ext in PDF_EXTS:
        return "pdf"
    return None

def share_page(sid, share, files, user=None):
    # user 能管理这个分享（本人或管理员）时，页面上可以追加和删除文件
    manage = user is not None and can_manage_share(user, share)
    rows = []
    for f in files:
        name = html.escape(f["filename"])
        kind = _view_kind(f["filename"])
        media = ""
        if kind == "img":
            media = (f"<a href='/s/{sid}/v/{f['id']}' target='_blank'>"
                     f"<img src='/s/{sid}/v/{f['id']}' loading='lazy' alt='{name}' "
                     "style='max-width:100%;max-height:340px;border-radius:8px;"
                     "display:block;margin-bottom:8px'></a>")
        elif kind == "vid":
            media = (f"<video controls preload='metadata' src='/s/{sid}/v/{f['id']}' "
                     "style='max-width:100%;max-height:340px;border-radius:8px;"
                     "display:block;margin-bottom:8px'></video>")
        view_btn = (f"<a href='/s/{sid}/v/{f['id']}' target='_blank'>"
                    "<button class='ghost'>查看</button></a> " if kind else "")
        del_btn = (f"<button class='ghost' onclick='delShareFile({f['id']},this)'>删除</button> "
                   if manage else "")
        rows.append(f"""<div class='file' style='display:block'>{media}<div>📄 {name}
<div class='muted'>{hsize(f['size'])}</div></div>
<div style='margin-top:6px'>{view_btn}{del_btn}<a href='/s/{sid}/f/{f['id']}'><button class='ghost'>下载</button></a></div></div>""")
    add_form = ""
    if manage:
        add_form = """<div class='card' style='max-width:560px;margin:16px auto'>
<h3>➕ 添加文件</h3>
<form id='addForm'><input type='file' name='file' multiple required>
<button>上传</button>
<progress id='addProg' value='0' max='100' style='display:none'></progress></form>
<div id='addRes'></div></div>
<script>
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
document.getElementById('addForm').addEventListener('submit', function(ev){
  ev.preventDefault();
  var res=document.getElementById('addRes'), prog=document.getElementById('addProg');
  res.innerHTML=''; prog.style.display='block'; prog.value=0;
  var xhr=new XMLHttpRequest(); xhr.open('POST', location.pathname+'/add');
  xhr.upload.onprogress=function(e){if(e.lengthComputable)prog.value=e.loaded/e.total*100;};
  xhr.onload=function(){
    prog.style.display='none';
    try{var j=JSON.parse(xhr.responseText);
      if(j.ok) location.reload();
      else res.innerHTML="<div class='err'>"+(j.error||'上传失败')+"</div>";
    }catch(e){res.innerHTML="<div class='err'>请求失败("+xhr.status+")</div>";}
  };
  xhr.onerror=function(){prog.style.display='none';res.innerHTML="<div class='err'>网络错误</div>";};
  xhr.send(new FormData(this));
});
</script>"""
    return page("下载文件", f"""<div class='card' style='max-width:560px;margin:30px auto'>
<h1>📥 {html.escape(share['title'] or '文件分享')}</h1>
<p class='muted'>共 {len(files)} 个文件 · 到期：{htime(share['expires'])}</p>
{''.join(rows) if rows else "<p class='muted'>📭 文件都被删除啦</p>"}
</div>{add_form}""")

def receive_page(sid, share):
    limit, _ = upload_limit()
    return page("上传文件", f"""<div class='card' style='max-width:560px;margin:30px auto'>
<h1>📤 {html.escape(share['title'] or '文件接收')}</h1>
<p class='muted'>选择文件上传，上传完成后对方即可收到。到期：{htime(share['expires'])}</p>
<p class='muted'>📦最大可上传 <b>{hsize(limit)}</b>文件</p>
<form id='upForm'><input type='file' name='file' multiple required>
<button>开始上传</button>
<progress id='prog' value='0' max='100' style='display:none'></progress></form>
<div id='res'></div></div>
<script>
document.getElementById('upForm').addEventListener('submit', function(ev){{
  ev.preventDefault();
  var res=document.getElementById('res'), prog=document.getElementById('prog');
  res.innerHTML=''; prog.style.display='block'; prog.value=0;
  var xhr=new XMLHttpRequest(); xhr.open('POST', location.pathname+'/upload');
  xhr.upload.onprogress=function(e){{if(e.lengthComputable)prog.value=e.loaded/e.total*100;}};
  xhr.onload=function(){{
    prog.style.display='none';
    try{{var j=JSON.parse(xhr.responseText);
      res.innerHTML = j.ok ? "<div class='ok'>上传成功，共 "+j.count+" 个文件 ✅</div>"
                           : "<div class='err'>"+(j.error||'上传失败')+"</div>";
    }}catch(e){{res.innerHTML="<div class='err'>请求失败("+xhr.status+")</div>";}}
  }};
  xhr.onerror=function(){{prog.style.display='none';res.innerHTML="<div class='err'>网络错误</div>";}};
  xhr.send(new FormData(this));
}});
</script>""")

def not_found():
    return page("不存在", "<div class='card' style='max-width:420px;margin:40px auto'><h1>😅 链接不存在或已过期</h1><p class='muted'>请检查链接是否正确，或联系分享者。</p></div>")

# ---------------- HTTP 服务 ----------------
class Handler(BaseHTTPRequestHandler):
    server_version = "minishare/1.0"
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
        if self.close_connection:
            # 出错路径（请求体没读完）会关连接：明确告诉客户端不要复用，
            # 否则它会把残留的请求体当成下一个请求的响应来读。
            self.send_header("Connection", "close")
        self.end_headers()
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

    def _login_allowed(self):
        ip = self.client_address[0]
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
        ip = self.client_address[0]
        with self.server._login_lock:
            self.server._login_fail.setdefault(ip, []).append(time.time())

    def _login_ok(self):
        ip = self.client_address[0]
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
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
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

    def _send_file(self, path, filename):
        size = os.path.getsize(path)
        ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(size))
        self.send_header("Accept-Ranges", "none")
        self.send_header("X-Content-Type-Options", "nosniff")
        disp = "attachment; filename*=UTF-8''%s" % quote(filename)
        self.send_header("Content-Disposition", disp)
        self.end_headers()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def _send_file_inline(self, path, filename):
        """在线查看：Content-Disposition: inline + 支持 Range 分片（视频拖进度条需要）。"""
        size = os.path.getsize(path)
        ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        if ctype.split("/")[0] not in ("image", "video") and ctype != "application/pdf":
            # 非图片/视频/PDF：不内联，退回普通下载（防 MIME 混淆）。
            # PDF 例外：浏览器用自带阅读器渲染，不会执行页面脚本，安全。
            return self._send_file(path, filename)
        start, end, status = 0, size - 1, 200
        rh = (self.headers.get("Range") or "").strip()
        if rh:
            m = re.fullmatch(r"bytes=(\d*)-(\d*)", rh)
            if not m or (not m.group(1) and not m.group(2)):
                return self._send(416, "Range 不合法", "text/plain; charset=utf-8")
            if m.group(1):
                start = int(m.group(1))
                end = int(m.group(2)) if m.group(2) else size - 1
            else:
                # bytes=-N：文件最后 N 字节
                start = max(size - int(m.group(2)), 0)
            end = min(end, size - 1)
            if start >= size or end < start:
                self.send_response(416)
                self.send_header("Content-Range", "bytes */%d" % size)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            status = 206
        length = end - start + 1
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        if status == 206:
            self.send_header("Content-Range",
                             "bytes %d-%d/%d" % (start, end, size))
        self.send_header("Content-Disposition", "inline")
        # 防 MIME 嗅探：浏览器只能按声明的 Content-Type 处理
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
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
                return self._send(200, dash_page(shares, user))

            m = re.fullmatch(r"/dl/(\d+)", p)
            if m:
                # 控制台"全部文件"的下载按钮：登录即可下载，
                # 分享链接已删的孤儿文件也能下（/s/<sid>/f/<fid> 走不通）
                if not self._user():
                    return self._redirect("/login")
                with db() as c:
                    f = c.execute("SELECT f.*, s.expires FROM files f"
                                  " LEFT JOIN shares s ON s.id=f.share_id"
                                  " WHERE f.id=?",
                                  (int(m.group(1)),)).fetchone()
                if not f:
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

            m = re.fullmatch(r"/s/([A-Za-z0-9_\-]{1,16})/f/(\d+)", p)
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

            m = re.fullmatch(r"/s/([A-Za-z0-9_\-]{1,16})/v/(\d+)", p)
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
                self._send(500, page("出错", "<div class='card'><h1>😵 出错了</h1></div>"))
            except Exception:
                pass

    # ---- POST ----
    def do_POST(self):
        try:
            p = urlparse(self.path).path
            if p == "/setup" and not has_users():
                f = self._form()
                pw1, pw2 = f.get("pw1", ""), f.get("pw2", "")
                if len(pw1) < 4:
                    return self._send(200, setup_page("密码至少 4 位"))
                if pw1 != pw2:
                    return self._send(200, setup_page("两次输入不一致"))
                # 首个账号即管理员
                admin = create_user(pw1, is_admin=True)
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
                if not files:
                    return self._json({"ok": False, "error": "没有收到文件"}, 400)
                now = int(time.time())
                try:
                    with db() as c:
                        for fo in files:
                            c.execute("INSERT INTO files(share_id,filename,stored,size,created)"
                                      " VALUES(?,?,?,?,?)",
                                      (sid, fo["filename"], fo["stored"], fo["size"], now))
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
                if not re.fullmatch(r"[0-9]+", fid or ""):
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
                            c.execute("INSERT INTO files(share_id,filename,stored,size,created)"
                                      " VALUES(?,?,?,?,?)",
                                      (sid, fo["filename"], fo["stored"], fo["size"], now))
                except Exception:
                    # 入库失败（如磁盘满）：删掉已落盘的文件，不能留孤儿占空间
                    for fo in files:
                        try:
                            os.unlink(os.path.join(FILES_DIR, fo["stored"]))
                        except OSError:
                            pass
                    raise
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
                s = get_share(sid)
                if not s:
                    return self._json({"ok": False, "error": "分享不存在"}, 404)
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
                       if re.fullmatch(r"[0-9]+", x.strip() or "")]
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
                with db() as c:
                    s = c.execute("SELECT id, owner_id FROM shares WHERE id=?",
                                  (sid,)).fetchone()
                    if not s:
                        return self._json({"ok": False, "error": "分享不存在"}, 404)
                    if not can_manage_share(user, s):
                        return self._json({"ok": False, "error": "只能修改自己的分享"}, 403)
                    days = _expiry_days(f.get("expiry"))
                    now = int(time.time())
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
                with db() as c:
                    s = c.execute("SELECT owner_id FROM shares WHERE id=?",
                                  (sid,)).fetchone()
                    if not s:
                        return self._json({"ok": False, "error": "分享不存在"}, 404)
                    if not can_manage_share(user, s):
                        return self._json({"ok": False, "error": "只能修改自己的分享"}, 403)
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
                try:
                    uid = int(f.get("id", ""))
                except (TypeError, ValueError):
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
                try:
                    uid = int(f.get("id", ""))
                except (TypeError, ValueError):
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
                try:
                    uid = int(f.get("id", ""))
                except (TypeError, ValueError):
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
                try:
                    uid = int(f.get("id", ""))
                except (TypeError, ValueError):
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
                if not files:
                    return self._json({"ok": False, "error": "没有收到文件"}, 400)
                now = int(time.time())
                try:
                    with db() as c:
                        for fo in files:
                            c.execute("INSERT INTO files(share_id,filename,stored,size,created)"
                                      " VALUES(?,?,?,?,?)",
                                      (sid, fo["filename"], fo["stored"], fo["size"], now))
                except Exception:
                    # 入库失败（如磁盘满）：删掉已落盘的文件，不能留孤儿占空间
                    for fo in files:
                        try:
                            os.unlink(os.path.join(FILES_DIR, fo["stored"]))
                        except OSError:
                            pass
                    raise
                return self._json({"ok": True, "count": len(files)})

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


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--check":
        sys.exit(check_server(sys.argv[2], int(sys.argv[3])))
    init_db()
    cleanup_expired()
    threading.Thread(target=cleanup_loop, daemon=True).start()
    srv = Server((HOST, PORT), Handler)
    srv.daemon_threads = True
    url_host = f"[{HOST}]" if ":" in HOST else HOST
    print(f"minishare 启动：http://{url_host}:{PORT}  数据目录={DATA_DIR} MSS={MSS}",
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
