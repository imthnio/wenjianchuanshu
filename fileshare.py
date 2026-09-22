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
        c.execute("""CREATE TABLE IF NOT EXISTS sessions(
            token TEXT PRIMARY KEY, created INTEGER, expires INTEGER)""")
        c.execute("""CREATE TABLE IF NOT EXISTS shares(
            id TEXT PRIMARY KEY, type TEXT, title TEXT,
            created INTEGER, expires INTEGER)""")
        c.execute("""CREATE TABLE IF NOT EXISTS files(
            id INTEGER PRIMARY KEY AUTOINCREMENT, share_id TEXT,
            filename TEXT, stored TEXT, size INTEGER, created INTEGER)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_files_share ON files(share_id)")

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
    except ValueError:
        return False
    return hmac.compare_digest(hash_pw(pw, bytes.fromhex(salt_hex)), stored)

def new_session():
    tok = secrets.token_urlsafe(32)
    now = int(time.time())
    with db() as c:
        c.execute("INSERT INTO sessions(token,created,expires) VALUES(?,?,?)",
                  (tok, now, now + SESSION_DAYS * 86400))
    return tok

def valid_session(tok):
    if not tok:
        return False
    with db() as c:
        r = c.execute("SELECT expires FROM sessions WHERE token=?", (tok,)).fetchone()
    return bool(r and r["expires"] > time.time())

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
    with db() as c:
        for f in c.execute("SELECT stored FROM files WHERE share_id=?", (sid,)).fetchall():
            try:
                os.unlink(os.path.join(FILES_DIR, f["stored"]))
            except OSError:
                pass
        c.execute("DELETE FROM files WHERE share_id=?", (sid,))
        c.execute("DELETE FROM shares WHERE id=?", (sid,))

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

def _fix_header_encoding(v):
    """HTTP 头是按 latin1 解码的；如果里面实际是 UTF-8 字节（如中文文件名），还原它。"""
    try:
        return v.encode("latin1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return v

def _disp_param(disp, key):
    """从 Content-Disposition 头取参数，支持 filename*=UTF-8''... 形式"""
    kl = key.lower()
    for part in disp.split(";"):
        p = part.strip()
        pl = p.lower()
        if pl.startswith(kl + "*="):
            v = p.split("=", 1)[1].strip()
            if "''" in v:
                enc, _, val = v.partition("''")
                return unquote(val, encoding=enc or "utf-8", errors="replace")
            return v.strip('"')
        if pl.startswith(kl + "="):
            v = p.split("=", 1)[1].strip()
            if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                v = v[1:-1]
            return _fix_header_encoding(v)
    return None

def _clean_filename(fn):
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
    if total > max_bytes:
        raise UploadTooLarge()
    bnd = b"--" + boundary
    delim = b"\r\n" + bnd
    buf = bytearray()
    remaining = total
    fields, files = {}, []
    created_paths = []

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
        headers = {}
        while True:
            eol = -1
            while eol == -1:
                if not fill(4):
                    raise BadUpload("truncated headers")
                eol = bytes(buf).find(b"\r\n")
                if eol == -1 and len(buf) > 65536:
                    raise BadUpload("header too long")
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
                    ended = b[i + len(delim):i + len(delim) + 2] == b"--"
                    del buf[:i + len(delim) + 2]
                    out.close()
                    return size, ended
                if len(buf) > keep:
                    out.write(buf[:-keep])
                    size += len(buf) - keep
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
            if not fill(len(bnd) + 2):
                raise BadUpload("no boundary")
            i = bytes(buf).find(bnd)
            if i != -1:
                del buf[:i]
                break
            if len(buf) > 1024 * 1024:
                raise BadUpload("preamble too long")
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
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
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
<input type='password' name='pw' placeholder='管理员密码' required autofocus>
<button>登录</button></form></div>""")

def dash_page(shares):
    items = []
    for s in shares:
        files = share_files(s["id"])
        total = sum(f["size"] for f in files)
        typ = "发送" if s["type"] == "send" else "接收"
        cls = "" if s["type"] == "send" else "recv"
        link = f"/{'s' if s['type']=='send' else 'r'}/{s['id']}"
        items.append(f"""<div class='file'><div>
<span class='badge {cls}'>{typ}</span><b>{html.escape(s['title'] or '(无备注)')}</b>
<div class='muted'>{len(files)} 个文件 · {hsize(total)} · 到期：{htime(s['expires'])}</div>
<div class='linkbox' id='lk-{s['id']}'></div></div>
<div style='white-space:nowrap'>
<button class='ghost' onclick="copyLink('{s['id']}','{link}')">复制链接</button>
<button class='danger' onclick="delShare('{s['id']}')">删除</button>
</div></div>""")
    lst = "".join(items) if items else "<p class='muted'>还没有分享，来创建一个吧 👆</p>"
    return page("控制台", f"""<div class='topbar'><h1>🗂️ 文件分享</h1>
<a href='/logout' class='muted'>退出登录</a></div>
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
<div class='card'><h2>📋 我的分享</h2>{lst}</div>
<div class='card'><h2>🔑 修改密码</h2>
<form id='pwForm'>
<input type='password' name='old' placeholder='当前密码' required>
<input type='password' name='new1' placeholder='新密码' required minlength='4'>
<input type='password' name='new2' placeholder='重复新密码' required minlength='4'>
<button class='ghost' style='width:100%'>修改密码</button></form><div id='pwRes'></div></div>
<script>
function fullLink(p){{return location.origin + p;}}
function copyLink(id, p){{
  var el = document.getElementById('lk-'+id);
  el.textContent = fullLink(p);
  navigator.clipboard.writeText(fullLink(p)).then(()=>{{el.innerHTML='<span class=ok>已复制到剪贴板</span>';}});
}}
function delShare(id){{
  if(!confirm('确定删除这个分享吗？文件也会一起删除。')) return;
  fetch('/api/delete',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
    body:'id='+encodeURIComponent(id)}}).then(r=>r.json()).then(()=>location.reload());
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
        if(j.ok){{res.innerHTML="<div class='ok'>"+okText+"</div><div class='linkbox'>"+fullLink(j.link)+"</div><button class='ghost' onclick=\\"navigator.clipboard.writeText(fullLink('"+j.link+"'))\\">复制链接</button>";
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
document.getElementById('pwForm').addEventListener('submit', function(ev){{
  ev.preventDefault();
  var fd=new FormData(this);
  fetch('/api/chpw',{{method:'POST',body:new URLSearchParams([...fd])}})
    .then(r=>r.json()).then(j=>{{
      document.getElementById('pwRes').innerHTML = j.ok?"<div class='ok'>密码已修改</div>":"<div class='err'>"+(j.error||'失败')+"</div>";
    }});
}});
</script>""")

def share_page(sid, share, files, base):
    rows = []
    for f in files:
        rows.append(f"""<div class='file'><div>📄 {html.escape(f['filename'])}
<div class='muted'>{hsize(f['size'])}</div></div>
<a href='/s/{sid}/f/{f['id']}'><button class='ghost'>下载</button></a></div>""")
    return page("下载文件", f"""<div class='card' style='max-width:560px;margin:30px auto'>
<h1>📥 {html.escape(share['title'] or '文件分享')}</h1>
<p class='muted'>共 {len(files)} 个文件 · 到期：{htime(share['expires'])}</p>
{''.join(rows) if rows else "<p class='muted'>文件已被删除</p>"}
<p class='muted' style='margin-top:16px'>由 minishare 提供 · {html.escape(base)}</p></div>""")

def receive_page(sid, share):
    return page("上传文件", f"""<div class='card' style='max-width:560px;margin:30px auto'>
<h1>📤 {html.escape(share['title'] or '文件接收')}</h1>
<p class='muted'>选择文件上传，上传完成后对方即可收到。到期：{htime(share['expires'])}</p>
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

    def _authed(self):
        return valid_session(self._cookie().get("sid"))

    def _base(self):
        proto = self.headers.get("X-Forwarded-Proto", "http")
        host = (self.headers.get("X-Forwarded-Host") or self.headers.get("Host")
                or f"{HOST}:{PORT}")
        return f"{proto}://{host}"

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False),
                   "application/json; charset=utf-8")

    def _redirect(self, loc):
        self.send_response(302)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
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
        self.end_headers()

    def _form(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n > 0 else b""
        d = parse_qs(raw.decode("utf-8", "replace"))
        return {k: v[0] for k, v in d.items()}

    def _multipart(self):
        ctype = self.headers.get("Content-Type", "")
        m = re.search(r"boundary=([^;]+)", ctype)
        if not m:
            raise BadUpload("no boundary")
        boundary = m.group(1).strip().strip('"').encode("latin1")
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            raise BadUpload("empty body")
        if self.headers.get("Expect", "").lower() == "100-continue":
            self.send_response_only(100)
            self.end_headers()
        return parse_multipart(self.rfile, n, boundary, MAX_UPLOAD)

    def _send_file(self, path, filename):
        size = os.path.getsize(path)
        ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(size))
        self.send_header("Accept-Ranges", "none")
        disp = "attachment; filename*=UTF-8''%s" % quote(filename)
        self.send_header("Content-Disposition", disp)
        self.end_headers()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                self.wfile.write(chunk)

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
            p = urlparse(self.path).path
            if p == "/healthz":
                # Check SQLite too: a listening socket alone does not mean the app works.
                meta_get("pw")
                return self._json({"service": "minishare", "ok": True})
            if not meta_get("pw"):
                if p in ("/", "/setup"):
                    return self._send(200, setup_page())
                return self._redirect("/")
            if p == "/":
                return self._redirect("/dash" if self._authed() else "/login")
            if p == "/login":
                if self._authed():
                    return self._redirect("/dash")
                return self._send(200, login_page())
            if p == "/logout":
                return self._clear_sid()
            if p == "/dash":
                if not self._authed():
                    return self._redirect("/login")
                with db() as c:
                    shares = c.execute(
                        "SELECT * FROM shares ORDER BY created DESC").fetchall()
                return self._send(200, dash_page(shares))

            m = re.fullmatch(r"/s/([A-Za-z0-9_\-]{1,16})", p)
            if m:
                sid = m.group(1)
                s = self._valid_share(sid)
                if not s:
                    return self._send(404, not_found())
                if s["type"] == "receive":
                    return self._redirect(f"/r/{sid}")
                return self._send(200, share_page(sid, s, share_files(sid), self._base()))

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
            try:
                self._send(500, page("出错", "<div class='card'><h1>😵 出错了</h1></div>"))
            except Exception:
                pass

    # ---- POST ----
    def do_POST(self):
        try:
            p = urlparse(self.path).path
            if p == "/setup" and not meta_get("pw"):
                f = self._form()
                pw1, pw2 = f.get("pw1", ""), f.get("pw2", "")
                if len(pw1) < 4:
                    return self._send(200, setup_page("密码至少 4 位"))
                if pw1 != pw2:
                    return self._send(200, setup_page("两次输入不一致"))
                meta_set("pw", hash_pw(pw1))
                return self._set_sid(new_session())

            if p == "/login" and meta_get("pw"):
                f = self._form()
                if check_pw(f.get("pw", ""), meta_get("pw")):
                    return self._set_sid(new_session())
                return self._send(200, login_page("密码错误"))

            if p == "/logout":
                return self._clear_sid()

            if p == "/api/share":
                if not self._authed():
                    return self._json({"ok": False, "error": "未登录"}, 401)
                try:
                    fields, files = self._multipart()
                except UploadTooLarge:
                    return self._json({"ok": False, "error": "文件太大，超出上限"}, 413)
                except BadUpload as e:
                    return self._json({"ok": False, "error": f"上传解析失败: {e}"}, 400)
                if not files:
                    return self._json({"ok": False, "error": "没有收到文件"}, 400)
                title = (fields.get("title") or "").strip()[:100]
                days = _expiry_days(fields.get("expiry"))
                now = int(time.time())
                sid = new_share_id()
                with db() as c:
                    c.execute("INSERT INTO shares(id,type,title,created,expires)"
                              " VALUES(?,?,?,?,?)",
                              (sid, "send", title, now, now + days * 86400 if days else 0))
                    for fo in files:
                        c.execute("INSERT INTO files(share_id,filename,stored,size,created)"
                                  " VALUES(?,?,?,?,?)",
                                  (sid, fo["filename"], fo["stored"], fo["size"], now))
                return self._json({"ok": True, "link": f"/s/{sid}", "id": sid})

            if p == "/api/receive":
                if not self._authed():
                    return self._json({"ok": False, "error": "未登录"}, 401)
                try:
                    fields, _ = self._multipart()
                except (UploadTooLarge, BadUpload) as e:
                    return self._json({"ok": False, "error": str(e)}, 400)
                title = (fields.get("title") or "").strip()[:100]
                days = _expiry_days(fields.get("expiry"))
                now = int(time.time())
                sid = new_share_id()
                with db() as c:
                    c.execute("INSERT INTO shares(id,type,title,created,expires)"
                              " VALUES(?,?,?,?,?)",
                              (sid, "receive", title, now, now + days * 86400 if days else 0))
                return self._json({"ok": True, "link": f"/r/{sid}", "id": sid})

            if p == "/api/delete":
                if not self._authed():
                    return self._json({"ok": False, "error": "未登录"}, 401)
                f = self._form()
                if f.get("id"):
                    delete_share(f["id"])
                return self._json({"ok": True})

            if p == "/api/chpw":
                if not self._authed():
                    return self._json({"ok": False, "error": "未登录"}, 401)
                f = self._form()
                if not check_pw(f.get("old", ""), meta_get("pw")):
                    return self._json({"ok": False, "error": "当前密码错误"})
                if len(f.get("new1", "")) < 4 or f.get("new1") != f.get("new2"):
                    return self._json({"ok": False, "error": "新密码至少4位且两次一致"})
                meta_set("pw", hash_pw(f["new1"]))
                return self._json({"ok": True})

            m = re.fullmatch(r"/r/([A-Za-z0-9_\-]{1,16})/upload", p)
            if m:
                sid = m.group(1)
                s = self._valid_share(sid, "receive")
                if not s:
                    return self._json({"ok": False, "error": "链接不存在或已过期"}, 404)
                try:
                    _, files = self._multipart()
                except UploadTooLarge:
                    return self._json({"ok": False, "error": "文件太大，超出上限"}, 413)
                except BadUpload as e:
                    return self._json({"ok": False, "error": f"上传解析失败: {e}"}, 400)
                if not files:
                    return self._json({"ok": False, "error": "没有收到文件"}, 400)
                now = int(time.time())
                with db() as c:
                    for fo in files:
                        c.execute("INSERT INTO files(share_id,filename,stored,size,created)"
                                  " VALUES(?,?,?,?,?)",
                                  (sid, fo["filename"], fo["stored"], fo["size"], now))
                return self._json({"ok": True, "count": len(files)})

            return self._json({"ok": False, "error": "unknown"}, 404)
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            self.log_message("POST %s error: %s", self.path, e)
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
        super().__init__(server_address, handler, bind_and_activate)

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
