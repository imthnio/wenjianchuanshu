"""Regression tests: real local HTTP/SQLite, IPv4/IPv6 and installer failure handling."""
import contextlib
import http.client
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import re
import socket
import subprocess
import tempfile
import json
import threading
import time
import unittest
import urllib.parse
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fileshare', ROOT / 'fileshare.py')
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

class Connectivity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        app.DATA_DIR = self.tmp.name
        app.FILES_DIR = os.path.join(self.tmp.name, 'files')
        app.DB_PATH = os.path.join(self.tmp.name, 'share.db')
        app.init_db()
        self.addCleanup(self.tmp.cleanup)

    @contextlib.contextmanager
    def server(self, host):
        srv = app.Server((host, 0), app.Handler)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        try:
            yield srv.server_address[1]
        finally:
            srv.shutdown()
            srv.server_close()
            thread.join(2)

    def request(self, host, port, path):
        c = http.client.HTTPConnection(host, port, timeout=2)
        try:
            c.request('GET', path)
            r = c.getresponse()
            return r.status, r.read()
        finally:
            c.close()

    def exercise(self, bind, client):
        with self.server(bind) as port:
            status, body = self.request(client, port, '/')
            self.assertEqual(status, 200)
            self.assertIn(b"action='/setup'", body)
            self.assertEqual(app.check_server(bind, port, attempts=1), 0)
            app.meta_set('pw', app.hash_pw('test-local-only'))
            self.assertEqual(self.request(client, port, '/')[0], 302)
            self.assertEqual(self.request(client, port, '/login')[0], 200)
            self.assertEqual(app.check_server(bind, port, attempts=1), 0)

    def test_ipv4(self):
        self.exercise('0.0.0.0', '127.0.0.1')

    @unittest.skipUnless(socket.has_ipv6, 'IPv6 unavailable')
    def test_ipv6(self):
        self.exercise('::', '::1')

    def test_dash_expiry_buttons_have_valid_onclick(self):
        # 回归测试：控制台"改过期"的确定/取消按钮由 JS 拼出 onclick，
        # 引号错位会导致运行时生成 onclick="saveExpiry("+id+"')" 这种坏 HTML，
        # 点确定没反应。正确应为 onclick="saveExpiry('"+id+"')"。
        now = int(time.time())
        with app.db() as c:
            c.execute("INSERT INTO shares(id,type,title,created,expires) VALUES(?,?,?,?,?)",
                      ("abC123-_", "send", "t", now, 0))
            shares = c.execute("SELECT * FROM shares").fetchall()
        body = app.dash_page(shares).decode("utf-8")
        self.assertIn('saveExpiry(\'\\"+id+\\"\')', body)
        self.assertIn('cancelExpiry(\'\\"+id+\\"\')', body)
        self.assertNotIn('saveExpiry(\\"+id+\\")', body)

    def test_oversized_form_rejected_without_reading(self):
        # 普通表单超过 1MB 直接 400，不读进内存
        with self.server("127.0.0.1") as port:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/setup", body=b"x=1",
                      headers={"Content-Type": "application/x-www-form-urlencoded",
                               "Content-Length": "2000000"})
            r = c.getresponse()
            self.assertEqual(r.status, 400)
            c.close()

    def test_error_paths_close_connection(self):
        # 请求体没读完就报错（超大上传）时必须关连接并带 Connection: close，
        # 否则残留的请求体会污染同一 keep-alive 连接上的下一个请求
        # （曾实测到服务端把请求体当成新请求解析，吐出 400/414 垃圾）。
        old_max = app.MAX_UPLOAD
        app.MAX_UPLOAD = 200
        try:
            with self.server("127.0.0.1") as port:
                app.meta_set("pw", app.hash_pw("pw123456"))
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request("POST", "/login",
                          body=urllib.parse.urlencode({"pw": "pw123456"}).encode(),
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
                r = c.getresponse()
                r.read()
                cookie = r.getheader("Set-Cookie").split(";")[0]
                bnd = "----t"
                mp = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; "
                      f"filename=\"a.txt\"\r\n\r\n" + "x" * 500 +
                      f"\r\n--{bnd}--\r\n").encode()
                c.request("POST", "/api/share", body=mp,
                          headers={"Content-Type": f"multipart/form-data; boundary={bnd}",
                                   "Cookie": cookie})
                r = c.getresponse()
                self.assertEqual(r.status, 413)
                self.assertEqual(r.getheader("Connection"), "close")
                r.read()
                c.close()
        finally:
            app.MAX_UPLOAD = old_max

    def test_receive_with_files_rejected_and_cleaned(self):
        # 回归测试：/api/receive 只创建接收链接。以前顺手带上的文件会落盘
        # 后被直接丢弃，变成谁也看不见、清不掉的孤儿文件占着磁盘。
        # 现在应 400，且磁盘上不留文件。
        with self.server("127.0.0.1") as port:
            app.meta_set("pw", app.hash_pw("pw123456"))
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/login",
                      body=urllib.parse.urlencode({"pw": "pw123456"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            r.read()
            cookie = r.getheader("Set-Cookie").split(";")[0]
            bnd = "----rx"
            mp = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nt\r\n"
                  f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\n\r\n"
                  + "y" * 1000 + f"\r\n--{bnd}--\r\n").encode()
            c.request("POST", "/api/receive", body=mp,
                      headers={"Content-Type": f"multipart/form-data; boundary={bnd}",
                               "Cookie": cookie})
            r = c.getresponse()
            self.assertEqual(r.status, 400)
            self.assertIn("不需要上传文件", r.read().decode("utf-8"))
            self.assertEqual(os.listdir(app.FILES_DIR), [])
            c.close()

    def test_unread_body_closes_connection(self):
        # 回归测试：没读请求体就返回（未知 POST 路径、未登录的 API、
        # 无效的上传链接、带 body 的 GET）必须带 Connection: close，
        # 否则残留的 body 会被当成同一 keep-alive 连接上的下一个请求解析
        # （曾实测：下一个请求直接 501）。
        with self.server("127.0.0.1") as port:
            def post(path, body, headers=None):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                h = {"Content-Type": "application/x-www-form-urlencoded"}
                h.update(headers or {})
                c.request("POST", path, body=body, headers=h)
                r = c.getresponse()
                status, conn, data = r.status, r.getheader("Connection"), r.read()
                c.close()
                return status, conn, data
            # 1) 未知路径
            s, conn, _ = post("/no-such-path", b"z" * 100)
            self.assertEqual(s, 404)
            self.assertEqual(conn, "close")
            # 2) 未登录调 /api/share（body 没读）
            s, conn, _ = post("/api/share", b"z" * 100)
            self.assertEqual(s, 401)
            self.assertEqual(conn, "close")
            # 3) 无效的接收上传链接
            s, conn, _ = post("/r/deadbeef/upload", b"z" * 100)
            self.assertEqual(s, 404)
            self.assertEqual(conn, "close")
            # 4) 带 body 的 GET（本应用 GET 从不读 body）
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/healthz", body=b"z" * 10)
            r = c.getresponse()
            self.assertEqual(r.status, 200)
            self.assertEqual(r.getheader("Connection"), "close")
            r.read()
            c.close()
            # 5) 同一连接对象：未知路径（关连接）之后再发正常请求，
            # 不应被残留 body 污染（旧代码这里会返回 501）
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/no-such-path", body=b"z" * 100,
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            self.assertEqual(r.status, 404)
            r.read()
            c.request("GET", "/healthz")  # 服务端已关连接，客户端自动重连
            r = c.getresponse()
            self.assertEqual(r.status, 200)
            self.assertIn(b"minishare", r.read())
            c.close()

    def test_db_failure_cleans_orphan_files(self):
        # 回归测试：文件落盘后入库失败（如主键冲突/磁盘满），
        # 不能留下孤儿文件占空间。
        with self.server("127.0.0.1") as port:
            app.meta_set("pw", app.hash_pw("pw123456"))
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/login",
                      body=urllib.parse.urlencode({"pw": "pw123456"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            r.read()
            cookie = r.getheader("Set-Cookie").split(";")[0]
            # 预置同 id 分享，让 INSERT 撞主键失败
            with app.db() as dbc:
                dbc.execute("INSERT INTO shares(id,type,title,created,expires)"
                            " VALUES(?,?,?,?,?)",
                            ("fixedsid1", "send", "t", int(time.time()), 0))
            bnd = "----db"
            mp = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; "
                  f"filename=\"a.txt\"\r\n\r\n" + "x" * 100 +
                  f"\r\n--{bnd}--\r\n").encode()
            with patch.object(app, "new_share_id", return_value="fixedsid1"):
                c.request("POST", "/api/share", body=mp,
                          headers={"Content-Type": f"multipart/form-data; boundary={bnd}",
                                   "Cookie": cookie})
                r = c.getresponse()
                self.assertEqual(r.status, 500)
                r.read()
            self.assertEqual(os.listdir(app.FILES_DIR), [])
            c.close()

    def test_chpw_kills_other_sessions(self):
        # 改密码后其他会话立即失效（旧密码可能已泄露），当前会话不断线
        with self.server("127.0.0.1") as port:
            def login(pw):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request("POST", "/login",
                          body=urllib.parse.urlencode({"pw": pw}).encode(),
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
                r = c.getresponse()
                r.read()
                self.assertEqual(r.status, 302)
                return r.getheader("Set-Cookie").split(";")[0].split("=")[1], c
            app.meta_set("pw", app.hash_pw("oldpw123"))
            sess_a, ca = login("oldpw123")
            sess_b, cb = login("oldpw123")
            ca.request("POST", "/api/chpw",
                       body=urllib.parse.urlencode(
                           {"new1": "newpw123", "new2": "newpw123"}).encode(),
                       headers={"Content-Type": "application/x-www-form-urlencoded",
                                "Cookie": f"sid={sess_a}"})
            r = ca.getresponse()
            self.assertEqual(r.status, 200)
            self.assertTrue(json.loads(r.read())["ok"])
            cb.request("GET", "/dash", headers={"Cookie": f"sid={sess_b}"})
            r = cb.getresponse()
            r.read()
            self.assertEqual(r.status, 302)
            ca.request("GET", "/dash", headers={"Cookie": f"sid={sess_a}"})
            r = ca.getresponse()
            r.read()
            self.assertEqual(r.status, 200)
            ca.close()
            cb.close()

    def test_del_files_rejects_non_ascii_ids(self):
        # str.isdigit() 对 "²" 返回 True 但 int() 会炸：非法 id 应忽略而非 500
        with self.server("127.0.0.1") as port:
            app.meta_set("pw", app.hash_pw("pw123456"))
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/login",
                      body=urllib.parse.urlencode({"pw": "pw123456"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            r.read()
            cookie = r.getheader("Set-Cookie").split(";")[0]
            c.request("POST", "/api/del_files",
                      body=urllib.parse.urlencode({"ids": "²,abc"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded",
                               "Cookie": cookie})
            r = c.getresponse()
            body = r.read()
            self.assertEqual(r.status, 200)
            self.assertTrue(json.loads(body)["ok"])
            c.close()

    def test_title_api(self):
        # 改备注：未登录 401 → 登录后改名 → dash 显示 → 清空 → 不存在 404
        with self.server("127.0.0.1") as port:
            def req(method, path, body=None, headers=None, cookie=None):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                h = dict(headers or {})
                if cookie:
                    h["Cookie"] = cookie
                c.request(method, path, body=body, headers=h)
                r = c.getresponse()
                data = r.read()
                ck = r.getheader("Set-Cookie")
                c.close()
                return r.status, ck, data

            form = {"Content-Type": "application/x-www-form-urlencoded"}
            s, _, _ = req("POST", "/api/title", b"id=x&title=y", form)
            self.assertEqual(s, 401)

            body = urllib.parse.urlencode({"pw1": "test1234", "pw2": "test1234"}).encode()
            s, ck, _ = req("POST", "/setup", body, form)
            self.assertEqual(s, 302)
            cookie = ck.split(";")[0]

            mp = ("------b\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nold\r\n"
                  "------b--\r\n").encode()
            s, _, b = req("POST", "/api/receive", mp,
                          {"Content-Type": "multipart/form-data; boundary=----b"}, cookie)
            sid = json.loads(b)["id"]

            body = urllib.parse.urlencode({"id": sid, "title": "新备注名"}).encode()
            s, _, b = req("POST", "/api/title", body, form, cookie)
            self.assertEqual(s, 200)
            self.assertTrue(json.loads(b)["ok"])
            with app.db() as c:
                row = c.execute("SELECT title FROM shares WHERE id=?", (sid,)).fetchone()
            self.assertEqual(row["title"], "新备注名")

            s, _, b = req("GET", "/dash", cookie=cookie)
            self.assertIn("新备注名".encode(), b)

            body = urllib.parse.urlencode({"id": sid, "title": ""}).encode()
            s, _, b = req("POST", "/api/title", body, form, cookie)
            self.assertTrue(json.loads(b)["ok"])
            s, _, b = req("GET", "/dash", cookie=cookie)
            self.assertIn("(无备注)".encode(), b)

            body = urllib.parse.urlencode({"id": "nope12345", "title": "x"}).encode()
            s, _, b = req("POST", "/api/title", body, form, cookie)
            self.assertEqual(s, 404)

    def test_clean_filename_strips_control_chars(self):
        # 文件名里的 CR/LF 若不清理，会污染下载时的 Content-Disposition 响应头
        self.assertEqual(app._clean_filename('evil\r\nX-Injected: 1.txt'),
                         'evilX-Injected: 1.txt')

    def test_dash_shows_disk_usage_in_corner(self):
        # 控制台左下角固定角标显示剩余/已用空间；公开分享页不暴露磁盘信息
        with self.server("127.0.0.1") as port:
            def req(method, path, body=None, headers=None, cookie=None):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                h = dict(headers or {})
                if cookie:
                    h["Cookie"] = cookie
                c.request(method, path, body=body, headers=h)
                r = c.getresponse()
                data = r.read()
                ck = r.getheader("Set-Cookie")
                c.close()
                return r.status, ck, data

            form = {"Content-Type": "application/x-www-form-urlencoded"}
            body = urllib.parse.urlencode({"pw1": "test1234", "pw2": "test1234"}).encode()
            s, ck, _ = req("POST", "/setup", body, form)
            self.assertEqual(s, 302)
            cookie = ck.split(";")[0]

            s, _, b = req("GET", "/dash", cookie=cookie)
            self.assertEqual(s, 200)
            html = b.decode("utf-8")
            used, total = app.disk_usage()
            free = max(total - used, 0)
            self.assertIn("class='diskfoot'", html)
            self.assertIn(f"剩余 {app.hsize(free)} / 已用 {app.hsize(used)}", html)

            # 未登录访问公开分享页，不应出现磁盘信息
            mp = ("------b\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nt\r\n"
                  "------b--\r\n").encode()
            s, _, b = req("POST", "/api/receive", mp,
                          {"Content-Type": "multipart/form-data; boundary=----b"}, cookie)
            sid = json.loads(b)["id"]
            s, _, b = req("GET", f"/r/{sid}")
            self.assertEqual(s, 200)
            self.assertNotIn(b"class='diskfoot'", b)
            self.assertNotIn("已用".encode(), b)

    def test_dash_linkbox_prefilled(self):
        # 回归测试：分享卡片的虚线链接框以前是空的占位 div，
        # 点"复制链接"之前一直是个空框让人困惑；现在渲染时就填好链接
        now = int(time.time())
        with app.db() as c:
            c.execute("INSERT INTO shares(id,type,title,created,expires) VALUES(?,?,?,?,?)",
                      ("abC123-_", "send", "t", now, 0))
            shares = c.execute("SELECT * FROM shares").fetchall()
        body = app.dash_page(shares).decode("utf-8")
        self.assertIn("<div class='linkbox' id='lk-abC123-_'>/s/abC123-_</div>", body)
        self.assertEqual(app._clean_filename('../../etc/passwd'), 'passwd')
        self.assertEqual(app._clean_filename('正常 文件名.pdf'), '正常 文件名.pdf')

    def test_health_fails_when_database_unavailable(self):
        with self.server('127.0.0.1') as port:
            with patch.object(app, 'DB_PATH', '/nonexistent-minishare-test/share.db'):
                self.assertEqual(app.check_server('127.0.0.1', port, attempts=1), 1)

    def test_health_rejects_unrelated_service(self):
        class Other(app.Handler):
            def do_GET(self):
                self._send(200, 'not minishare')
        with patch.object(app, 'Handler', Other), self.server('127.0.0.1') as port:
            self.assertEqual(app.check_server('127.0.0.1', port, attempts=1), 1)

    def test_closed_port_fails(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            # Bound but not listening, so no other process can steal this port.
            self.assertEqual(app.check_server('127.0.0.1', sock.getsockname()[1], attempts=1), 1)

    def test_check_cli_does_not_initialize_database(self):
        with self.server('127.0.0.1') as port:
            data = Path(self.tmp.name) / 'must-not-exist'
            result = subprocess.run(['python3', str(ROOT / 'fileshare.py'), '--check', '127.0.0.1', str(port)],
                                    env={**os.environ, 'SHARE_DATA': str(data)}, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(data.exists())

    def test_separate_backend_port_allows_proxy_listener(self):
        with self.server('127.0.0.1') as backend:
            with socket.socket() as proxy:
                proxy.bind(('0.0.0.0', 0))
                proxy.listen()
                self.assertNotEqual(proxy.getsockname()[1], backend)
                self.assertEqual(self.request('127.0.0.1', backend, '/')[0], 200)

    def _login_cookie(self, port, pw="pw123456"):
        app.meta_set("pw", app.hash_pw(pw))
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", "/login",
                  body=urllib.parse.urlencode({"pw": pw}).encode(),
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 302)
        cookie = r.getheader("Set-Cookie").split(";")[0]
        c.close()
        return cookie

    def test_filename_star_garbage_encoding_not_500(self):
        # filename*=GARBAGE''%41%42：编码名是客户端随便填的，unquote 会抛
        # LookupError。应回退 utf-8 解码得到文件名 "AB"，200 而不是 500。
        with self.server("127.0.0.1") as port:
            cookie = self._login_cookie(port)
            bnd = "----b"
            mp = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nt\r\n"
                  f"--{bnd}--\r\n").encode()
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/api/receive", body=mp,
                      headers={"Content-Type": f"multipart/form-data; boundary={bnd}",
                               "Cookie": cookie})
            r = c.getresponse()
            sid = json.loads(r.read())["id"]
            c.close()
            up = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"file\"; "
                  f"filename*=GARBAGE''%41%42\r\n"
                  f"Content-Type: application/octet-stream\r\n\r\nhello\r\n"
                  f"--{bnd}--\r\n").encode("latin1")
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", f"/r/{sid}/upload", body=up,
                      headers={"Content-Type": f"multipart/form-data; boundary={bnd}"})
            r = c.getresponse()
            body = r.read()
            c.close()
            self.assertEqual(r.status, 200)
            self.assertTrue(json.loads(body)["ok"])
            with app.db() as dbc:
                row = dbc.execute("SELECT filename FROM files").fetchone()
            self.assertEqual(row["filename"], "AB")

    def test_garbage_content_length_is_400_not_500(self):
        # Content-Length 填垃圾值：int() 抛 ValueError，必须 400 而不是 500。
        # 表单路径（_form）和 multipart 路径（_multipart）都要覆盖。
        with self.server("127.0.0.1") as port:
            cookie = self._login_cookie(port)
            bad = {"Content-Length": "abc"}
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/login", body=b"",
                      headers={"Content-Type": "application/x-www-form-urlencoded",
                               **bad})
            r = c.getresponse()
            r.read()
            self.assertEqual(r.status, 400)
            c.close()
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/api/share", body=b"",
                      headers={"Content-Type": "multipart/form-data; boundary=----x",
                               "Cookie": cookie, **bad})
            r = c.getresponse()
            r.read()
            self.assertEqual(r.status, 400)
            self.assertEqual(r.getheader("Connection"), "close")
            c.close()

    def test_share_badupload_closes_connection(self):
        # /api/share 解析失败（如 Content-Type 里没 boundary）时请求体没读完：
        # 必须关连接并带 Connection: close，否则残留的请求体会污染同一
        # keep-alive 连接上的下一个请求（实测：服务端曾把残留 body 当成
        # 新请求的方法行解析，吐出 501）。/api/receive 早就是这么做的。
        with self.server("127.0.0.1") as port:
            cookie = self._login_cookie(port)
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            raw = (f"POST /api/share HTTP/1.1\r\nHost: x\r\nCookie: {cookie}\r\n"
                   "Content-Type: multipart/form-data\r\nContent-Length: 100\r\n\r\n").encode() + b"Z" * 100
            s.sendall(raw)
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
            clen = 0
            for line in resp.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    clen = int(line.split(b":", 1)[1])
            body = resp.split(b"\r\n\r\n", 1)[1]
            while len(body) < clen:
                body += s.recv(4096)
            self.assertTrue(resp.split(b"\r\n")[0].endswith(b"400 Bad Request"),
                            resp.split(b"\r\n")[0])
            self.assertTrue(any(l.lower().startswith(b"connection:") and b"close" in l.lower()
                                for l in resp.split(b"\r\n")), resp)
            # 同一连接上再发请求：服务端已关连接，绝不能把残留 body 当请求解析
            try:
                s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass
            s.settimeout(3)
            try:
                more = s.recv(4096)
            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                more = b""
            self.assertNotIn(b"501", more)
            s.close()

    def test_receive_api_oversized_is_413(self):
        # /api/receive 超大上传应与 /api/share、/r/<sid>/upload 一致返回 413
        #（之前是 400 且错误信息为空字符串）。
        old_max = app.MAX_UPLOAD
        app.MAX_UPLOAD = 200
        try:
            with self.server("127.0.0.1") as port:
                cookie = self._login_cookie(port)
                bnd = "----t"
                mp = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nx\r\n"
                      f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\n"
                      + "x" * 500 + f"\r\n--{bnd}--\r\n").encode()
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request("POST", "/api/receive", body=mp,
                          headers={"Content-Type": f"multipart/form-data; boundary={bnd}",
                                   "Cookie": cookie})
                r = c.getresponse()
                body = r.read()
                c.close()
                self.assertEqual(r.status, 413)
                self.assertIn("太大", body.decode("utf-8"))
        finally:
            app.MAX_UPLOAD = old_max

class Installer(unittest.TestCase):
    def run_install(self, port, mode='no-manager', ipver='4'):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'source'
            shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns('.git', '__pycache__'))
            bin_dir = root / 'bin'
            bin_dir.mkdir()
            def command(name, body):
                p = bin_dir / name
                p.write_text('#!/bin/sh\n' + body + '\n')
                p.chmod(0o755)
            command('id', 'echo 0')
            # Emulate manager acceptance followed by a dead Python process.
            command('systemctl', 'exit 0')
            command('journalctl', 'echo TEST_STARTUP_LOG')
            script = (source / 'install.sh').read_text()
            marker = root / 'run-systemd'
            if mode == 'dead': marker.mkdir()
            units = root / 'units'
            units.mkdir()
            script = script.replace('/run/systemd/system', str(marker)).replace('/etc/systemd/system', str(units))
            script = script.replace('elif command -v rc-service >/dev/null 2>&1; then', 'elif false; then')
            (source / 'install.sh').write_text(script)
            result = subprocess.run(['sh', str(source / 'install.sh')], cwd=root,
                env={**os.environ, 'PATH': str(bin_dir) + ':' + os.environ['PATH'], 'PORT': port,
                     'IPVER': ipver, 'APP_DIR': str(root / 'app'), 'NONINTERACTIVE': '1'},
                capture_output=True, text=True, timeout=40)
            return result

    def test_invalid_ports_rejected(self):
        for port in ('0', '65536', '999999999999999999999', 'abc'):
            with self.subTest(port=port):
                r = self.run_install(port)
                self.assertNotEqual(r.returncode, 0)
                self.assertNotIn('安装完成', r.stdout)

    def test_no_manager_does_not_claim_success(self):
        r = self.run_install('18080')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('无法自动启动', r.stdout)
        self.assertNotIn('安装完成', r.stdout)

    def test_manager_success_but_app_dead_fails_install(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            r = self.run_install(str(sock.getsockname()[1]), 'dead')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('TEST_STARTUP_LOG', r.stdout)
        self.assertNotIn('安装完成', r.stdout)

    def run_install_repair(self, with_listener=False):
        """Sandbox with a fake pre-installed minishare service on disk."""
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)
        source = root / 'source'
        shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns('.git', '__pycache__'))
        bin_dir = root / 'bin'
        bin_dir.mkdir()
        def command(name, body):
            p = bin_dir / name
            p.write_text('#!/bin/sh\n' + body + '\n')
            p.chmod(0o755)
        command('id', 'echo 0')
        command('systemctl', 'exit 0')
        command('journalctl', 'echo TEST_STARTUP_LOG')
        script = (source / 'install.sh').read_text()
        marker = root / 'run-systemd'
        marker.mkdir()
        units = root / 'units'
        units.mkdir()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        app_dir = root / 'app'
        (app_dir / 'data' / 'files').mkdir(parents=True)
        (units / 'minishare.service').write_text(
            'Environment=SHARE_HOST=127.0.0.1\n'
            'Environment=SHARE_PORT=%d\n'
            'Environment=SHARE_DATA=%s\n' % (port, app_dir / 'data'))
        installed_py = app_dir / 'fileshare.py'
        installed_py.write_text('# installed version\n' + (ROOT / 'fileshare.py').read_text())
        marker_text = '# updated by repair test\n'
        (source / 'fileshare.py').write_text(
            (ROOT / 'fileshare.py').read_text() + marker_text)
        script = script.replace('/run/systemd/system', str(marker)).replace('/etc/systemd/system', str(units))
        script = script.replace('elif command -v rc-service >/dev/null 2>&1; then', 'elif false; then')
        (source / 'install.sh').write_text(script)
        server_proc = None
        if with_listener:
            server_proc = subprocess.Popen(
                [sys.executable, str(installed_py)],
                env={**os.environ, 'SHARE_HOST': '127.0.0.1', 'SHARE_PORT': str(port),
                     'SHARE_DATA': str(app_dir / 'data'), 'PYTHONDONTWRITEBYTECODE': '1'},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.addCleanup(server_proc.terminate)
            for _ in range(60):
                probe = subprocess.run(
                    [sys.executable, str(installed_py), '--check', '127.0.0.1', str(port)],
                    capture_output=True, timeout=10)
                if probe.returncode == 0:
                    break
                time.sleep(0.5)
            else:
                self.fail('test server did not become ready')
        result = subprocess.run(['sh', str(source / 'install.sh')], cwd=root,
            env={**os.environ, 'PATH': str(bin_dir) + ':' + os.environ['PATH'],
                 'NONINTERACTIVE': '1', 'PYTHONDONTWRITEBYTECODE': '1'},
            capture_output=True, text=True, timeout=60)
        return result, root, marker_text, port

    def test_repair_mode_detected_for_existing_install(self):
        r, root, _, _ = self.run_install_repair(with_listener=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('保留数据修复', r.stdout)
        self.assertIn('恢复原程序', r.stdout)
        self.assertTrue((root / 'app' / 'fileshare.py').read_text().startswith('# installed version'))
        self.assertEqual(len(list((root / 'app').glob('fileshare.py.backup.*'))), 1)

    def test_repair_mode_updates_program_when_check_passes(self):
        r, root, marker_text, port = self.run_install_repair(with_listener=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('修复完成', r.stdout)
        self.assertIn(str(port), r.stdout)
        content = (root / 'app' / 'fileshare.py').read_text()
        self.assertIn(marker_text.strip(), content)
        self.assertFalse(content.startswith('# installed version'))

    def run_install_pty(self, choice):
        """Run install.sh under a pty so [ -t 0 ] is true; answer the repair/reinstall prompt."""
        import pty
        import select
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)
        source = root / 'source'
        shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns('.git', '__pycache__'))
        bin_dir = root / 'bin'
        bin_dir.mkdir()
        def command(name, body):
            q = bin_dir / name
            q.write_text('#!/bin/sh\n' + body + '\n')
            q.chmod(0o755)
        command('id', 'echo 0')
        command('systemctl', 'exit 0')
        command('journalctl', 'echo TEST_STARTUP_LOG')
        script = (source / 'install.sh').read_text()
        marker = root / 'run-systemd'
        marker.mkdir()
        units = root / 'units'
        units.mkdir()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        app_dir = root / 'app'
        (app_dir / 'data' / 'files').mkdir(parents=True)
        (units / 'minishare.service').write_text(
            'Environment=SHARE_HOST=127.0.0.1\n'
            'Environment=SHARE_PORT=%d\n'
            'Environment=SHARE_DATA=%s\n' % (port, app_dir / 'data'))
        (app_dir / 'fileshare.py').write_text('# installed version\n' + (ROOT / 'fileshare.py').read_text())
        script = script.replace('/run/systemd/system', str(marker)).replace('/etc/systemd/system', str(units))
        script = script.replace('elif command -v rc-service >/dev/null 2>&1; then', 'elif false; then')
        (source / 'install.sh').write_text(script)
        master, slave = pty.openpty()
        env = {**os.environ, 'PATH': str(bin_dir) + ':' + os.environ['PATH'],
               'APP_DIR': str(app_dir), 'PYTHONDONTWRITEBYTECODE': '1'}
        env.pop('NONINTERACTIVE', None)
        proc = subprocess.Popen(['sh', str(source / 'install.sh')], cwd=root,
                                stdin=slave, stdout=slave, stderr=slave,
                                env=env, close_fds=True)
        os.close(slave)
        self.addCleanup(lambda: proc.poll() is None and proc.terminate())
        out = b''
        def drain():
            data = b''
            end = time.time() + 5
            while time.time() < end:
                r, _, _ = select.select([master], [], [], 1)
                if not r:
                    break
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                data += chunk
            return data
        def read_until(needle, timeout=25):
            nonlocal out
            end = time.time() + timeout
            while time.time() < end:
                r, _, _ = select.select([master], [], [], 1)
                if r:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    out += chunk
                    if needle in out:
                        return True
                if proc.poll() is not None:
                    break
            return needle in out
        self.assertTrue(read_until('请选择'.encode('utf-8')), 'prompt not shown: %r' % out[-500:])
        os.write(master, (choice + '\n').encode())
        if choice == '2':
            self.assertTrue(read_until('1/3'.encode()), 'wizard q1 not reached')
            os.write(master, b'\n')
            self.assertTrue(read_until('2/3'.encode()), 'wizard q2 not reached')
            os.write(master, ('%d\n' % port).encode())
            self.assertTrue(read_until('3/3'.encode()), 'wizard q3 not reached')
            os.write(master, b'1\n')
        try:
            proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            proc.terminate()
            self.fail('installer did not exit: %r' % out[-2000:])
        rest = drain()
        if rest:
            out += rest
        os.close(master)
        return proc.returncode, out.decode('utf-8', 'replace')

    def test_pty_choice_2_goes_to_reinstall(self):
        rc, text = self.run_install_pty('2')
        self.assertNotEqual(rc, 0)  # no listener: --check fails after reinstall
        self.assertIn('安装向导', text)
        self.assertNotIn('修复完成', text)

    def test_pty_default_choice_repairs(self):
        rc, text = self.run_install_pty('')
        self.assertNotEqual(rc, 0)  # no listener: check fails and rolls back
        self.assertIn('恢复原程序', text)
        self.assertNotIn('安装向导', text)

class HTTPSConfig(unittest.TestCase):
    def nat_case(self, fail):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'etc/systemd/system').mkdir(parents=True)
            (root / 'run/systemd/system').mkdir(parents=True)
            (root / 'etc/caddy').mkdir()
            service = root / 'etc/systemd/system/minishare.service'
            original = 'Environment=SHARE_HOST=0.0.0.0\nEnvironment=SHARE_PORT=19332\n'
            service.write_text(original)
            caddyfile = root / 'etc/caddy/Caddyfile'
            caddyfile.write_text('original caddy config\n')
            bin_dir = root / 'bin'
            bin_dir.mkdir()
            commands = {'sleep': 'exit 0', 'systemctl':
                        'if [ "$1 $2" = "restart caddy" ] && [ "$FAIL_CADDY" = 1 ]; then exit 1; fi\nexit 0'}
            if sys.platform == 'darwin':
                commands['sed'] = 'if [ "$1" = -i ]; then shift; exec /usr/bin/sed -i "" "$@"; else exec /usr/bin/sed "$@"; fi'
            for name, body in commands.items():
                path = bin_dir / name
                path.write_text('#!/bin/sh\n' + body + '\n')
                path.chmod(0o755)
            text = (ROOT / 'enable-https.sh').read_text()
            block = text[text.index('# Caddy wildcard bind'):text.index('# ---- [9] 放行防火墙')]
            block = block.replace('/etc/', str(root / 'etc') + '/').replace('/run/systemd/system', str(root / 'run/systemd/system'))
            result = subprocess.run(['sh', '-c', 'set -eu\n' + block], env={**os.environ,
                'PATH': str(bin_dir) + ':' + os.environ['PATH'], 'SRV_FILE': str(service),
                'SRV_HOST': '0.0.0.0', 'ORIG_PORT': '19332', 'PORT': '19332',
                'DOMAIN': 'test.example.com', 'CERTDIR': str(root / 'cert'), 'FAIL_CADDY': str(int(fail))},
                capture_output=True, text=True, errors="replace", timeout=10)
            if fail:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(service.read_text(), original)
                self.assertEqual(caddyfile.read_text(), 'original caddy config\n')
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                config = service.read_text()
                self.assertIn('SHARE_HOST=127.0.0.1', config)
                backend = re.search(r'SHARE_PORT=(\d+)', config).group(1)
                self.assertNotEqual(backend, '19332')
                self.assertIn('https://test.example.com:19332', caddyfile.read_text())
                self.assertIn('reverse_proxy 127.0.0.1:' + backend, caddyfile.read_text())
                self.assertEqual((root / 'etc/minishare-nat-port').read_text().strip(), '19332')

    def test_nat_uses_distinct_backend_port(self):
        self.nat_case(False)

    def test_nat_start_failure_restores_original_configuration(self):
        self.nat_case(True)

    def test_normal_https_targets_ipv6_backend(self):
        with tempfile.TemporaryDirectory() as folder:
            text = (ROOT / 'enable-https.sh').read_text()
            a = text.index('echo "[4] 配置反向代理…"')
            block = text[a:text.index('# ---- [5] 设置开机自启', a)].replace('/etc/caddy', folder)
            result = subprocess.run(['sh', '-c', 'set -eu\n' + block], env={**os.environ,
                'SRV_HOST': '::', 'PORT': '18080', 'DOMAIN': 'test.example.com'}, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('reverse_proxy [::1]:18080', (Path(folder) / 'Caddyfile').read_text())

if __name__ == '__main__':
    unittest.main(verbosity=2)
