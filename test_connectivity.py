"""Regression tests: real local HTTP/SQLite, IPv4/IPv6 and installer failure handling."""
import contextlib
import http.client
import importlib.util
import os
from pathlib import Path
import shutil
import shlex
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
            app.create_user('test-local-only', is_admin=True)
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
        body = app.dash_page(shares, {"id": 1, "is_admin": True}).decode("utf-8")
        self.assertIn('saveExpiry(\'\\"+id+\\"\')', body)
        self.assertIn('cancelExpiry(\'\\"+id+\\"\')', body)
        self.assertNotIn('saveExpiry(\\"+id+\\")', body)

    def test_copy_button_has_insecure_context_fallback(self):
        # 回归测试：复制链接按钮之前直接调 navigator.clipboard.writeText，
        # 而剪贴板 API 只在安全上下文（HTTPS/localhost）可用；默认用
        # http://IP:端口 打开时 navigator.clipboard 是 undefined，
        # 点了抛 TypeError 没任何反应。现在必须先判断再调，
        # 不可用时明确提示手动复制，且链接一直可见。
        now = int(time.time())
        with app.db() as c:
            c.execute("INSERT INTO shares(id,type,title,created,expires) VALUES(?,?,?,?,?)",
                      ("abC123-_", "send", "t", now, 0))
            shares = c.execute("SELECT * FROM shares").fetchall()
        body = app.dash_page(shares, {"id": 1, "is_admin": True}).decode("utf-8")
        m = re.search(r"<script>(.*)</script>", body, re.S)
        self.assertIsNotNone(m)
        js = m.group(1)
        self.assertIn("function copyText", js)
        self.assertIn("window.isSecureContext", js)
        self.assertIn("copyText(t, el)", js)  # 卡片上的复制链接走 copyText
        self.assertIn("copyText(fullLink(", js)  # 上传成功后的复制按钮也走 copyText
        # 唯一的 writeText 调用必须落在 isSecureContext 保护分支内
        idx = js.index("navigator.clipboard.writeText(t)")
        guard = js.rindex("if (", 0, idx)
        self.assertIn("window.isSecureContext", js[guard:idx])
        if shutil.which("node"):
            with tempfile.NamedTemporaryFile("w", suffix=".js",
                                             delete=False) as f:
                f.write(js)
                path = f.name
            try:
                r = subprocess.run(["node", "--check", path],
                                   capture_output=True, timeout=30)
                self.assertEqual(r.returncode, 0, r.stderr.decode())
            finally:
                os.unlink(path)

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
                app.create_user("pw123456", is_admin=True)
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
            app.create_user("pw123456", is_admin=True)
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
            app.create_user("pw123456", is_admin=True)
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

    def test_upload_limit_falls_back_when_disk_unknown(self):
        # 回归测试：statvfs 失败（目录被删、NFS 掉线等）时磁盘大小未知，
        # 不能按"剩余 0"处理，否则所有上传直接 413。未知时应退回配置上限。
        with patch.object(app.os, "statvfs", side_effect=OSError("boom")):
            limit, free = app.upload_limit()
            self.assertEqual(limit, app.MAX_UPLOAD)
            self.assertIsNone(free)

    def test_file_at_displayed_limit_is_accepted(self):
        # 回归测试：上限按"实际文件字节数"执行，multipart 信封开销不计入。
        # 以前是整个请求体（含信封）与上限比较，正好卡着页面显示数字的
        # 文件会因为信封多出几十字节被 413。
        import io as _io
        def body_of(n):
            bnd = b"----t"
            body = (b"--" + bnd + b"\r\n"
                    b'Content-Disposition: form-data; name="f"; filename="a.bin"\r\n'
                    b"\r\n" + b"x" * n +
                    b"\r\n--" + bnd + b"--\r\n")
            return body, bnd
        # 正好等于上限：必须通过（旧代码这里抛 UploadTooLarge）
        body, bnd = body_of(1000)
        self.assertGreater(len(body), 1000)  # 确认信封确实让 total 超过上限
        fields, files = app.parse_multipart(_io.BytesIO(body), len(body), bnd, 1000)
        self.assertEqual(files[0]["size"], 1000)
        for fo in files:  # 成功落盘的文件测试自己清理
            os.unlink(os.path.join(app.FILES_DIR, fo["stored"]))
        # 真超了：流式扣额度时 413，且已落盘的部分文件被清理
        body, bnd = body_of(1100)
        with self.assertRaises(app.UploadTooLarge):
            app.parse_multipart(_io.BytesIO(body), len(body), bnd, 1000)
        self.assertEqual(os.listdir(app.FILES_DIR), [])
        # 明显超大（total 远超上限+余量）：前置快速拒绝
        body, bnd = body_of(1000)
        with self.assertRaises(app.UploadTooLarge):
            app.parse_multipart(_io.BytesIO(body), len(body) + 2 * 1024 * 1024,
                                bnd, 1000)

    def test_receive_link_creation_ignores_disk_cap(self):
        # 回归测试：/api/receive 只创建接收链接、不收文件，这个动作本身
        # 不占磁盘。磁盘快满时它不该被"剩余空间"上限卡住而报 413；
        # 而真正的上传（/api/share）仍受磁盘上限约束，且 413 文案应说明
        # 是磁盘满了，而不是"文件太大"。
        with self.server("127.0.0.1") as port:
            app.create_user("pw123456", is_admin=True)
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/login",
                      body=urllib.parse.urlencode({"pw": "pw123456"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            r.read()
            cookie = r.getheader("Set-Cookie").split(";")[0]
            bnd = "----t"
            mp = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nt\r\n"
                  f"--{bnd}--\r\n").encode()
            with patch.object(app, "upload_limit", return_value=(50, 50)):
                # 建链接：纯表单约 100 字节 > 磁盘上限 50，旧代码 413
                c.request("POST", "/api/receive", body=mp,
                          headers={"Content-Type": f"multipart/form-data; boundary={bnd}",
                                   "Cookie": cookie})
                r = c.getresponse()
                self.assertEqual(r.status, 200, r.read())
                r.read()
                # 真上传 100 字节文件：磁盘只剩 50，413 且文案说明磁盘不足
                mp2 = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; "
                       f"filename=\"a.txt\"\r\n\r\n" + "x" * 100 +
                       f"\r\n--{bnd}--\r\n").encode()
                c.request("POST", "/api/share", body=mp2,
                          headers={"Content-Type": f"multipart/form-data; boundary={bnd}",
                                   "Cookie": cookie})
                r = c.getresponse()
                self.assertEqual(r.status, 413)
                self.assertIn("磁盘剩余空间不足", r.read().decode("utf-8"))
            c.close()

    def test_share_page_has_no_footer(self):
        # 分享页不再显示"由 minishare 提供"字样
        now = int(time.time())
        body = app.share_page("abC123-_",
                              {"id": "abC123-_", "type": "send", "title": "t",
                               "created": now, "expires": 0},
                              []).decode("utf-8")
        self.assertNotIn("由 minishare 提供", body)

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
            app.create_user("oldpw123", is_admin=True)
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
            app.create_user("pw123456", is_admin=True)
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

    def test_delete_share_keeps_files(self):
        # 删除分享只删链接不删文件：文件保留在"全部文件"里（标记为"链接已删"），
        # 由用户手动删除。
        with self.server("127.0.0.1") as port:
            app.create_user("pw123456", is_admin=True)
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/login",
                      body=urllib.parse.urlencode({"pw": "pw123456"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            r.read()
            cookie = r.getheader("Set-Cookie").split(";")[0]
            bnd = "----keep"
            mp = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; "
                  f"filename=\"keepme.txt\"\r\n\r\n" + "k" * 100 +
                  f"\r\n--{bnd}--\r\n").encode()
            c.request("POST", "/api/share", body=mp,
                      headers={"Content-Type": f"multipart/form-data; boundary={bnd}",
                               "Cookie": cookie})
            r = c.getresponse()
            share = json.loads(r.read())
            self.assertTrue(share["ok"])
            sid = share["id"]
            self.assertEqual(len(os.listdir(app.FILES_DIR)), 1)
            c.request("POST", "/api/delete",
                      body=urllib.parse.urlencode({"id": sid}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded",
                               "Cookie": cookie})
            r = c.getresponse()
            self.assertTrue(json.loads(r.read())["ok"])
            # 链接已失效
            c.request("GET", f"/s/{sid}")
            r = c.getresponse()
            r.read()
            self.assertEqual(r.status, 404)
            # 文件仍在磁盘上，且控制台"全部文件"里可见并标为"链接已删"
            self.assertEqual(len(os.listdir(app.FILES_DIR)), 1)
            c.request("GET", "/dash", headers={"Cookie": cookie})
            r = c.getresponse()
            dash = r.read().decode("utf-8")
            self.assertIn("keepme.txt", dash)
            self.assertIn("链接已删", dash)
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
        body = app.dash_page(shares, {"id": 1, "is_admin": True}).decode("utf-8")
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
        app.create_user(pw, is_admin=True)
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

    def test_check_pw_corrupted_hash_returns_false(self):
        # 回归测试：数据库里存的密码哈希损坏（含 $ 但 salt 不是合法 hex）时，
        # 之前 bytes.fromhex 在 try 外面抛 ValueError，/login 直接 500；
        # 损坏的哈希只能判为密码不对，页面显示"密码错误"。
        self.assertFalse(app.check_pw("x", "zz$xx"))
        self.assertFalse(app.check_pw("x", "no-dollar-sign"))
        h = app.hash_pw("right-pw")
        self.assertTrue(app.check_pw("right-pw", h))
        self.assertFalse(app.check_pw("wrong-pw", h))
        with self.server("127.0.0.1") as port:
            # 模拟损坏的哈希：直接往 users 表里写一行坏数据
            with app.db() as dbc:
                dbc.execute("INSERT INTO users(pw,is_admin,created) VALUES(?,?,?)",
                            ("zz$xx", 1, int(time.time())))
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/login",
                      body=urllib.parse.urlencode({"pw": "whatever"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            body = r.read()
            c.close()
            self.assertEqual(r.status, 200)  # 旧代码这里是 500
            self.assertIn("密码错误".encode("utf-8"), body)

    def test_disp_param_semicolon_in_quoted_filename(self):
        # 回归测试：Content-Disposition 参数按分号切时，引号里的分号
        # （如 filename="a;b.txt"）不能当分隔符；之前直接 split(";")，
        # 文件名会被截成 "\"a"。
        disp = 'form-data; name="file"; filename="a;b.txt"'
        self.assertEqual(app._disp_param(disp, "filename"), "a;b.txt")
        # 端到端：上传带分号的文件名，入库名字保持完整
        with self.server("127.0.0.1") as port:
            app.create_user("pw123456", is_admin=True)
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/login",
                      body=urllib.parse.urlencode({"pw": "pw123456"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            r.read()
            cookie = r.getheader("Set-Cookie").split(";")[0]
            bnd = "----semi"
            mp = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"file\"; "
                  f"filename=\"a;b.txt\"\r\n\r\ndata\r\n--{bnd}--\r\n").encode()
            c.request("POST", "/api/share", body=mp,
                      headers={"Content-Type": f"multipart/form-data; boundary={bnd}",
                               "Cookie": cookie})
            r = c.getresponse()
            self.assertEqual(r.status, 200, r.read())
            c.close()
            with app.db() as dbc:
                fn = dbc.execute("SELECT filename FROM files").fetchone()["filename"]
            self.assertEqual(fn, "a;b.txt")

    def test_del_files_reports_actual_deletions(self):
        # 回归测试：/api/del_files 的 deleted 之前是 len(ids)，勾了不存在的
        # id 也会算进去；现在只计真实删掉的行。
        with self.server("127.0.0.1") as port:
            app.create_user("pw123456", is_admin=True)
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/login",
                      body=urllib.parse.urlencode({"pw": "pw123456"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            r.read()
            cookie = r.getheader("Set-Cookie").split(";")[0]
            bnd = "----cnt"
            mp = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"file\"; "
                  f"filename=\"a.txt\"\r\n\r\ndata\r\n--{bnd}--\r\n").encode()
            c.request("POST", "/api/share", body=mp,
                      headers={"Content-Type": f"multipart/form-data; boundary={bnd}",
                               "Cookie": cookie})
            r = c.getresponse()
            r.read()
            self.assertEqual(r.status, 200)
            with app.db() as dbc:
                fid = dbc.execute("SELECT id FROM files").fetchone()["id"]
            c.request("POST", "/api/del_files",
                      body=urllib.parse.urlencode({"ids": f"{fid},999999"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded",
                               "Cookie": cookie})
            r = c.getresponse()
            j = json.loads(r.read())
            c.close()
            self.assertTrue(j["ok"])
            self.assertEqual(j["deleted"], 1)  # 旧代码这里是 2

    def test_dash_hides_expired_shares(self):
        # 回归测试：已过期的分享（每小时才会被清理线程删掉）在删掉之前，
        # 控制台不应再列出来——访问它的链接已经是 404，列表保持一致。
        now = int(time.time())
        with app.db() as c:
            c.execute("INSERT INTO shares(id,type,title,created,expires) VALUES(?,?,?,?,?)",
                      ("exp12345", "send", "已过期", now - 100, now - 10))
            c.execute("INSERT INTO shares(id,type,title,created,expires) VALUES(?,?,?,?,?)",
                      ("ok123456", "send", "还有效", now - 100, 0))
            c.execute("INSERT INTO files(share_id,filename,stored,size,created)"
                      " VALUES(?,?,?,?,?)",
                      ("exp12345", "old.txt", "x" * 32, 3, now - 100))
        with self.server("127.0.0.1") as port:
            app.create_user("pw123456", is_admin=True)
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/login",
                      body=urllib.parse.urlencode({"pw": "pw123456"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            r.read()
            cookie = r.getheader("Set-Cookie").split(";")[0]
            c.request("GET", "/dash", headers={"Cookie": cookie})
            r = c.getresponse()
            body = r.read().decode("utf-8")
            c.close()
            self.assertEqual(r.status, 200)
            self.assertNotIn("已过期", body)
            self.assertNotIn("old.txt", body)
            self.assertIn("还有效", body)

    def test_receive_page_shows_upload_limit(self):
        # 需求：分享出去的接收链接页面，要提示对方可上传的最大值
        #（配置上限与服务器剩余空间取小者），免得传了超大文件才发现传不上去。
        # 页面只显示一行"📦最大可上传 X文件"，括号里的明细不要。
        # 1) 函数级：upload_limit() == min(MAX_UPLOAD, 剩余空间)
        limit, free = app.upload_limit()
        used, total = app.disk_usage()
        self.assertEqual(free, max(total - used, 0))
        self.assertEqual(limit, min(app.MAX_UPLOAD, free))
        # 2) 页面级：GET /r/<sid> 渲染出提示行，且数字与函数返回值一致，
        #    且不含括号明细（"上传上限"/"服务器剩余空间"）
        with self.server("127.0.0.1") as port:
            def req(method, path, body=None, headers=None):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request(method, path, body=body, headers=dict(headers or {}))
                r = c.getresponse()
                data = r.read()
                c.close()
                return r.status, data

            app.create_user("pw123456", is_admin=True)
            # 直接入库一个接收分享（省去 multipart 建链接的步骤）
            with app.db() as c:
                c.execute("INSERT INTO shares(id,type,title,created,expires)"
                          " VALUES(?,?,?,?,?)",
                          ("recvlim1", "receive", "收文件", int(time.time()), 0))
            s, data = req("GET", "/r/recvlim1")
            self.assertEqual(s, 200)
            text = data.decode("utf-8")
            self.assertIn("📦最大可上传", text)
            self.assertIn(app.hsize(limit) + "</b>文件", text)
            self.assertNotIn("上传上限", text)
            self.assertNotIn("服务器剩余空间", text)

    def test_upload_beyond_free_space_rejected_413(self):
        # 回归测试：_multipart 的实际解析上限是 min(MAX_UPLOAD, 磁盘剩余空间)，
        # 与接收页面显示给对方的数字一致。磁盘快满时，超过剩余空间的上传
        # 应在请求头阶段就 413 拒绝，而不是让对方传一半才遇到 500。
        # 之前上限只看 MAX_UPLOAD：比如剩余 1GB 时传 2GB 的文件，
        # 会一直传到写满磁盘才 500。
        with self.server("127.0.0.1") as port:
            app.create_user("pw123456", is_admin=True)
            with app.db() as c:
                c.execute("INSERT INTO shares(id,type,title,created,expires)"
                          " VALUES(?,?,?,?,?)",
                          ("recvfull", "receive", "收文件", int(time.time()), 0))
            bnd = "----full"
            mp = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; "
                  f"filename=\"big.bin\"\r\n\r\n" + "z" * 2000 +
                  f"\r\n--{bnd}--\r\n").encode()
            headers = {"Content-Type": f"multipart/form-data; boundary={bnd}"}
            # 模拟磁盘只剩 100 字节：2KB 的请求体应直接 413
            with patch.object(app, "disk_usage", return_value=(900, 1000)):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request("POST", "/r/recvfull/upload", body=mp, headers=headers)
                r = c.getresponse()
                self.assertEqual(r.status, 413)
                self.assertEqual(r.getheader("Connection"), "close")
                r.read()
                c.close()
            # 磁盘空间正常时：同一个包应正常接收
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/r/recvfull/upload", body=mp, headers=headers)
            r = c.getresponse()
            self.assertEqual(r.status, 200)
            self.assertTrue(json.loads(r.read())["ok"])
            c.close()

    # ---------------- 多用户 ----------------
    def _t_login(self, port, pw):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", "/login",
                  body=urllib.parse.urlencode({"pw": pw}).encode(),
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
        r = c.getresponse()
        body = r.read()
        ck = r.getheader("Set-Cookie")
        c.close()
        return r.status, (ck.split(";")[0] if ck else None), body

    def _t_api(self, port, path, params, cookie):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", path, body=urllib.parse.urlencode(params).encode(),
                  headers={"Content-Type": "application/x-www-form-urlencoded",
                           "Cookie": cookie})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, json.loads(data)

    def _t_mk_recv_share(self, port, cookie, title="t"):
        bnd = "----mu"
        mp = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\n"
              f"{title}\r\n--{bnd}--\r\n").encode()
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", "/api/receive", body=mp,
                  headers={"Content-Type": f"multipart/form-data; boundary={bnd}",
                           "Cookie": cookie})
        r = c.getresponse()
        data = json.loads(r.read())
        c.close()
        self.assertEqual(r.status, 200)
        return data["id"]

    def test_multiuser_login_roles(self):
        # 同一个登录页、只输密码：不同密码 = 不同账号，控制台显示身份
        with self.server("127.0.0.1") as port:
            app.create_user("adminpw1", is_admin=True)
            app.create_user("userpw22")
            s, acookie, _ = self._t_login(port, "adminpw1")
            self.assertEqual(s, 302)
            s, ucookie, _ = self._t_login(port, "userpw22")
            self.assertEqual(s, 302)
            # 密码错误
            s, _, body = self._t_login(port, "wrongpw")
            self.assertEqual(s, 200)
            self.assertIn("密码错误".encode(), body)
            # 管理员控制台：身份徽标 + 用户管理 + 删文件按钮
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/dash", headers={"Cookie": acookie})
            r = c.getresponse()
            ahtml = r.read().decode()
            c.close()
            self.assertIn("👑 管理员", ahtml)
            self.assertIn("👥 用户管理", ahtml)
            self.assertIn("<form id='userAddForm'", ahtml)
            # 普通用户控制台：无用户管理
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/dash", headers={"Cookie": ucookie})
            r = c.getresponse()
            uhtml = r.read().decode()
            c.close()
            self.assertIn("👤 普通用户", uhtml)
            self.assertNotIn("👥 用户管理", uhtml)
            self.assertNotIn("<form id='userAddForm'", uhtml)

    def test_multiuser_share_permissions(self):
        # 普通用户只能取消自己的分享；管理员可以取消任何人的
        with self.server("127.0.0.1") as port:
            app.create_user("adminpw1", is_admin=True)
            app.create_user("userpw22")
            _, acookie, _ = self._t_login(port, "adminpw1")
            _, ucookie, _ = self._t_login(port, "userpw22")
            asid = self._t_mk_recv_share(port, acookie, "admin的")
            usid = self._t_mk_recv_share(port, ucookie, "用户的")
            # 普通用户删管理员的分享：403
            s, j = self._t_api(port, "/api/delete", {"id": asid}, ucookie)
            self.assertEqual(s, 403)
            # 普通用户改管理员分享的备注/过期：403
            s, j = self._t_api(port, "/api/title", {"id": asid, "title": "x"}, ucookie)
            self.assertEqual(s, 403)
            s, j = self._t_api(port, "/api/expiry", {"id": asid, "expiry": "1"}, ucookie)
            self.assertEqual(s, 403)
            # 普通用户删自己的：ok
            s, j = self._t_api(port, "/api/delete", {"id": usid}, ucookie)
            self.assertEqual(s, 200)
            self.assertTrue(j["ok"])
            # 管理员删任何人的：ok（再建一个给管理员删）
            usid2 = self._t_mk_recv_share(port, ucookie, "用户的2")
            s, j = self._t_api(port, "/api/delete", {"id": usid2}, acookie)
            self.assertEqual(s, 200)
            self.assertTrue(j["ok"])
            # 删不存在的：404
            s, j = self._t_api(port, "/api/delete", {"id": "nope12345"}, acookie)
            self.assertEqual(s, 404)

    def test_multiuser_file_delete_admin_only(self):
        # 全部文件所有人可见，但删除只有管理员可以
        with self.server("127.0.0.1") as port:
            app.create_user("adminpw1", is_admin=True)
            app.create_user("userpw22")
            _, acookie, _ = self._t_login(port, "adminpw1")
            _, ucookie, _ = self._t_login(port, "userpw22")
            # 管理员上传一个文件
            bnd = "----mu"
            mp = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; "
                  f"filename=\"a.txt\"\r\n\r\nhello\r\n--{bnd}--\r\n").encode()
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/api/share", body=mp,
                      headers={"Content-Type": f"multipart/form-data; boundary={bnd}",
                               "Cookie": acookie})
            r = c.getresponse()
            sid = json.loads(r.read())["id"]
            c.close()
            with app.db() as dbc:
                fid = dbc.execute("SELECT id FROM files WHERE share_id=?",
                                  (sid,)).fetchone()["id"]
            # 普通用户能看到这个文件，但删不了；控制台里也没有删除按钮
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/dash", headers={"Cookie": ucookie})
            uhtml = c.getresponse().read().decode()
            c.close()
            self.assertIn("a.txt", uhtml)
            self.assertNotIn('onclick="delOneFile(', uhtml)
            self.assertNotIn("class='fileck'", uhtml)
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/dash", headers={"Cookie": acookie})
            ahtml = c.getresponse().read().decode()
            c.close()
            self.assertIn('onclick="delOneFile(', ahtml)
            self.assertIn("class='fileck'", ahtml)
            s, j = self._t_api(port, "/api/del_files", {"ids": str(fid)}, ucookie)
            self.assertEqual(s, 403)
            # 管理员可以删
            s, j = self._t_api(port, "/api/del_files", {"ids": str(fid)}, acookie)
            self.assertEqual(s, 200)
            self.assertEqual(j["deleted"], 1)

    def test_multiuser_user_management(self):
        # 用户管理只有管理员能用；没有注册入口
        with self.server("127.0.0.1") as port:
            app.create_user("adminpw1", is_admin=True)
            app.create_user("userpw22")
            _, acookie, _ = self._t_login(port, "adminpw1")
            _, ucookie, _ = self._t_login(port, "userpw22")
            # 普通用户调管理接口：403
            s, j = self._t_api(port, "/api/user_add",
                               {"pw1": "newpw33", "pw2": "newpw33"}, ucookie)
            self.assertEqual(s, 403)
            # 管理员添加用户
            s, j = self._t_api(port, "/api/user_add",
                               {"pw1": "newpw33", "pw2": "newpw33"}, acookie)
            self.assertEqual(s, 200)
            new_id = j["id"]
            # 密码不能和已有账号重复（否则登录无法区分是谁）
            s, j = self._t_api(port, "/api/user_add",
                               {"pw1": "adminpw1", "pw2": "adminpw1"}, acookie)
            self.assertEqual(s, 400)
            # 两次输入不一致
            s, j = self._t_api(port, "/api/user_add",
                               {"pw1": "newpw44", "pw2": "diff"}, acookie)
            self.assertEqual(s, 400)
            # 新用户能登录
            s, ncookie, _ = self._t_login(port, "newpw33")
            self.assertEqual(s, 302)
            # 管理员给新用户重设密码：旧密码失效
            s, j = self._t_api(port, "/api/user_resetpw",
                               {"id": new_id, "pw1": "resetpw5", "pw2": "resetpw5"},
                               acookie)
            self.assertEqual(s, 200)
            s, _, _ = self._t_login(port, "newpw33")
            self.assertEqual(s, 200)  # 旧密码登录失败，回到登录页
            s, ncookie, _ = self._t_login(port, "resetpw5")
            self.assertEqual(s, 302)
            # 普通用户不能给别人重设密码
            s, j = self._t_api(port, "/api/user_resetpw",
                               {"id": new_id, "pw1": "x", "pw2": "x"}, ucookie)
            self.assertEqual(s, 403)
            # 不能删管理员、不能删自己
            admin_id = app.find_user_by_pw("adminpw1")["id"]
            s, j = self._t_api(port, "/api/user_del", {"id": admin_id}, acookie)
            self.assertEqual(s, 403)
            # 新用户建个分享，删用户后分享失效、用户登不进
            usid = self._t_mk_recv_share(port, ncookie, "待删用户的")
            s, j = self._t_api(port, "/api/user_del", {"id": new_id}, acookie)
            self.assertEqual(s, 200)
            s, _, _ = self._t_login(port, "resetpw5")
            self.assertEqual(s, 200)
            s, j = self._t_api(port, "/api/delete", {"id": usid}, acookie)
            self.assertEqual(s, 404)

    def test_multiuser_chpw_kills_only_own_sessions(self):
        # 改密码只踢掉自己的其他会话，不能影响别的账号
        with self.server("127.0.0.1") as port:
            app.create_user("adminpw1", is_admin=True)
            app.create_user("userpw22")
            _, acookie, _ = self._t_login(port, "adminpw1")
            _, ucookie1, _ = self._t_login(port, "userpw22")
            _, ucookie2, _ = self._t_login(port, "userpw22")
            s, j = self._t_api(port, "/api/chpw",
                               {"new1": "usernew66", "new2": "usernew66"}, ucookie1)
            self.assertEqual(s, 200)
            self.assertTrue(j["ok"])

            def dash_status(cookie):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request("GET", "/dash", headers={"Cookie": cookie})
                r = c.getresponse()
                r.read()
                st = r.status
                c.close()
                return st
            # 自己的另一个会话被踢掉，管理员不受影响
            self.assertEqual(dash_status(ucookie2), 302)
            self.assertEqual(dash_status(acookie), 200)
            self.assertEqual(dash_status(ucookie1), 200)
            # 新密码能登录
            s, _, _ = self._t_login(port, "usernew66")
            self.assertEqual(s, 302)

    def test_multiuser_migration_from_single_pw(self):
        # 老版本数据库（meta.pw 单密码、无 users 表）升级后：
        # 旧密码变成管理员账号，老分享归管理员，老会话作废
        with app.db() as c:
            c.execute("INSERT INTO meta(k,v) VALUES('pw',?)",
                      (app.hash_pw("oldadminpw"),))
        # 手工造出老结构：删掉新表，按老 schema 重建
        with app.db() as c:
            c.execute("DROP TABLE sessions")
            c.execute("DROP TABLE shares")
            c.execute("DROP TABLE users")
            c.execute("CREATE TABLE sessions(token TEXT PRIMARY KEY,"
                      " created INTEGER, expires INTEGER)")
            c.execute("CREATE TABLE shares(id TEXT PRIMARY KEY, type TEXT,"
                      " title TEXT, created INTEGER, expires INTEGER)")
            now = int(time.time())
            c.execute("INSERT INTO sessions(token,created,expires) VALUES(?,?,?)",
                      ("oldt-token", now, now + 99999))
            c.execute("INSERT INTO shares(id,type,title,created,expires)"
                      " VALUES(?,?,?,?,?)", ("oldshr01", "send", "t", now, 0))
        app.init_db()  # 触发迁移
        self.assertTrue(app.has_users())
        admin = app.find_user_by_pw("oldadminpw")
        self.assertTrue(admin and admin["is_admin"])
        with app.db() as c:
            self.assertIsNone(c.execute("SELECT v FROM meta WHERE k='pw'").fetchone())
            self.assertEqual(c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
            owner = c.execute("SELECT owner_id FROM shares WHERE id='oldshr01'").fetchone()["owner_id"]
            self.assertEqual(owner, admin["id"])

    def _mkview_share(self, files, stype="send", owner=1):
        # files: [(filename, bytes)]，返回 (sid, [fid...])
        os.makedirs(app.FILES_DIR, exist_ok=True)
        now = int(time.time())
        sid = "viewtest01"
        with app.db() as c:
            c.execute("INSERT INTO shares(id,type,title,created,expires,owner_id)"
                      " VALUES(?,?,?,?,?,?)", (sid, stype, "t", now, 0, owner))
            ids = []
            for name, data in files:
                stored = "st_%d_%s" % (len(ids), name.replace("/", "_"))
                with open(os.path.join(app.FILES_DIR, stored), "wb") as f:
                    f.write(data)
                cur = c.execute("INSERT INTO files(share_id,filename,stored,size,created)"
                                " VALUES(?,?,?,?,?)",
                                (sid, name, stored, len(data), now))
                ids.append(cur.lastrowid)
        return sid, ids

    def _vget(self, port, path, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            c.request("GET", path, headers=headers or {})
            r = c.getresponse()
            body = r.read()
            return r.status, dict(r.getheaders()), body
        finally:
            c.close()

    def test_view_kind_svg_not_inline(self):
        # svg 内联打开时里面的脚本会在本站域名下执行：只能下载，不能查看
        self.assertIsNone(app._view_kind("x.svg"))
        self.assertEqual(app._view_kind("x.PNG"), "img")
        self.assertEqual(app._view_kind("x.Mp4"), "vid")
        self.assertIsNone(app._view_kind("x.txt"))

    def test_inline_view_image_200_and_headers(self):
        app.create_user("pw123456", is_admin=True)
        png = b"\x89PNG\r\n\x1a\n" + b"x" * 1000
        with self.server("127.0.0.1") as port:
            sid, (fid,) = self._mkview_share([("a.png", png)])
            s, h, body = self._vget(port, f"/s/{sid}/v/{fid}")
            self.assertEqual(s, 200)
            self.assertEqual(h.get("Content-Type"), "image/png")
            self.assertEqual(h.get("Content-Disposition"), "inline")
            self.assertEqual(h.get("Accept-Ranges"), "bytes")
            self.assertEqual(h.get("X-Content-Type-Options"), "nosniff")
            self.assertEqual(body, png)

    def test_inline_view_range_206_and_suffix_range(self):
        app.create_user("pw123456", is_admin=True)
        data = b"y" * 5000
        with self.server("127.0.0.1") as port:
            sid, (fid,) = self._mkview_share([("b.mp4", data)])
            s, h, body = self._vget(port, f"/s/{sid}/v/{fid}",
                                    {"Range": "bytes=0-99"})
            self.assertEqual(s, 206)
            self.assertEqual(h.get("Content-Range"),
                             "bytes 0-99/%d" % len(data))
            self.assertEqual(body, data[:100])
            # bytes=-N：最后 N 字节
            s, h, body = self._vget(port, f"/s/{sid}/v/{fid}",
                                    {"Range": "bytes=-10"})
            self.assertEqual(s, 206)
            self.assertEqual(h.get("Content-Range"),
                             "bytes %d-%d/%d" % (len(data) - 10, len(data) - 1,
                                                 len(data)))
            self.assertEqual(body, data[-10:])

    def test_inline_view_invalid_range_416(self):
        app.create_user("pw123456", is_admin=True)
        data = b"y" * 5000
        with self.server("127.0.0.1") as port:
            sid, (fid,) = self._mkview_share([("b.mp4", data)])
            s, _, _ = self._vget(port, f"/s/{sid}/v/{fid}",
                                 {"Range": "bytes=999999-"})
            self.assertEqual(s, 416)

    def test_inline_view_nonmedia_falls_back_to_download(self):
        app.create_user("pw123456", is_admin=True)
        # /v/ 指向非图片/视频：退回 attachment 下载，防 MIME 混淆
        data = b"hello"
        with self.server("127.0.0.1") as port:
            sid, (fid,) = self._mkview_share([("c.txt", data)])
            s, h, body = self._vget(port, f"/s/{sid}/v/{fid}")
            self.assertEqual(s, 200)
            self.assertTrue(h.get("Content-Disposition", "").startswith("attachment"))
            self.assertEqual(body, data)

    def test_inline_view_404_paths(self):
        app.create_user("pw123456", is_admin=True)
        data = b"y" * 100
        with self.server("127.0.0.1") as port:
            sid, (fid,) = self._mkview_share([("b.mp4", data)])
            # 不存在的文件 id
            self.assertEqual(self._vget(port, f"/s/{sid}/v/{fid + 9999}")[0], 404)
            # 不存在的分享 id
            self.assertEqual(self._vget(port, f"/s/nope1234/v/{fid}")[0], 404)
            # 接收链接没有在线查看
            os.makedirs(app.FILES_DIR, exist_ok=True)
            now = int(time.time())
            with app.db() as c:
                c.execute("INSERT INTO shares(id,type,title,created,expires,owner_id)"
                          " VALUES(?,?,?,?,?,1)", ("recvtest01", "receive", "t", now, 0))
            self.assertEqual(self._vget(port, f"/s/recvtest01/v/{fid}")[0], 404)

    def test_share_page_renders_preview_for_media(self):
        sid = "viewtest01"
        share = {"title": "t", "expires": 0}
        files = [{"id": 1, "filename": "a.png", "size": 10},
                 {"id": 2, "filename": "b.mp4", "size": 20},
                 {"id": 3, "filename": "c.txt", "size": 5}]
        body = app.share_page(sid, share, files).decode("utf-8")
        self.assertIn("<video", body)
        self.assertIn("<img", body)
        self.assertIn(f"/s/{sid}/v/1", body)
        self.assertIn(f"/s/{sid}/v/2", body)
        # txt 没有查看入口，但下载链接还在
        self.assertNotIn(f"/s/{sid}/v/3", body)
        self.assertIn(f"/s/{sid}/f/3", body)

    def _t_multipart(self, port, path, cookie, files):
        # files: [(filename, bytes)]，返回 (status, json)
        bnd = "----addt"
        parts = []
        for name, data in files:
            parts.append((f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; "
                          f"filename=\"{name}\"\r\n\r\n").encode() + data + b"\r\n")
        body = b"".join(parts) + f"--{bnd}--\r\n".encode()
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        c.request("POST", path, body=body,
                  headers={"Content-Type": f"multipart/form-data; boundary={bnd}",
                           "Cookie": cookie})
        r = c.getresponse()
        data = json.loads(r.read())
        c.close()
        return r.status, data

    def test_share_add_and_del_file_flow(self):
        # 分享创建后：主人可以在分享页追加文件、删除文件；
        # 删光后访客看到"文件都被删除啦"
        with self.server("127.0.0.1") as port:
            cookie = self._login_cookie(port)  # 管理员，同时是分享的 owner
            sid, (fid,) = self._mkview_share([("a.txt", b"hello")])
            # 追加一个文件
            s, data = self._t_multipart(port, f"/s/{sid}/add", cookie,
                                        [("b.png", b"\x89PNG\r\n\x1a\n" + b"z" * 50)])
            self.assertEqual(s, 200)
            self.assertTrue(data["ok"])
            self.assertEqual(data["count"], 1)
            _, _, body = self._vget(port, f"/s/{sid}")
            self.assertIn(b"b.png", body)
            # 删掉追加的文件
            with app.db() as c:
                newfid = c.execute("SELECT id FROM files WHERE share_id=? AND filename='b.png'",
                                   (sid,)).fetchone()["id"]
            s, data = self._t_api(port, "/api/share_file_del",
                                  {"sid": sid, "id": str(newfid)}, cookie)
            self.assertEqual(s, 200)
            self.assertTrue(data["ok"])
            self.assertEqual(self._vget(port, f"/s/{sid}/v/{newfid}")[0], 404)
            # 删光：访客看到"文件都被删除啦"
            s, data = self._t_api(port, "/api/share_file_del",
                                  {"sid": sid, "id": str(fid)}, cookie)
            self.assertTrue(data["ok"])
            _, _, body = self._vget(port, f"/s/{sid}")
            self.assertIn("文件都被删除啦".encode("utf-8"), body)

    def test_share_add_del_forbidden_for_other_user(self):
        # 普通用户不能给别人的分享加文件/删文件；管理员可以
        app.create_user("adminpw1", is_admin=True)
        app.create_user("userBbbb")
        with self.server("127.0.0.1") as port:
            _, bcookie, _ = self._t_login(port, "userBbbb")
            _, admcookie, _ = self._t_login(port, "adminpw1")
            sid, (fid,) = self._mkview_share([("a.txt", b"hello")], owner=1)
            # B 加文件 → 403
            s, data = self._t_multipart(port, f"/s/{sid}/add", bcookie,
                                        [("x.txt", b"x")])
            self.assertEqual(s, 403)
            self.assertFalse(data["ok"])
            # B 删文件 → 403
            s, data = self._t_api(port, "/api/share_file_del",
                                  {"sid": sid, "id": str(fid)}, bcookie)
            self.assertEqual(s, 403)
            # 未登录 → 401
            s, _ = self._t_multipart(port, f"/s/{sid}/add", "", [("x.txt", b"x")])
            self.assertEqual(s, 401)
            # 删别人的分享里不存在的文件 id → 404（不是 403 信息泄露）
            s, data = self._t_api(port, "/api/share_file_del",
                                  {"sid": sid, "id": "999999"}, admcookie)
            self.assertEqual(s, 404)
            # 管理员可以删
            s, data = self._t_api(port, "/api/share_file_del",
                                  {"sid": sid, "id": str(fid)}, admcookie)
            self.assertEqual(s, 200)
            self.assertTrue(data["ok"])

    def test_share_page_manage_controls_visibility(self):
        # 管理按钮（删除/添加文件）只出现在本人或管理员打开的分享页上
        sid = "viewtest01"
        share = {"title": "t", "expires": 0, "owner_id": 5}
        files = [{"id": 1, "filename": "a.txt", "size": 5}]
        b_owner = app.share_page(sid, share, files, {"id": 5, "is_admin": False}).decode("utf-8")
        self.assertIn("delShareFile", b_owner)
        self.assertIn("addForm", b_owner)
        b_other = app.share_page(sid, share, files, {"id": 6, "is_admin": False}).decode("utf-8")
        self.assertNotIn("delShareFile", b_other)
        self.assertNotIn("addForm", b_other)
        b_admin = app.share_page(sid, share, files, {"id": 7, "is_admin": True}).decode("utf-8")
        self.assertIn("delShareFile", b_admin)
        b_none = app.share_page(sid, share, files).decode("utf-8")
        self.assertNotIn("delShareFile", b_none)
        self.assertNotIn("addForm", b_none)
        # 文件删空后的提示文案
        b_empty = app.share_page(sid, share, [], {"id": 5, "is_admin": False}).decode("utf-8")
        self.assertIn("文件都被删除啦", b_empty)

    def test_console_file_download(self):
        # 控制台"全部文件"的下载：登录可下（attachment），
        # 分享链接删掉后的孤儿文件也能下；未登录跳登录页
        with self.server("127.0.0.1") as port:
            cookie = self._login_cookie(port)
            sid, (fid,) = self._mkview_share([("doc.pdf", b"%PDF-1.4" + b"z" * 100)])
            # 删掉分享链接，文件变孤儿
            with app.db() as c:
                c.execute("DELETE FROM shares WHERE id=?", (sid,))
            s, h, body = self._vget(port, f"/dl/{fid}", {"Cookie": cookie})
            self.assertEqual(s, 200)
            self.assertTrue(h.get("Content-Disposition", "").startswith("attachment"))
            self.assertEqual(body, b"%PDF-1.4" + b"z" * 100)
            # 不存在的文件 id → 404
            self.assertEqual(self._vget(port, "/dl/999999", {"Cookie": cookie})[0], 404)
            # 未登录 → 跳登录
            s, h, _ = self._vget(port, f"/dl/{fid}")
            self.assertEqual(s, 302)
            self.assertIn("/login", h.get("Location", ""))

    def test_dash_all_files_has_download_button(self):
        # "全部文件"每行都有下载按钮：管理员和普通用户都能看到
        now = int(time.time())
        with app.db() as c:
            c.execute("INSERT INTO shares(id,type,title,created,expires,owner_id)"
                      " VALUES(?,?,?,?,?,1)", ("dlbtn01", "send", "t", now, 0))
            cur = c.execute("INSERT INTO files(share_id,filename,stored,size,created)"
                            " VALUES(?,?,?,?,?)", ("dlbtn01", "a.txt", "st_a", 5, now))
            fid = cur.lastrowid
            shares = c.execute("SELECT * FROM shares").fetchall()
        for user in ({"id": 1, "is_admin": True}, {"id": 2, "is_admin": False}):
            body = app.dash_page(shares, user).decode("utf-8")
            self.assertIn(f"/dl/{fid}", body)
            self.assertIn("下载</button>", body)

    def test_dash_forms_use_postform(self):
        # 回归测试：添加用户/改密码曾用 new URLSearchParams([...fd]) 且没有 .catch，
        # 某些浏览器或网络下请求失败时页面静默、看起来"点了没反应"。
        # 现统一走 postForm：手动拼 urlencoded、有明确的失败提示。
        shares = []
        admin_html = app.dash_page(shares, {"id": 1, "is_admin": True}).decode("utf-8")
        self.assertIn("function postForm", admin_html)
        self.assertIn("postForm('/api/user_add'", admin_html)
        self.assertIn("postForm('/api/chpw'", admin_html)
        self.assertNotIn("URLSearchParams", admin_html)
        user_html = app.dash_page(shares, {"id": 2, "is_admin": False}).decode("utf-8")
        self.assertIn("postForm('/api/chpw'", user_html)
        self.assertNotIn("URLSearchParams", user_html)
        self.assertNotIn("<form id='userAddForm'", user_html)

    def test_postform_never_silent(self):
        # postForm 必须：有 .catch、有"处理中"反馈、提交时禁用按钮、
        # HTTP 错误时优先展示服务端返回的 error 文案。
        shares = []
        html = app.dash_page(shares, {"id": 1, "is_admin": True}).decode("utf-8")
        i = html.find("function postForm")
        self.assertGreater(i, 0)
        seg = html[i:html.find("</script>", i)]
        self.assertIn(".catch(function", seg)
        self.assertIn("处理中", seg)
        self.assertIn("btn.disabled=true", seg)
        self.assertIn("(j&&j.error)", seg)

    def test_user_add_duplicate_pw_json_error(self):
        # 密码重复时服务端返回 400 + JSON error，前端能直接展示文案而不是静默
        with self.server("127.0.0.1") as port:
            app.create_user("dup_pw_admin", is_admin=True)
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/login",
                      body=urllib.parse.urlencode({"pw": "dup_pw_admin"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            r.read()
            cookie = r.getheader("Set-Cookie").split(";")[0]
            c.request("POST", "/api/user_add",
                      body=urllib.parse.urlencode(
                          {"pw1": "dup_pw_admin", "pw2": "dup_pw_admin"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded",
                               "Cookie": cookie})
            r = c.getresponse()
            body = r.read()
            self.assertEqual(r.status, 400)
            j = json.loads(body)
            self.assertFalse(j["ok"])
            self.assertTrue(j["error"])
            c.close()

    def test_regular_user_changes_own_password(self):
        # 普通用户走 /api/chpw 改自己的密码：成功后新密码能登录、旧密码失效
        with self.server("127.0.0.1") as port:
            app.create_user("adm_for_chpw", is_admin=True)
            app.create_user("user_old_pw")
            def login(pw):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request("POST", "/login",
                          body=urllib.parse.urlencode({"pw": pw}).encode(),
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
                r = c.getresponse()
                r.read()
                ck = r.getheader("Set-Cookie")
                c.close()
                return r.status, (ck.split(";")[0].split("=")[1] if ck else None)
            st, cookie = login("user_old_pw")
            self.assertEqual(st, 302)
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/api/chpw",
                      body=urllib.parse.urlencode(
                          {"new1": "user_new_pw", "new2": "user_new_pw"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded",
                               "Cookie": f"sid={cookie}"})
            r = c.getresponse()
            self.assertEqual(r.status, 200)
            self.assertTrue(json.loads(r.read())["ok"])
            c.close()
            st_new, _ = login("user_new_pw")
            st_old, _ = login("user_old_pw")
            self.assertEqual(st_new, 302)
            self.assertEqual(st_old, 200)

    # ---- 小工具 ----
    def _login_as(self, port, pw):
        # 只登录（用户已由 create_user 建好），不重复创建
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", "/login",
                  body=urllib.parse.urlencode({"pw": pw}).encode(),
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 302)
        ck = r.getheader("Set-Cookie").split(";")[0]
        c.close()
        return ck

    def _post(self, port, path, fields, cookie):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", path,
                  body=urllib.parse.urlencode(fields).encode(),
                  headers={"Content-Type": "application/x-www-form-urlencoded",
                           "Cookie": cookie})
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, json.loads(body)

    def _upload_share(self, port, cookie, filename, data, ctype):
        boundary = "TSTBND"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
                f"filename=\"{filename}\"\r\nContent-Type: {ctype}\r\n\r\n").encode()
        body += data + f"\r\n--{boundary}--\r\n".encode()
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", "/api/share", body=body,
                  headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                           "Cookie": cookie})
        r = c.getresponse()
        j = json.loads(r.read())
        c.close()
        self.assertTrue(j["ok"])
        return j["id"]

    # ---- PDF 在线查看 ----
    def test_pdf_has_view_button_and_inline_view(self):
        # 回归：PDF 在分享页要有"查看"按钮（之前只有下载），
        # 点开后浏览器内联打开（application/pdf + inline），而不是下载。
        with self.server("127.0.0.1") as port:
            cookie = self._login_cookie(port, "pdf_admin")
            pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF"
            sid = self._upload_share(port, cookie, "322.pdf", pdf, "application/pdf")
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", f"/s/{sid}")
            r = c.getresponse()
            page = r.read().decode("utf-8")
            c.close()
            self.assertEqual(r.status, 200)
            m = re.search(r"/s/%s/v/(\d+)" % sid, page)
            self.assertIsNotNone(m, "分享页没有 PDF 的查看链接")
            self.assertIn("查看</button>", page)
            # 列表里不内联嵌入整个 PDF（太重），只给按钮
            self.assertNotIn("<embed", page)
            self.assertNotIn("<iframe", page)
            fid = m.group(1)
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", f"/s/{sid}/v/{fid}")
            r = c.getresponse()
            data = r.read()
            self.assertEqual(r.status, 200)
            self.assertEqual(r.getheader("Content-Type"), "application/pdf")
            self.assertIn("inline", r.getheader("Content-Disposition"))
            self.assertEqual(data, pdf)
            c.close()

    def test_pdf_view_supports_range(self):
        # PDF 阅读器打开大文件时会发 Range 分片请求，必须 206
        with self.server("127.0.0.1") as port:
            cookie = self._login_cookie(port, "pdf2_admin")
            pdf = b"%PDF-1.4\n" + b"x" * 5000 + b"\n%%EOF"
            sid = self._upload_share(port, cookie, "a.pdf", pdf, "application/pdf")
            with app.db() as c:
                fid = c.execute("SELECT id FROM files WHERE share_id=?", (sid,)).fetchone()["id"]
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", f"/s/{sid}/v/{fid}", headers={"Range": "bytes=0-99"})
            r = c.getresponse()
            data = r.read()
            c.close()
            self.assertEqual(r.status, 206)
            self.assertEqual(data, pdf[:100])

    def test_txt_view_still_forces_download(self):
        # 非图片/视频/PDF（比如 txt）走查看接口仍强制下载：防 MIME 混淆，原有行为不变
        with self.server("127.0.0.1") as port:
            cookie = self._login_cookie(port, "pdf3_admin")
            sid = self._upload_share(port, cookie, "note.txt", b"hello", "text/plain")
            with app.db() as c:
                fid = c.execute("SELECT id FROM files WHERE share_id=?", (sid,)).fetchone()["id"]
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", f"/s/{sid}/v/{fid}")
            r = c.getresponse()
            r.read()
            c.close()
            self.assertEqual(r.status, 200)
            self.assertIn("attachment", r.getheader("Content-Disposition"))
            # 分享页上 txt 没有查看按钮
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", f"/s/{sid}")
            page = c.getresponse().read().decode("utf-8")
            c.close()
            self.assertNotIn("查看</button>", page)

    # ---- 备注名 ----
    def test_user_remark_add_set_and_list(self):
        # 备注名：建用户时带 remark，之后改备注，list_users 读到最新值；
        # 全空白视为清除
        app.create_user("rmk_admin", is_admin=True)
        u = app.create_user("rmk_user1", remark="张三")
        users = {x["id"]: x for x in app.list_users()}
        self.assertEqual(users[u["id"]]["remark"], "张三")
        app.set_user_remark(u["id"], "李四")
        users = {x["id"]: x for x in app.list_users()}
        self.assertEqual(users[u["id"]]["remark"], "李四")
        app.set_user_remark(u["id"], "   ")
        users = {x["id"]: x for x in app.list_users()}
        self.assertEqual(users[u["id"]]["remark"], "")

    def test_user_add_api_with_remark(self):
        # /api/user_add 带 remark 字段：存进数据库
        with self.server("127.0.0.1") as port:
            cookie = self._login_cookie(port, "rmk2_admin")
            st, j = self._post(port, "/api/user_add",
                               {"pw1": "rmk2_user", "pw2": "rmk2_user", "remark": "王五"},
                               cookie)
            self.assertEqual(st, 200)
            self.assertTrue(j["ok"])
            users = {x["id"]: x for x in app.list_users()}
            self.assertEqual(users[j["id"]]["remark"], "王五")

    def test_user_remark_api(self):
        # 管理员改备注成功；普通用户调接口 403 且改不掉
        with self.server("127.0.0.1") as port:
            acookie = self._login_cookie(port, "rmk3_admin")
            u = app.create_user("rmk3_user", remark="原备注")
            ucookie = self._login_as(port, "rmk3_user")
            st, j = self._post(port, "/api/user_remark",
                               {"id": u["id"], "remark": "赵六"}, acookie)
            self.assertEqual(st, 200)
            self.assertTrue(j["ok"])
            users = {x["id"]: x for x in app.list_users()}
            self.assertEqual(users[u["id"]]["remark"], "赵六")
            st, j = self._post(port, "/api/user_remark",
                               {"id": u["id"], "remark": "黑客"}, ucookie)
            self.assertEqual(st, 403)
            users = {x["id"]: x for x in app.list_users()}
            self.assertEqual(users[u["id"]]["remark"], "赵六")

    def test_user_remark_xss_escaped(self):
        # 备注名里的 HTML 必须转义，不能注入脚本
        app.create_user("rmk4_admin", is_admin=True)
        u = app.create_user("rmk4_user", remark="<script>alert(1)</script>")
        page = app.dash_page([], {"id": 1, "is_admin": True}).decode("utf-8")
        m = re.search(r"id='rmk-%d'>(.*?)</span>" % u["id"], page)
        self.assertIsNotNone(m)
        self.assertNotIn("<script>", m.group(1))
        self.assertIn("&lt;script&gt;", m.group(1))

    def test_remark_and_pwplain_migration(self):
        # 老库（没有 remark / pw_plain 列）：init_db 自动补上，不丢数据
        import sqlite3
        dbp = os.path.join(self.tmp.name, "old.db")
        con = sqlite3.connect(dbp)
        con.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, pw TEXT, is_admin INTEGER, created INTEGER)")
        con.execute("INSERT INTO users(pw,is_admin,created) VALUES(?,?,?)", ("x", 1, 1))
        con.commit()
        con.close()
        app.DB_PATH = dbp
        app.init_db()
        cols = [r[1] for r in sqlite3.connect(dbp).execute("PRAGMA table_info(users)")]
        self.assertIn("remark", cols)
        self.assertIn("pw_plain", cols)

    def test_dash_remark_ui_only_for_admin(self):
        # 备注输入框/改备注按钮只出现在管理员的控制台
        app.create_user("rmk5_admin", is_admin=True)
        app.create_user("rmk5_user")
        pa = app.dash_page([], {"id": 1, "is_admin": True}).decode("utf-8")
        pn = app.dash_page([], {"id": 2, "is_admin": False}).decode("utf-8")
        self.assertIn("name='remark'", pa)
        self.assertIn('onclick="editRemark(', pa)
        self.assertNotIn('onclick="editRemark(', pn)
        self.assertNotIn("👥 用户管理</h2>", pn)

    # ---- 眼睛：管理员查看用户密码 ----
    def test_admin_can_view_user_pw(self):
        # 眼睛：管理员能看到用户当前明文密码
        with self.server("127.0.0.1") as port:
            cookie = self._login_cookie(port, "eye_admin")
            u = app.create_user("eye_user1")
            st, j = self._post(port, "/api/user_pw", {"id": u["id"]}, cookie)
            self.assertEqual(st, 200)
            self.assertTrue(j["ok"])
            self.assertEqual(j["pw"], "eye_user1")

    def test_admin_view_pw_follows_changes(self):
        # 用户自己改密码 / 管理员重设后，眼睛看到的永远是最新密码
        with self.server("127.0.0.1") as port:
            acookie = self._login_cookie(port, "eye2_admin")
            u = app.create_user("eye2_user")
            ucookie = self._login_as(port, "eye2_user")
            st, j = self._post(port, "/api/chpw",
                               {"new1": "eye2_newpw", "new2": "eye2_newpw"}, ucookie)
            self.assertEqual(st, 200)
            st, j = self._post(port, "/api/user_pw", {"id": u["id"]}, acookie)
            self.assertEqual(j["pw"], "eye2_newpw")
            st, j = self._post(port, "/api/user_resetpw",
                               {"id": u["id"], "pw1": "eye2_rst", "pw2": "eye2_rst"},
                               acookie)
            self.assertEqual(st, 200)
            st, j = self._post(port, "/api/user_pw", {"id": u["id"]}, acookie)
            self.assertEqual(j["pw"], "eye2_rst")

    def test_user_pw_admin_only(self):
        # 普通用户不能看任何人的密码；管理员也不能看管理员账号的
        with self.server("127.0.0.1") as port:
            acookie = self._login_cookie(port, "eye3_admin")
            u = app.create_user("eye3_user")
            ucookie = self._login_as(port, "eye3_user")
            st, _ = self._post(port, "/api/user_pw", {"id": u["id"]}, ucookie)
            self.assertEqual(st, 403)
            st, _ = self._post(port, "/api/user_pw", {"id": 1}, acookie)
            self.assertEqual(st, 403)

    def test_user_pw_old_account_empty(self):
        # 老版本迁移来的账号明文未知：返回空串，前端提示改一次密码后可见
        with self.server("127.0.0.1") as port:
            cookie = self._login_cookie(port, "eye4_admin")
            with app.db() as c:
                c.execute("INSERT INTO users(pw,is_admin,created) VALUES(?,?,?)",
                          (app.hash_pw("eye4_old"), 0, 1))
                uid = c.execute("SELECT id FROM users WHERE is_admin=0").fetchone()["id"]
            st, j = self._post(port, "/api/user_pw", {"id": uid}, cookie)
            self.assertEqual(st, 200)
            self.assertEqual(j["pw"], "")

    def test_eye_button_only_for_admin(self):
        # 眼睛按钮只在管理员控制台出现，普通用户页面没有任何痕迹
        app.create_user("eye5_admin", is_admin=True)
        app.create_user("eye5_user")
        pa = app.dash_page([], {"id": 1, "is_admin": True}).decode("utf-8")
        pn = app.dash_page([], {"id": 2, "is_admin": False}).decode("utf-8")
        self.assertIn('onclick="togglePw(', pa)
        self.assertNotIn('onclick="togglePw(', pn)
        self.assertNotIn("/api/user_pw", pn.split("<script>")[0])

    # ---- 未读请求体必须关连接（防 keep-alive 污染） ----
    def test_unread_body_closes_connection(self):
        # 回归：鉴权/参数检查失败直接返回、但请求体没读时，
        # 必须发 Connection: close，否则残留 body 会污染同一 keep-alive
        # 连接上的下一个请求（实测：/s/<sid>/add 404 后，下一个请求被
        # multipart 残留 body 污染成 400）。
        with self.server("127.0.0.1") as port:
            acookie = self._login_cookie(port, "cc_admin")
            u = app.create_user("cc_user")
            ucookie = self._login_as(port, "cc_user")
            big = "x" * 5000
            cases = [
                ("/s/deadbeef/add", acookie, 404),  # 分享不存在
                ("/api/user_add", ucookie, 403),    # 普通用户调管理员接口
                ("/logout", acookie, 302),          # POST logout 带 body
            ]
            for path, cookie, st in cases:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request("POST", path, body=big.encode(),
                          headers={"Content-Type": "text/plain", "Cookie": cookie})
                r = c.getresponse()
                r.read()
                self.assertEqual(r.status, st, path)
                self.assertEqual(r.getheader("Connection"), "close", path)
                c.close()

    def test_dead_add_closes_socket(self):
        # 更直接的证明：发完带 body 的 404 后，服务端真关掉 socket（读到 EOF），
        # 而不是留着连接让残留 body 污染下一个请求
        with self.server("127.0.0.1") as port:
            cookie = self._login_cookie(port, "cc2_admin")
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            body = b"x" * 3000
            req = (f"POST /s/deadbeef/add HTTP/1.1\r\nHost: x\r\n"
                   f"Cookie: {cookie}\r\nContent-Type: text/plain\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n"
                   ).encode() + body
            s.sendall(req)
            s.settimeout(3)
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            s.close()
            head = data.split(b"\r\n\r\n")[0].decode("latin1")
            self.assertIn("404", head.split("\r\n")[0])
            self.assertIn("Connection: close", head)
            # 能读到 EOF = 服务端关了连接；旧代码会一直挂着等下一个请求

    # ---- statvfs 失败 ----
    def test_too_large_msg_no_disk(self):
        # 磁盘信息未知时 413 文案不能谎称"剩余 0B"
        with patch.object(app.os, "statvfs", side_effect=OSError("nope")):
            msg = app.too_large_msg()
            self.assertNotIn("0B", msg)
            self.assertIn("超出上限", msg)
            foot = app.disk_foot()
            self.assertIn("磁盘信息不可用", foot)

    def test_login_rate_limited_after_many_failures(self):
        # 回归：登录是"密码即账号"（无用户名），以前无限次试密码还没限流，
        # 每次尝试还烧 20 万轮 pbkdf2。现在同一 IP 10 分钟内错 20 次就 429，
        # 登录成功清零（限流器放 Server 实例上，每个测试新实例互不干扰）。
        with self.server("127.0.0.1") as port:
            app.create_user("right-pw-123", is_admin=True)

            def login(pw):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                try:
                    c.request("POST", "/login",
                              body=urllib.parse.urlencode({"pw": pw}).encode(),
                              headers={"Content-Type":
                                       "application/x-www-form-urlencoded"})
                    r = c.getresponse()
                    st, body = r.status, r.read().decode("utf-8", "replace")
                    return st, body
                finally:
                    c.close()

            for _ in range(19):
                st, _ = login("wrong")
                self.assertEqual(st, 200)
            # 成功登录一次，计数清零
            st, _ = login("right-pw-123")
            self.assertEqual(st, 302)
            for _ in range(20):
                st, _ = login("wrong")
                self.assertEqual(st, 200)
            # 第 21 次：429，且页面上明确告诉用户等 10 分钟
            st, body = login("wrong")
            self.assertEqual(st, 429)
            self.assertIn("10 分钟", body)
            # 限流期间即使密码正确也进不去（先查限流器，避免被拿来烧 CPU）
            st, _ = login("right-pw-123")
            self.assertEqual(st, 429)

    def test_upload_too_many_files_rejected(self):
        # 回归：以前单次上传的文件 part 数量不限，每个 part 都在磁盘建临时
        # 文件——几千万个空 part 能把 inode 和 SQLite 拖死。现在超过 200 个
        # 直接 400，已落盘的临时文件要清理干净。
        with self.server("127.0.0.1") as port:
            app.create_user("pw123456", is_admin=True)
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            c.request("POST", "/login",
                      body=urllib.parse.urlencode({"pw": "pw123456"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            r.read()
            cookie = r.getheader("Set-Cookie").split(";")[0]
            bnd = "----many"
            parts = []
            for i in range(201):
                parts.append(f'--{bnd}\r\nContent-Disposition: form-data; name="f"; '
                             f'filename="f{i}.txt"\r\n\r\nx\r\n')
            parts.append(f"--{bnd}--\r\n")
            mp = "".join(parts).encode()
            c.request("POST", "/api/share", body=mp,
                      headers={"Content-Type": f"multipart/form-data; boundary={bnd}",
                               "Cookie": cookie})
            r = c.getresponse()
            self.assertEqual(r.status, 400)
            self.assertIn("too many files", r.read().decode("utf-8"))
            left = os.listdir(app.FILES_DIR) if os.path.isdir(app.FILES_DIR) else []
            self.assertEqual(left, [])
            c.close()

    def test_form_too_many_fields_rejected(self):
        # 回归：以前 urlencoded 表单的字段数不限，1MB 全是碎字段的 body
        # 会让 parse_qs 造出十几万个 dict 条目。现在超过 2000 个直接 400。
        try:
            urllib.parse.parse_qs(b"a=1", max_num_fields=1)
        except TypeError:
            self.skipTest("python < 3.10.7 没有 max_num_fields")
        with self.server("127.0.0.1") as port:
            app.create_user("pw123456", is_admin=True)
            body = "&".join(f"k{i}=v" for i in range(3000)).encode()
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("POST", "/login", body=body,
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            self.assertEqual(r.status, 400)
            r.read()
            c.close()

    def test_dl_expired_share_404_but_orphan_ok(self):
        # 回归：/dl/<fid> 以前不看分享是否过期——控制台"全部文件"隐藏了
        # 过期分享的文件，但记下 /dl/ 链接的人照样能下。现在过期分享的
        # 文件走 /dl/ 也 404（并顺手删掉过期分享）；分享已删的孤儿文件
        # 不受影响，照样能下。
        with self.server("127.0.0.1") as port:
            app.create_user("pw123456", is_admin=True)
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("POST", "/login",
                      body=urllib.parse.urlencode({"pw": "pw123456"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            r.read()
            cookie = r.getheader("Set-Cookie").split(";")[0]

            def get(path):
                c2 = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                try:
                    c2.request("GET", path, headers={"Cookie": cookie})
                    r2 = c2.getresponse()
                    return r2.status, r2.getheader("X-Content-Type-Options"), r2.read()
                finally:
                    c2.close()

            os.makedirs(app.FILES_DIR, exist_ok=True)
            now = int(time.time())
            with app.db() as dbc:
                # 已过期的分享 + 文件
                dbc.execute("INSERT INTO shares(id,type,title,created,expires,owner_id)"
                            " VALUES(?,?,?,?,?,?)",
                            ("expired01", "send", "t", now, now - 10, 1))
                stored1 = "stored-expired-1"
                open(os.path.join(app.FILES_DIR, stored1), "wb").write(b"expired-data")
                dbc.execute("INSERT INTO files(share_id,filename,stored,size,created)"
                            " VALUES(?,?,?,?,?)",
                            ("expired01", "a.txt", stored1, 12, now))
                fid_exp = dbc.execute("SELECT id FROM files WHERE stored=?",
                                      (stored1,)).fetchone()[0]
                # 孤儿文件：分享行已删
                stored2 = "stored-orphan-2"
                open(os.path.join(app.FILES_DIR, stored2), "wb").write(b"orphan-data")
                dbc.execute("INSERT INTO files(share_id,filename,stored,size,created)"
                            " VALUES(?,?,?,?,?)",
                            ("gone-share", "b.txt", stored2, 11, now))
                fid_orphan = dbc.execute("SELECT id FROM files WHERE stored=?",
                                         (stored2,)).fetchone()[0]
            st, _, _ = get(f"/dl/{fid_exp}")
            self.assertEqual(st, 404)
            # 过期分享被顺手删掉，文件变成孤儿后反而能下了（和控制台一致）
            st, nosniff, body = get(f"/dl/{fid_exp}")
            self.assertEqual(st, 200)
            self.assertEqual(body, b"expired-data")
            st, nosniff, body = get(f"/dl/{fid_orphan}")
            self.assertEqual(st, 200)
            self.assertEqual(nosniff, "nosniff")
            self.assertEqual(body, b"orphan-data")
            c.close()

    def test_share_file_del_expired_share_404(self):
        # 回归：/api/share_file_del 以前用 get_share 不看过期——分享页对
        # 过期分享已经 404 了，但清理线程跑之前还能调接口删里面的文件。
        # 现在跟分享页一致：404。
        with self.server("127.0.0.1") as port:
            app.create_user("pw123456", is_admin=True)
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("POST", "/login",
                      body=urllib.parse.urlencode({"pw": "pw123456"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            r.read()
            cookie = r.getheader("Set-Cookie").split(";")[0]
            now = int(time.time())
            with app.db() as dbc:
                dbc.execute("INSERT INTO shares(id,type,title,created,expires,owner_id)"
                            " VALUES(?,?,?,?,?,?)",
                            ("expired02", "send", "t", now, now - 10, 1))
            c.request("POST", "/api/share_file_del",
                      body=urllib.parse.urlencode({"sid": "expired02",
                                                   "id": "1"}).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded",
                               "Cookie": cookie})
            r = c.getresponse()
            self.assertEqual(r.status, 404)
            self.assertIn("已过期", r.read().decode("utf-8"))
            c.close()


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

    def test_install_rejects_bad_app_dir(self):
        # 回归测试：安装目录之前只校验了"绝对路径+字符集"，APP_DIR="/"
        # 或带 .. 的路径也能通过；"/" 会导致文件被拷到根目录（//fileshare.py）。
        text = (ROOT / "install.sh").read_text()
        start = text.index('case "$APP_DIR" in\n  /*)')
        end = text.index("# 按选择的 IP 版本决定监听地址")
        block = text[start:end]

        def run(d):
            r = subprocess.run(["sh", "-c", "set -eu\n" + block],
                               env={**os.environ, "APP_DIR": d},
                               capture_output=True, text=True, timeout=10)
            return r.returncode

        self.assertNotEqual(run("/"), 0)
        self.assertNotEqual(run("/opt/../evil"), 0)
        self.assertNotEqual(run("/.."), 0)
        self.assertEqual(run("/opt/minishare"), 0)
        self.assertEqual(run("/opt/mini-share_2.0"), 0)

    def test_install_validates_template_placeholders(self):
        # 回归测试：下载的服务模板如果被代理/缓存换成 200 错误页面，
        # sed 替换占位符会静默失败，装出坏服务；现在下载后校验占位符。
        text = (ROOT / "install.sh").read_text()
        start = text.index("for t in minishare.service minishare.openrc; do")
        end = text.index('echo "下载完成。"', start)
        block = text[start:end]
        with tempfile.TemporaryDirectory() as folder:
            bad = Path(folder) / "minishare.service"
            bad.write_text("<html>error page</html>")
            good = Path(folder) / "minishare.openrc"
            good.write_text("Environment=SHARE_DATA=@APP_DIR@/data")
            script = "set -eu\ncd " + shlex.quote(folder) + "\n" + block
            r = subprocess.run(["sh", "-c", script], capture_output=True,
                               text=True, timeout=10)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("不是有效的服务模板", r.stdout + r.stderr)
            bad.write_text("Environment=SHARE_DATA=@APP_DIR@/data")
            r = subprocess.run(["sh", "-c", script], capture_output=True,
                               text=True, timeout=10)
            self.assertEqual(r.returncode, 0, r.stderr)

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
            # 注意：假 systemctl 必须"真实"——restart 失败后 is-active 也要失败。
            # 新版脚本里 restart 失败不再被 set -e 直接掐死（|| true），而是由
            # [8b] 的 is-active 检查来发现失败并回滚；假 is-active 永远成功
            # 会让失败路径测不到。
            commands = {'sleep': 'exit 0', 'systemctl':
                        'if [ "$1 $2" = "restart caddy" ] && [ "$FAIL_CADDY" = 1 ]; then exit 1; fi\n'
                        'if [ "$1 $2" = "is-active --quiet" ] && [ "$FAIL_CADDY" = 1 ]; then exit 1; fi\nexit 0',
                        'journalctl': 'exit 1'}
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

    def nat_port_block(self):
        text = (ROOT / 'enable-https.sh').read_text()
        start = text.index('ORIG_PORT="$PORT"')
        end = text.index('if [ "$NAT" = "1" ]; then\n  echo "使用 NAT 模式')
        return text[start:end]

    def run_nat_port(self, block, srv_host, service_port, saved_port):
        with tempfile.TemporaryDirectory() as folder:
            saved = Path(folder) / 'nat-port'
            saved.write_text(saved_port + '\n')
            script = ('set -eu\n' + block.replace('/etc/minishare-nat-port', str(saved))
                      + '\nprintf "PORT=%s\\n" "$PORT"\n')
            r = subprocess.run(['sh', '-c', script],
                               env={**os.environ, 'NAT': '1',
                                    'SRV_HOST': srv_host, 'PORT': service_port},
                               capture_output=True, text=True, timeout=10)
            self.assertEqual(r.returncode, 0, r.stderr)
            return r.stdout.strip().splitlines()[-1]

    def test_nat_rerun_after_reinstall_uses_new_port(self):
        # 回归测试：用户重装改了端口后，旧保存文件里的端口不能再覆盖新端口
        #（之前会静默用回旧端口，Caddy 监听的和用户刚选的不一致）。
        block = self.nat_port_block()
        self.assertEqual(self.run_nat_port(block, '0.0.0.0', '20000', '19332'),
                         'PORT=20000')

    def test_nat_rerun_without_reinstall_keeps_saved_port(self):
        # 没重装（minishare 仍在 127.0.0.1）时，沿用上次的 HTTPS 公开端口。
        block = self.nat_port_block()
        self.assertEqual(self.run_nat_port(block, '127.0.0.1', '45678', '19332'),
                         'PORT=19332')

    def dns_check_block(self):
        text = (ROOT / 'enable-https.sh').read_text()
        start = text.index('if [ -n "$PUBIP" ] && [ "$DNSIP" != "$PUBIP" ]; then')
        end = text.index('echo "域名解析正常', start)
        return text[start:end]

    def run_dns_check(self, block, nat):
        script = 'set -eu\n' + block + '\necho STILL_ALIVE\n'
        return subprocess.run(['sh', '-c', script],
                              env={**os.environ, 'NAT': nat, 'PUBIP': '5.6.7.8',
                                   'DNSIP': '1.2.3.4', 'DOMAIN': 'd.test', 'REC': 'A'},
                              capture_output=True, text=True, timeout=10)

    def test_nat_dns_mismatch_warns_but_continues(self):
        # 回归测试：NAT 机器出口 IP 与域名入站 IP 不同是常态，证书走 DNS
        # 验证不依赖 IP 一致；之前直接退出，还误导用户把 A 记录改成出口 IP。
        block = self.dns_check_block()
        r = self.run_dns_check(block, '1')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('STILL_ALIVE', r.stdout)
        self.assertIn('注意', r.stdout)

    def test_normal_dns_mismatch_still_blocks(self):
        # 普通模式走 HTTP 验证，IP 对不上证书确实下不来，保持硬阻断。
        block = self.dns_check_block()
        r = self.run_dns_check(block, '0')
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn('STILL_ALIVE', r.stdout)

    def port_check_block(self):
        text = (ROOT / 'enable-https.sh').read_text()
        start = text.index('for p in 80 443; do')
        end = text.index('echo "80/443 端口空闲.')
        return text[start:end]

    def run_port_check(self, listen, port):
        block = self.port_check_block()
        script = 'set -eu\n_LISTEN="$1"\nPORT="$2"\n' + block + '\necho STILL_ALIVE'
        return subprocess.run(['sh', '-c', script, 'sh', listen, port],
                              capture_output=True, text=True, timeout=10)

    def test_port_check_detects_minishare_itself(self):
        # 回归：minishare 自己就装在 80/443 上时，提示必须说"重装换端口"，
        # 而不是让用户"停掉占用程序"（停掉 minishare 自己没有意义）。
        r = self.run_port_check('tcp 0 0 0.0.0.0:80 x', '80')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('minishare 自己就装在端口 80 上', r.stdout)
        self.assertIn('STILL_ALIVE', self.run_port_check('', '18080').stdout)

    def test_port_check_other_program_message(self):
        # 别人占了 443：保持原来的"停掉占用程序"提示
        r = self.run_port_check('tcp 0 0 :::443 x', '18080')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('停掉占用它们的程序', r.stdout)

    def test_normal_caddyfile_backed_up(self):
        # 回归：普通模式覆盖 /etc/caddy/Caddyfile 前必须先备份，
        # 之前直接覆盖，机器上原有的 Caddy 配置就丢了。
        text = (ROOT / 'enable-https.sh').read_text()
        a = text.index('echo "[4] 配置反向代理…')
        block = text[a:text.index('# ---- [5] 设置开机自启', a)]
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / 'Caddyfile').write_text('old config\n')
            block2 = block.replace('/etc/caddy', folder)
            r = subprocess.run(['sh', '-c', 'set -eu\n' + block2],
                               env={**os.environ, 'SRV_HOST': '0.0.0.0',
                                    'PORT': '18080', 'DOMAIN': 'test.example.com'},
                               capture_output=True, text=True, timeout=10)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual((Path(folder) / 'Caddyfile.bak').read_text(), 'old config\n')
            self.assertIn('test.example.com', (Path(folder) / 'Caddyfile').read_text())

    def test_caddy_restart_never_kills_script(self):
        # 回归：set -e 下裸写 systemctl restart caddy，失败会直接退出脚本，
        # 后面的"[5b]/[8b] 是否真在跑"检查和日志打印就永远跑不到了。
        # 所有启动 caddy 的地方必须 || true，把"起没起来"的判断交给后面的检查。
        text = (ROOT / 'enable-https.sh').read_text()
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if s.startswith('#') or 'RELOAD_HOOK' in s:
                continue
            if 'systemctl restart caddy' in s or 'rc-service caddy restart' in s:
                self.assertIn('|| true', s, f'line {i}: {s}')


    def test_normal_mode_restores_caddyfile_on_failure(self):
        # 回归：普通模式 [5b] Caddy 没起来时，以前直接 exit 1——但 [4] 已经
        # 把 Caddyfile 覆盖了。如果机器之前跑的是别的 Caddy 配置（比如之前
        # 成功跑过的 NAT 模式），原来的 HTTPS 反而被这次失败的运行搞挂了。
        # 现在失败时必须先把 Caddyfile.bak 恢复回去并尽量重启 Caddy。
        text = (ROOT / 'enable-https.sh').read_text()
        start = text.index('if [ "$CADDY_CHECKABLE" = "1" ]')
        end = text.index('exit 1\nfi', start) + len('exit 1\nfi')
        block = text[start:end]
        with tempfile.TemporaryDirectory() as folder:
            caddy_dir = Path(folder) / 'caddy'
            caddy_dir.mkdir()
            (caddy_dir / 'Caddyfile').write_text('new broken config\n')
            (caddy_dir / 'Caddyfile.bak').write_text('old working config\n')
            bindir = Path(folder) / 'bin'
            bindir.mkdir()
            # 假 systemctl：盖住测试机上真家伙，记录调用并让 restart 失败——
            # 失败也不能杀死脚本（|| true 由另一个回归测试保证），恢复流程
            # 必须照样走完。
            (bindir / 'systemctl').write_text(
                '#!/bin/sh\necho "$@" >> "$RC_LOG"\nexit 1\n')
            (bindir / 'systemctl').chmod(0o755)
            block2 = block.replace('/etc/caddy', str(caddy_dir))
            r = subprocess.run(['sh', '-c', 'set -eu\n' + block2],
                               env={**os.environ,
                                    'PATH': str(bindir) + ':/usr/bin:/bin',
                                    'CADDY_CHECKABLE': '1', 'CADDY_OK': '0',
                                    'RC_LOG': str(Path(folder) / 'rc.log')},
                               capture_output=True, text=True, timeout=10)
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertEqual((caddy_dir / 'Caddyfile').read_text(),
                             'old working config\n')
            self.assertIn('restart caddy', (Path(folder) / 'rc.log').read_text())

if __name__ == '__main__':
    unittest.main(verbosity=2)
