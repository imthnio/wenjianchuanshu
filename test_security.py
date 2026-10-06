"""Security regressions: inline whitelist, Range edge cases, CSRF, headers, bounded ids."""
import http.client
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib.parse import urlencode

spec = importlib.util.spec_from_file_location('security_app', Path(__file__).with_name('fileshare.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

DATA = bytes(range(256)) * 40  # 10240 字节


class SecurityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        app.DATA_DIR = self.tmp.name
        app.FILES_DIR = os.path.join(self.tmp.name, 'files')
        app.DB_PATH = os.path.join(self.tmp.name, 'share.db')
        app.init_db()
        now = int(time.time())
        with app.db() as c:
            c.execute("INSERT INTO users(id,pw,is_admin,created) VALUES(1,'x',1,?)", (now,))
            c.execute("INSERT INTO sessions VALUES('tok1',1,?,?)", (now, now + 3600))
            c.execute("INSERT INTO shares(id,type,title,created,expires,owner_id) VALUES('share','send','t',?,0,1)", (now,))
            self.ids = {}
            for name, data in (("evil.svg", b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"),
                               ("page.html", b"<script>alert(1)</script>"),
                               ("v.mp4", DATA), ("pic.png", b"\x89PNG" + DATA),
                               ("中文 名字;\"x\".bin", b"abc"), ("empty.txt", b"")):
                stored = "st%d" % len(self.ids)
                with open(os.path.join(app.FILES_DIR, stored), "wb") as f:
                    f.write(data)
                cur = c.execute("INSERT INTO files(share_id,filename,stored,size,created,owner_id)"
                                " VALUES('share',?,?,?,?,1)", (name, stored, len(data), now))
                self.ids[name] = cur.lastrowid
        self.server = app.Server(('127.0.0.1', 0), app.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def req(self, method, path, headers=None, form=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        body = urlencode(form) if form is not None else None
        h = dict(headers or {})
        if form is not None:
            h['Content-Type'] = 'application/x-www-form-urlencoded'
        conn.request(method, path, body, h)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data

    def test_svg_and_html_never_inline(self):
        for name in ("evil.svg", "page.html"):
            s, h, _ = self.req("GET", "/s/share/v/%d" % self.ids[name])
            self.assertEqual(s, 200)
            self.assertTrue(h["content-disposition"].startswith("attachment"), name)
            self.assertIn("sandbox", h["content-security-policy"])
            self.assertEqual(h["x-content-type-options"], "nosniff")
            # 下载接口同样带 sandbox，直接在地址栏打开也不能以本站身份执行
            s, h, _ = self.req("GET", "/s/share/f/%d" % self.ids[name])
            self.assertIn("sandbox", h["content-security-policy"])

    def test_media_inline_without_sandbox(self):
        # 音视频/图片不加 sandbox：否则浏览器新窗口直接打开视频会因无来源而加载失败
        for name, ctype in (("v.mp4", "video/mp4"), ("pic.png", "image/png")):
            s, h, _ = self.req("GET", "/s/share/v/%d" % self.ids[name])
            self.assertEqual((s, h["content-type"]), (200, ctype))
            self.assertTrue(h["content-disposition"].startswith("inline"))
            self.assertNotIn("content-security-policy", h)

    def test_range_edge_cases(self):
        path = "/s/share/v/%d" % self.ids["v.mp4"]
        n = len(DATA)
        cases = [("bytes=0-99", 206, DATA[:100], "bytes 0-99/%d" % n),
                 ("bytes=100-", 206, DATA[100:], "bytes 100-%d/%d" % (n - 1, n)),
                 ("bytes=-10", 206, DATA[-10:], None),
                 ("bytes=-99999", 206, DATA, None),
                 ("bytes=0-999999", 206, DATA, "bytes 0-%d/%d" % (n - 1, n)),
                 ("bytes=%d-" % n, 416, b"", "bytes */%d" % n),
                 ("bytes=-0", 416, b"", None),
                 # 格式不支持/无效：忽略 Range，返回整个文件（之前多段 Range 回 416）
                 ("bytes=0-1,5-6", 200, DATA, None),
                 ("bytes=5-2", 200, DATA, None),
                 ("items=0-1", 200, DATA, None),
                 # 超长数字：之前 int() 抛异常，500
                 ("bytes=" + "9" * 5000 + "-", 200, DATA, None)]
        for rng, status, body, crange in cases:
            s, h, data = self.req("GET", path, {"Range": rng})
            self.assertEqual(s, status, rng)
            self.assertEqual(data, body, rng)
            if crange:
                self.assertEqual(h.get("content-range"), crange, rng)
        # 下载接口也支持 Range（断点续传）
        s, h, data = self.req("GET", "/s/share/f/%d" % self.ids["v.mp4"], {"Range": "bytes=10-19"})
        self.assertEqual((s, data), (206, DATA[10:20]))
        self.assertEqual(h["accept-ranges"], "bytes")
        self.assertTrue(h["content-disposition"].startswith("attachment"))
        # HEAD 不带 body
        s, h, data = self.req("HEAD", path, {"Range": "bytes=0-9"})
        self.assertEqual((s, h["content-length"], data), (206, "10", b""))
        # 空文件
        s, _, data = self.req("GET", "/s/share/v/%d" % self.ids["empty.txt"])
        self.assertEqual((s, data), (200, b""))

    def test_content_disposition_chinese_name(self):
        s, h, _ = self.req("GET", "/s/share/f/%d" % self.ids["中文 名字;\"x\".bin"])
        self.assertEqual(s, 200)
        cd = h["content-disposition"]
        self.assertEqual(cd, "attachment; filename=\"__ ____x_.bin\"; "
                             "filename*=UTF-8''%E4%B8%AD%E6%96%87%20%E5%90%8D%E5%AD%97%3B%22x%22.bin")

    def test_cross_site_posts_rejected(self):
        form = {"title": "csrf", "expiry": "1"}
        for headers in ({"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"},
                        {"Origin": "https://evil.example"}, {"Origin": "null"}):
            headers = dict(headers, Cookie="sid=tok1")
            s, _, body = self.req("POST", "/api/share_create", headers, form)
            self.assertEqual(s, 403, headers)
            self.assertFalse(json.loads(body)["ok"])
        with app.db() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM shares").fetchone()[0], 1)
        host = "127.0.0.1:%d" % self.server.server_port
        for headers in ({"Sec-Fetch-Site": "same-origin"}, {"Origin": "http://" + host}, {}):
            headers = dict(headers, Cookie="sid=tok1")
            s, _, body = self.req("POST", "/api/share_create", headers, form)
            self.assertEqual(s, 200, headers)
        # 老浏览器只带 Origin、反代改写了 Host：本机反代转来的 X-Forwarded-Host 算同源
        s, _, _ = self.req("POST", "/api/share_create",
                           {"Cookie": "sid=tok1", "Origin": "https://files.example.com",
                            "Host": "127.0.0.1", "X-Forwarded-Host": "files.example.com"}, form)
        self.assertEqual(s, 200)
        # 跨站登录（login CSRF）同样拒绝
        s, _, _ = self.req("POST", "/login", {"Sec-Fetch-Site": "cross-site"}, {"pw": "x"})
        self.assertEqual(s, 403)

    def test_page_security_headers(self):
        s, h, _ = self.req("GET", "/s/share")
        self.assertEqual(s, 200)
        self.assertEqual(h["x-frame-options"], "DENY")
        self.assertIn("frame-ancestors 'none'", h["content-security-policy"])
        self.assertEqual(h["cache-control"], "no-store")
        self.assertEqual(h["x-content-type-options"], "nosniff")

    def test_share_cancelled_during_plain_upload_not_attached(self):
        # 回归：普通（非分片）上传只在开始时查分享；传到一半分享被取消/过期，
        # 文件仍会挂到失效分享上。现在入库前再查一次，并删掉已落盘的文件。
        from unittest.mock import patch
        now = int(time.time())
        with app.db() as c:
            c.execute("INSERT INTO shares(id,type,title,created,expires,owner_id) VALUES('recv','receive','t',?,0,1)", (now,))
        orig = app.Handler._multipart

        def cancel_midway(handler, *a, **kw):
            res = orig(handler, *a, **kw)
            app.delete_share(self._cancel)
            return res
        boundary = "BOUNDARYx"
        body = ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n"
                "Content-Type: text/plain\r\n\r\nhello\r\n--%s--\r\n" % (boundary, boundary)).encode()
        before = set(os.listdir(app.FILES_DIR))
        with patch.object(app.Handler, "_multipart", cancel_midway):
            for self._cancel, path, cookie in (("recv", "/r/recv/upload", None),
                                               ("share", "/s/share/add", "sid=tok1")):
                conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
                h = {"Content-Type": "multipart/form-data; boundary=" + boundary}
                if cookie:
                    h["Cookie"] = cookie
                conn.request("POST", path, body, h)
                r = conn.getresponse()
                r.read()
                conn.close()
                self.assertEqual(r.status, 404, path)
        with app.db() as c:
            n = c.execute("SELECT COUNT(*) FROM files WHERE filename='a.txt'").fetchone()[0]
        self.assertEqual(n, 0)
        self.assertEqual(set(os.listdir(app.FILES_DIR)), before)

    def test_bidi_controls_stripped_from_filenames(self):
        # 匿名上传的"发票\u202egnp.exe"不能在页面上显示成"发票exe.png"
        self.assertEqual(app._clean_filename("发票\u202egnp.exe"), "发票gnp.exe")
        self.assertEqual(app._clean_filename("a\u2066b\u2069\u202a.txt"), "ab.txt")
        self.assertEqual(app._clean_filename("中文 😀 名字.txt"), "中文 😀 名字.txt")

    def test_filename_edge_cases(self):
        self.assertEqual(app._clean_filename(".."), "unnamed")
        self.assertEqual(app._clean_filename("a/."), "unnamed")
        long = "名" * 300 + ".mp4"
        out = app._clean_filename(long)
        self.assertEqual(len(out), 200)
        self.assertTrue(out.endswith(".mp4"))
        self.assertEqual(app._view_kind(out), "vid")
        self.assertEqual(len(app._clean_filename("x" * 300)), 200)

    def test_listen_backlog_not_tiny(self):
        # socketserver 默认 listen(5)：并发上传一多，新连接直接被内核 reset
        self.assertGreaterEqual(app.Server.request_queue_size, 128)
        results = []

        def hit():
            try:
                st, _, _ = self.req('GET', '/healthz')
                results.append(st)
            except OSError as e:
                results.append(repr(e))
        ts = [threading.Thread(target=hit) for _ in range(60)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(results, [200] * 60)

    def test_server_header_hides_python_version(self):
        st, h, _ = self.req('GET', '/healthz')
        self.assertEqual(h.get('server'), 'minishare/' + app.VERSION)

    def test_db_and_files_not_world_readable(self):
        # 数据库里有明文密码（管理员可查看），同机其他账号不能读
        os.chmod(app.DB_PATH, 0o644)
        os.chmod(app.FILES_DIR, 0o755)
        app.init_db()  # 升级旧安装时也收紧
        self.assertEqual(os.stat(app.DB_PATH).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(app.FILES_DIR).st_mode & 0o777, 0o700)

    def test_oversized_ids_are_not_500(self):
        big = "9" * 25
        for path in ("/s/share/f/" + big, "/s/share/v/" + big, "/dl/" + big):
            s, _, _ = self.req("GET", path, {"Cookie": "sid=tok1"})
            self.assertEqual(s, 404, path)
        for url, form in (("/api/del_files", {"ids": big}),
                          ("/api/user_remark", {"id": big, "remark": "x"}),
                          ("/api/user_del", {"id": big}),
                          ("/api/user_resetpw", {"id": big, "pw1": "abcd", "pw2": "abcd"}),
                          ("/api/user_pw", {"id": big}),
                          ("/api/share_file_del", {"sid": "share", "id": big}),
                          ("/api/share_file_existing", {"sid": "share", "ids": big})):
            s, _, _ = self.req("POST", url, {"Cookie": "sid=tok1"}, form)
            self.assertIn(s, (200, 400, 404), url)


if __name__ == '__main__':
    unittest.main()
