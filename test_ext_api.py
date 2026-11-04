"""同机程序接口：/api/ext/shares 和 /api/ext/upload。"""
import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from urllib.parse import quote

_data = tempfile.TemporaryDirectory()
os.environ["SHARE_DATA"] = _data.name
import fileshare as app


class ExtApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.init_db()
        cls.key = app.ext_key()
        now = int(time.time())
        with app.db() as c:
            c.execute("INSERT INTO users(id,pw,is_admin,created,remark) VALUES(1,'x',1,?,'我')", (now,))
            c.execute("INSERT INTO users(id,pw,is_admin,created) VALUES(2,'y',0,?)", (now,))
            for sid, owner, typ, exp, title in (
                    ("wall", 2, "send", 0, "动态壁纸"),
                    ("eng", 1, "send", now + 3600, "英语学习资料"),
                    ("recv", 1, "receive", 0, "收件"),
                    ("old", 1, "send", now - 5, "过期了")):
                c.execute("INSERT INTO shares(id,type,title,created,expires,owner_id)"
                          " VALUES(?,?,?,?,?,?)", (sid, typ, title, now, exp, owner))
        cls.server = app.Server(("127.0.0.1", 0), app.Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        _data.cleanup()

    def setUp(self):
        self.server._login_fail.clear()

    def req(self, method, path, body=None, key=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        h = {}
        if key is not None:
            h["Authorization"] = "Bearer " + key
        conn.request(method, path, body, h)
        r = conn.getresponse()
        data = json.loads(r.read() or b"{}")
        conn.close()
        return r.status, data

    def test_key_file_private(self):
        self.assertRegex(self.key, r"^[0-9a-f]{64}$")
        self.assertEqual(os.stat(app.ext_key_path()).st_mode & 0o777, 0o600)
        self.assertEqual(app.ext_key(), self.key)

    def test_needs_key(self):
        self.assertEqual(self.req("GET", "/api/ext/shares")[0], 401)
        self.assertEqual(self.req("GET", "/api/ext/shares", key="0" * 64)[0], 401)
        st, _ = self.req("POST", "/api/ext/upload?share=wall&name=a.mp4", b"abc", key="bad")
        self.assertEqual(st, 401)

    def test_list_only_live_send_shares(self):
        st, d = self.req("GET", "/api/ext/shares", key=self.key)
        self.assertEqual(st, 200)
        self.assertEqual({s["id"] for s in d["shares"]}, {"wall", "eng"})
        titles = {s["title"] for s in d["shares"]}
        self.assertIn("英语学习资料", titles)

    def test_list_tsv(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        conn.request("GET", "/api/ext/shares?fmt=tsv", headers={"Authorization": "Bearer " + self.key})
        r = conn.getresponse()
        rows = [l.split("\t") for l in r.read().decode().splitlines()]
        self.assertEqual(r.status, 200)
        self.assertEqual({row[0] for row in rows}, {"wall", "eng"})
        self.assertTrue(all(len(row) == 6 for row in rows))
        self.assertIn("动态壁纸", [row[5] for row in rows])

    def test_upload_into_share(self):
        body = os.urandom(3 * 1024 * 1024 + 7)
        name = quote("视频 1.mp4")
        st, d = self.req("POST", "/api/ext/upload?share=wall&name=" + name, body, key=self.key)
        self.assertEqual(st, 200, d)
        self.assertEqual(d["title"], "动态壁纸")
        with app.db() as c:
            r = c.execute("SELECT * FROM files WHERE id=?", (d["file_id"],)).fetchone()
        self.assertEqual(r["share_id"], "wall")
        self.assertEqual(r["filename"], "视频 1.mp4")
        self.assertEqual(r["owner_id"], 2)  # 归分享的主人
        self.assertEqual(r["size"], len(body))
        with open(os.path.join(app.FILES_DIR, r["stored"]), "rb") as f:
            self.assertEqual(f.read(), body)
        self.assertFalse([f for f in os.listdir(app.FILES_DIR) if f.startswith("ext_")])

    def test_upload_rejects_bad_targets(self):
        for sid in ("recv", "old", "nope"):
            st, _ = self.req("POST", "/api/ext/upload?share=%s&name=a.mp4" % sid, b"abc", key=self.key)
            self.assertEqual(st, 404, sid)

    def test_filename_cleaned(self):
        st, d = self.req("POST", "/api/ext/upload?share=eng&name=" + quote("../../etc/x\r\n.mp3"),
                         b"abc", key=self.key)
        self.assertEqual(st, 200, d)
        self.assertEqual(d["name"], "x.mp3")

    def test_truncated_upload_leaves_no_file(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        conn.putrequest("POST", "/api/ext/upload?share=wall&name=t.mp4")
        conn.putheader("Authorization", "Bearer " + self.key)
        conn.putheader("Content-Length", "1000000")
        conn.endheaders()
        conn.send(b"x" * 1000)
        conn.close()
        time.sleep(0.5)
        self.assertFalse([f for f in os.listdir(app.FILES_DIR) if f.startswith("ext_")])


if __name__ == "__main__":
    unittest.main()
