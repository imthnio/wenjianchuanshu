"""Regression checks for editing expiry and reusing uploaded files."""
import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from urllib.parse import urlencode

_data = tempfile.TemporaryDirectory()
os.environ["SHARE_DATA"] = _data.name
import fileshare as app


class ShareExistingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.init_db()
        now = int(time.time())
        with app.db() as c:
            for uid, admin in ((1, 0), (2, 0), (3, 1)):
                c.execute("INSERT INTO users(id,pw,is_admin,created) VALUES(?,?,?,?)",
                          (uid, "unused", admin, now))
                c.execute("INSERT INTO sessions(token,user_id,created,expires)"
                          " VALUES(?,?,?,?)", ("tok" + str(uid), uid, now, now + 3600))
            for sid, owner, typ, expiry in (
                    ("target", 1, "send", now + 3600),
                    ("admintarget", 2, "send", now + 3600),
                    ("original", 1, "send", now + 3600),
                    ("other", 2, "send", now + 3600),
                    ("expired", 1, "send", now - 10)):
                c.execute("INSERT INTO shares(id,type,title,created,expires,owner_id)"
                          " VALUES(?,?,?,?,?,?)", (sid, typ, "", now, expiry, owner))
            for fid, sid, owner in ((1, "original", 1), (2, "other", 2),
                                    (3, "expired", 1)):
                name = "stored" + str(fid)
                with open(os.path.join(app.FILES_DIR, name), "wb") as out:
                    out.write(b"file " + str(fid).encode())
                c.execute("INSERT INTO files(id,share_id,filename,stored,size,created,owner_id)"
                          " VALUES(?,?,?,?,?,?,?)",
                          (fid, sid, "item" + str(fid) + ".txt", name, 6, now, owner))
        cls.server = app.Server(("127.0.0.1", 0), app.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        _data.cleanup()

    def request(self, method, path, uid=None, form=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port)
        headers = {"Cookie": "sid=tok" + str(uid)} if uid else {}
        body = urlencode(form) if form is not None else None
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body, headers)
        response = conn.getresponse()
        result = response.status, response.read()
        conn.close()
        return result

    def test_expiry_api_and_page(self):
        status, page = self.request("GET", "/dash", 1)
        self.assertEqual(status, 200)
        self.assertIn(b"ok.onclick=function(){saveExpiry(id);}", page)
        status, body = self.request("POST", "/api/expiry", 1,
                                    {"id": "target", "expiry": "30"})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])
        with app.db() as c:
            expires = c.execute("SELECT expires FROM shares WHERE id='target'").fetchone()[0]
        self.assertGreater(expires, time.time() + 29 * 86400)

    def test_add_existing_permissions_and_independent_deletion(self):
        status, page = self.request("GET", "/s/target", 1)
        self.assertEqual(status, 200)
        self.assertIn(b"/api/share_file_existing", page)
        self.assertIn(b"item1.txt", page)
        self.assertNotIn(b"item2.txt", page)

        for uid, ids, expected in ((None, "1", 401), (2, "1", 403),
                                   (1, "2", 400), (1, "3", 400),
                                   (1, "1,2", 400)):
            status, _ = self.request("POST", "/api/share_file_existing", uid,
                                     {"sid": "target", "ids": ids})
            self.assertEqual(status, expected)
        with app.db() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM files WHERE share_id='target'")
                             .fetchone()[0], 0)

        status, body = self.request("POST", "/api/share_file_existing", 1,
                                    {"sid": "target", "ids": "1"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["count"], 1)
        with app.db() as c:
            copied = c.execute("SELECT * FROM files WHERE share_id='target'").fetchone()
        self.assertNotEqual(copied["stored"], "stored1")
        self.assertEqual(os.stat(os.path.join(app.FILES_DIR, "stored1")).st_ino,
                         os.stat(os.path.join(app.FILES_DIR, copied["stored"])).st_ino)
        app.delete_files([1])
        status, body = self.request("GET", "/s/target/f/" + str(copied["id"]))
        self.assertEqual((status, body), (200, b"file 1"))

    def test_admin_can_use_all_files(self):
        status, body = self.request("POST", "/api/share_file_existing", 3,
                                    {"sid": "admintarget", "ids": "2"})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])


if __name__ == "__main__":
    unittest.main()
