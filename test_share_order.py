"""Share ordering: migration, real HTTP permissions and persistent ordering."""
import http.client
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from urllib.parse import urlencode

spec = importlib.util.spec_from_file_location('order_app', Path(__file__).with_name('fileshare.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class ShareOrderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        app.DATA_DIR = self.tmp.name
        app.FILES_DIR = os.path.join(self.tmp.name, 'files')
        app.DB_PATH = os.path.join(self.tmp.name, 'share.db')
        # Exercise the migration from the schema before ordering existed.
        with sqlite3.connect(app.DB_PATH) as c:
            c.execute('CREATE TABLE files(id INTEGER PRIMARY KEY AUTOINCREMENT, '
                      'share_id TEXT, filename TEXT, stored TEXT, size INTEGER, '
                      'created INTEGER, owner_id INTEGER)')
            for fid in range(1, 5):
                c.execute('INSERT INTO files VALUES(?,?,?,?,?,?,?)',
                          (fid, 'share', 'file%d.txt' % fid, 'stored%d' % fid, 0, 0, 1))
        app.init_db()
        now = int(time.time())
        with app.db() as c:
            for uid in range(1, 4):
                c.execute('INSERT INTO users(id,pw,is_admin,created) VALUES(?,?,?,?)',
                          (uid, 'unused', int(uid == 3), now))
                c.execute('INSERT INTO sessions VALUES(?,?,?,?)',
                          ('tok%d' % uid, uid, now, now + 3600))
            for sid, typ, expiry in [('share', 'send', 0), ('other', 'send', 0),
                                     ('expired', 'send', now - 1), ('recv', 'recv', 0)]:
                c.execute('INSERT INTO shares(id,type,title,created,expires,owner_id) VALUES(?,?,?,?,?,?)',
                          (sid, typ, '', now, expiry, 1))
        self.server = app.Server(('127.0.0.1', 0), app.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, path, uid=None, form=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        headers = {'Cookie': 'sid=tok%d' % uid} if uid else {}
        if form is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        conn.request('POST' if form is not None else 'GET', path,
                     urlencode(form) if form is not None else None, headers)
        res = conn.getresponse()
        result = res.status, res.read().decode()
        conn.close()
        return result

    def change(self, fid, action, uid=1, sid='share', expected=200):
        status, body = self.request('/api/share_file_order', uid,
                                    {'sid': sid, 'id': fid, 'action': action})
        self.assertEqual(status, expected, body)
        self.assertEqual(json.loads(body)['ok'], expected == 200)

    def ids(self):
        return [r['id'] for r in app.share_files('share')]

    def test_migration_moves_pins_and_new_files(self):
        self.assertEqual(self.ids(), [4, 3, 2, 1])  # newest upload first
        self.change(3, 'up')
        self.assertEqual(self.ids(), [3, 4, 2, 1])
        self.change(4, 'pin')
        self.change(2, 'pin')
        self.assertEqual(self.ids(), [4, 2, 3, 1])
        self.change(2, 'up')
        self.change(2, 'pin')  # explicit state is idempotent
        self.assertEqual(self.ids(), [2, 4, 3, 1])
        self.change(4, 'down')  # cannot cross the pinned boundary
        self.change(3, 'up')
        self.assertEqual(self.ids(), [2, 4, 3, 1])
        self.change(2, 'unpin')
        self.assertEqual(self.ids(), [4, 3, 1, 2])
        with app.db() as c:
            c.execute('INSERT INTO files(share_id,filename,stored) VALUES(?,?,?)',
                      ('share', 'new.txt', 'new'))
        # a new upload goes to the top, right after the pinned files
        self.assertEqual(self.ids(), [4, 5, 3, 1, 2])
        app.init_db()  # repeated startup preserves the saved state
        self.assertEqual(self.ids(), [4, 5, 3, 1, 2])
        for fid in self.ids():
            self.change(fid, 'pin')
        self.assertTrue(all(r['pinned'] for r in app.share_files('share')))
        self.change(3, 'down')
        self.assertEqual(self.ids(), [4, 5, 1, 3, 2])

    def test_permissions_invalid_input_and_public_page(self):
        for uid, sid, fid, action, expected in [
                (None, 'share', 1, 'pin', 401), (2, 'share', 1, 'pin', 403),
                (1, 'other', 1, 'pin', 404), (1, 'missing', 1, 'pin', 404),
                (1, 'expired', 1, 'pin', 404), (1, 'recv', 1, 'pin', 404),
                (1, 'share', 999, 'pin', 404), (1, 'share', '²', 'pin', 400),
                (1, 'share', '9'*30, 'pin', 400), (1, 'share', 1, 'bad', 400)]:
            self.change(fid, action, uid, sid, expected)
        self.assertEqual(self.ids(), [4, 3, 2, 1])
        self.change(4, 'pin', uid=3)  # existing administrator privileges
        for uid in (None, 1, 2, 3):
            status, page = self.request('/s/share', uid)
            self.assertEqual(status, 200)
            self.assertLess(page.index("id='file-4'"), page.index("id='file-1'"))
            self.assertIn('📌 置顶', page)
            self.assertEqual('function arrangeFile' in page, uid in (1, 3))

    def test_many_pins_and_concurrent_updates(self):
        with app.db() as c:
            c.executemany('INSERT INTO files(share_id,filename,stored,size,pinned) '
                          'VALUES(?,?,?,?,?)',
                          [('share', 'extra%d.txt' % i, 'extra%d' % i, 0, 1)
                           for i in range(205)])
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda fid: self.change(fid, 'pin'), range(1, 5)))
        rows = app.share_files('share')
        self.assertEqual(len(rows), 209)
        self.assertTrue(all(row['pinned'] for row in rows))
        self.assertEqual(len({row['sort_order'] for row in rows}), 209)


if __name__ == '__main__':
    unittest.main()
