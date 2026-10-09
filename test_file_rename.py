"""File rename: extension is fixed, permissions match the share page / all-files page."""
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

spec = importlib.util.spec_from_file_location('rename_app', Path(__file__).with_name('fileshare.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class FileRenameTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        app.DATA_DIR = self.tmp.name
        app.FILES_DIR = os.path.join(self.tmp.name, 'files')
        app.DB_PATH = os.path.join(self.tmp.name, 'share.db')
        app.init_db()
        now = int(time.time())
        with app.db() as c:
            # 1、2 是普通用户，3 是管理员
            for uid in range(1, 4):
                c.execute('INSERT INTO users(id,pw,is_admin,created) VALUES(?,?,?,?)',
                          (uid, 'unused', int(uid == 3), now))
                c.execute('INSERT INTO sessions VALUES(?,?,?,?)',
                          ('tok%d' % uid, uid, now, now + 3600))
            for sid, typ, expiry, owner in [('share', 'send', 0, 1), ('other', 'send', 0, 2),
                                            ('expired', 'send', now - 1, 1),
                                            ('recv', 'receive', 0, 1)]:
                c.execute('INSERT INTO shares(id,type,title,created,expires,owner_id)'
                          ' VALUES(?,?,?,?,?,?)', (sid, typ, '', now, expiry, owner))
            for fid, sid, name, owner in [(1, 'share', '俄罗斯鼠疫.mov', 1),
                                          (2, 'share', 'README', 1),
                                          (3, 'other', 'b.tar.gz', 2),
                                          (4, 'expired', 'old.txt', 1),
                                          (5, 'recv', 'got.pdf', 1),
                                          (6, 'gone', 'orphan.zip', None)]:
                c.execute('INSERT INTO files(id,share_id,filename,stored,size,created,owner_id)'
                          ' VALUES(?,?,?,?,?,?,?)', (fid, sid, name, 's%d' % fid, 0, now, owner))
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

    def rename(self, fid, name, uid=1, sid=None, expected=200):
        form = {'id': fid, 'name': name}
        if sid is not None:
            form['sid'] = sid
        status, body = self.request('/api/file_rename', uid, form)
        self.assertEqual(status, expected, body)
        j = json.loads(body)
        self.assertEqual(j['ok'], expected == 200)
        return j

    def name(self, fid):
        with app.db() as c:
            return c.execute('SELECT filename FROM files WHERE id=?', (fid,)).fetchone()[0]

    def test_extension_is_kept(self):
        self.assertEqual(self.rename(1, '  新名字  ')['filename'], '新名字.mov')
        self.assertEqual(self.name(1), '新名字.mov')
        # 输入里带别的后缀也只会成为主文件名的一部分，格式仍是 .mov
        self.rename(1, 'x.mp4')
        self.assertEqual(self.name(1), 'x.mp4.mov')
        # 多重扩展名只固定最后一段
        self.rename(3, 'c.tar', uid=2)
        self.assertEqual(self.name(3), 'c.tar.gz')
        # 原来没有扩展名：不能靠改名加出一个格式
        self.rename(2, 'evil.exe', expected=400)
        self.rename(2, 'LICENSE')
        self.assertEqual(self.name(2), 'LICENSE')
        # 双向文本控制符、控制字符被去掉，防止伪装扩展名
        self.rename(1, 'a‮gpj\r\n')
        self.assertEqual(self.name(1), 'agpj.mov')
        for bad in ('', '   ', 'a/b', 'a\\b', '‮', 'x' * 200):
            self.rename(1, bad, expected=400)
        self.assertEqual(self.name(1), 'agpj.mov')

    def test_all_files_permissions(self):
        for uid, fid, expected in [(None, 1, 401), (2, 1, 403), (1, 3, 403),
                                   (1, 4, 404), (1, 999, 404), (1, '²', 400),
                                   (1, '9' * 30, 400), (1, 6, 403)]:
            self.rename(fid, 'n', uid=uid, expected=expected)
        self.rename(5, '收到的', uid=1)             # 自己接收链接里的文件
        self.rename(3, 'admin', uid=3)              # 管理员改别人的
        self.rename(6, 'orphan2', uid=3)            # 管理员改链接已删的
        self.assertEqual([self.name(i) for i in (5, 3, 6)],
                         ['收到的.pdf', 'admin.gz', 'orphan2.zip'])

    def test_share_page_permissions(self):
        for uid, fid, sid, expected in [(2, 1, 'share', 403), (1, 3, 'share', 404),
                                        (1, 1, 'other', 404), (1, 4, 'expired', 404),
                                        (1, 5, 'recv', 404), (1, 1, 'bad id!', 400)]:
            self.rename(fid, 'n', uid=uid, sid=sid, expected=expected)
        self.rename(1, '分享页改名', uid=1, sid='share')
        self.rename(1, '管理员改名', uid=3, sid='share')
        self.assertEqual(self.name(1), '管理员改名.mov')

    def test_pages_show_rename_button(self):
        status, page = self.request('/s/share', 1)
        self.assertEqual(status, 200)
        self.assertIn('function renameFile', page)
        self.assertIn("data-ext='.mov'", page)
        self.assertIn("data-sid='share'", page)
        self.assertIn("id='rn-1'", page)
        status, page = self.request('/s/share', 2)  # 访客看不到改名
        self.assertNotIn('renameFile', page)
        for uid in (1, 3):
            status, page = self.request('/dash', uid)
            self.assertEqual(status, 200)
            self.assertIn('function renameFile', page)
            self.assertIn("data-stem='俄罗斯鼠疫' data-ext='.mov'", page)
            self.assertNotIn("data-sid=", page)


if __name__ == '__main__':
    unittest.main()
