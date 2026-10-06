"""Media streaming for <video>/<audio> preview (iOS Safari is the strictest client):
validators + If-Range, fixed Content-Types, and stalled clients never get a 500 page
spliced into a half-sent 206 body."""
import http.client
import importlib.util
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('media_app', Path(__file__).with_name('fileshare.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

BIG = 24 * 1024 * 1024


class MediaStreamTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        app.DATA_DIR = self.tmp.name
        app.FILES_DIR = os.path.join(self.tmp.name, 'files')
        app.DB_PATH = os.path.join(self.tmp.name, 'share.db')
        app.init_db()
        now = int(time.time())
        self.ids = {}
        with app.db() as c:
            c.execute("INSERT INTO users(id,pw,is_admin,created) VALUES(1,'x',1,?)", (now,))
            c.execute("INSERT INTO shares(id,type,title,created,expires,owner_id) VALUES('share','send','t',?,0,1)", (now,))
            for name, size in (("big.mp4", BIG), ("a.MOV", 10), ("b.m4v", 10), ("c.webm", 10),
                               ("d.mkv", 10), ("e.flac", 10), ("f.opus", 10), ("g.avif", 10),
                               ("h.mp3", 10), ("i.m4a", 10)):
                stored = "st%d" % len(self.ids)
                with open(os.path.join(app.FILES_DIR, stored), "wb") as f:
                    f.write(b"\0" * size if size < 100 else os.urandom(size))
                cur = c.execute("INSERT INTO files(share_id,filename,stored,size,created,owner_id)"
                                " VALUES('share',?,?,?,?,1)", (name, stored, size, now))
                self.ids[name] = cur.lastrowid
        self.start(app.Server)

    def start(self, cls):
        self.server = cls(('127.0.0.1', 0), app.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop, self.server, self.thread)

    @staticmethod
    def stop(server, thread):
        server.shutdown()
        server.server_close()
        thread.join()

    def req(self, path, headers=None, method="GET"):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=10)
        conn.request(method, path, headers=headers or {})
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data

    def test_validators_if_range_and_304(self):
        path = "/s/share/v/%d" % self.ids["big.mp4"]
        s, h, _ = self.req(path, {"Range": "bytes=0-1"})
        self.assertEqual((s, h["content-range"], h["content-length"]), (206, "bytes 0-1/%d" % BIG, "2"))
        etag, lm = h["etag"], h["last-modified"]
        self.assertTrue(etag.startswith('"'))  # 强校验器，If-Range 只认强校验器
        self.assertEqual(h["accept-ranges"], "bytes")
        self.assertEqual(h["cache-control"], "private, no-cache")
        self.assertTrue(h["content-disposition"].startswith("inline"))
        # If-Range 匹配：照常 206；不匹配（文件变了）：200 整个文件
        s, _, data = self.req(path, {"Range": "bytes=0-1", "If-Range": etag})
        self.assertEqual((s, len(data)), (206, 2))
        s, _, data = self.req(path, {"Range": "bytes=0-1", "If-Range": lm})
        self.assertEqual((s, len(data)), (206, 2))
        s, h2, data = self.req(path, {"Range": "bytes=0-1", "If-Range": '"stale"'})
        self.assertEqual((s, len(data)), (200, BIG))
        self.assertNotIn("content-range", h2)
        s, _, data = self.req(path, {"Range": "bytes=0-1", "If-Range": "Mon, 01 Jan 2001 00:00:00 GMT"})
        self.assertEqual((s, len(data)), (200, BIG))
        # 条件 GET：没变回 304 不带正文
        s, h3, data = self.req(path, {"If-None-Match": etag})
        self.assertEqual((s, data, h3["etag"]), (304, b"", etag))
        s, _, data = self.req(path, {"If-None-Match": '"other"'}, "HEAD")
        self.assertEqual(s, 200)
        # 结尾探测（moov 在文件末尾的 mp4，iOS 会先取最后一段）
        s, h, data = self.req(path, {"Range": "bytes=-100"})
        self.assertEqual((s, h["content-range"], len(data)),
                         (206, "bytes %d-%d/%d" % (BIG - 100, BIG - 1, BIG), 100))

    def test_media_types_do_not_depend_on_system_mime_table(self):
        # 没有 /etc/mime.types 的系统 + 老 Python：mimetypes 认不出这些扩展名，
        # 之前会回 application/octet-stream 附件，<video> 一直转圈。
        want = {"a.MOV": "video/quicktime", "b.m4v": "video/mp4", "c.webm": "video/webm",
                "d.mkv": "video/x-matroska", "e.flac": "audio/flac", "f.opus": "audio/ogg",
                "g.avif": "image/avif", "h.mp3": "audio/mpeg", "i.m4a": "audio/mp4"}
        with patch.object(app.mimetypes, "guess_type", return_value=(None, None)):
            for name, ctype in want.items():
                s, h, _ = self.req("/s/share/v/%d" % self.ids[name], method="HEAD")
                self.assertEqual((s, h["content-type"]), (200, ctype), name)
                self.assertTrue(h["content-disposition"].startswith("inline"), name)

    def test_stalled_reader_never_gets_500_spliced_into_body(self):
        # iOS 暂停播放时会停着连接不读。之前发送超时后落到通用 except，
        # 在已经发了一半的 206 正文后面接着写 "HTTP/1.1 500" 和错误页。
        class Quick(app.Server):
            conn_timeout = 1
        self.start(Quick)
        port = self.server.server_port
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
        s.connect(('127.0.0.1', port))
        s.sendall(b"GET /s/share/v/%d HTTP/1.1\r\nHost: x\r\nRange: bytes=0-\r\n\r\n"
                  % self.ids["big.mp4"])
        got = s.recv(65536)
        self.assertIn(b"206 Partial Content", got)
        time.sleep(1.6)  # 超过服务端发送超时，但在它试图写错误页的过程中恢复读取
        s.settimeout(10)
        rest = b""
        while True:
            d = s.recv(1 << 20)
            if not d:
                break
            rest += d
        s.close()
        body = got + rest
        self.assertFalse(b"HTTP/1.1 500" in body, "500 response spliced into media body")
        self.assertFalse("出错了".encode() in body, "error page spliced into media body")
        self.assertLess(len(got) + len(rest), BIG)  # 连接被断开，而不是假装发完


if __name__ == '__main__':
    unittest.main()
