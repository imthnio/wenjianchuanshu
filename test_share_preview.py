"""Share page preview UI: prominent 查看 button, safe escaping and lazy media."""
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import os
import unittest

spec = importlib.util.spec_from_file_location('preview_app', Path(__file__).with_name('fileshare.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class SharePreviewPageTest(unittest.TestCase):
    FILES = [{"id": 1, "filename": "照片.JPG", "size": 10, "created": 1700000000},
             {"id": 2, "filename": "clip.mp4", "size": 20},
             {"id": 3, "filename": "song.mp3", "size": 30},
             {"id": 4, "filename": "doc.pdf", "size": 40},
             {"id": 5, "filename": "notes.md", "size": 50},
             {"id": 6, "filename": "archive.zip", "size": 60},
             {"id": 7, "filename": "\"><img src=x onerror=alert(1)>.png", "size": 1}]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        app.DATA_DIR = self.tmp.name
        app.FILES_DIR = os.path.join(self.tmp.name, 'files')
        app.DB_PATH = os.path.join(self.tmp.name, 'share.db')
        app.init_db()

    def render(self, user=None):
        return app.share_page("abC123-_", {"title": "t", "expires": 0, "owner_id": 1},
                              self.FILES, user).decode("utf-8")

    def test_view_button_is_primary_for_previewable_files(self):
        body = self.render()
        kinds = re.findall(r"class='btn-view' data-kind='(\w+)' data-src='/s/abC123-_/v/(\d+)'", body)
        self.assertEqual(kinds, [("img", "1"), ("vid", "2"), ("aud", "3"), ("pdf", "4"),
                                 ("txt", "5"), ("img", "7")])
        # 能预览的文件：下载是次要按钮；不能预览的文件：下载就是主按钮
        self.assertIn("<a class='btn ghost' href='/s/abC123-_/f/1'", body)
        self.assertIn("<a class='btn' href='/s/abC123-_/f/6'", body)
        self.assertNotIn("/s/abC123-_/v/6", body)
        # 预览弹层和脚本都在；媒体元素只在点击后由脚本创建
        self.assertIn("id='pv'", body)
        self.assertIn("history.pushState", body)
        self.assertIn("'Escape'", body)
        for tag in ("<img", "<video", "<audio", "<iframe", "<embed"):
            self.assertNotIn(tag, body)

    def test_filenames_escaped_everywhere(self):
        body = self.render({"id": 1, "is_admin": True})
        self.assertNotIn("<img src=x", body)
        self.assertNotIn("\"><img", body)
        self.assertIn("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;.png", body)

    def test_empty_share_has_no_preview_script(self):
        body = app.share_page("abC123-_", {"title": "t", "expires": 0}, []).decode("utf-8")
        self.assertIn("文件都被删除啦", body)
        self.assertNotIn("id='pv'", body)

    def test_video_preview_has_loading_and_fallback_states(self):
        js = app.PREVIEW_JS
        # 加载中提示、超时/卡住提示（重试/新窗口/下载）、出错兜底、不支持格式的检测
        for needle in ("pv-vload", "pv-vnote", "pv-retry", "canPlayType", "retryVideo",
                       "'waiting'", "playsinline", "继续等待"):
            self.assertIn(needle, js)
        # 切换文件时旧的看门狗定时器要停掉，旧视频要停止并释放连接
        self.assertIn("clearInterval(watch)", js)
        self.assertIn("removeAttribute('src')", js)

    def test_audio_preview_has_error_and_timeout_fallback(self):
        js = app.PREVIEW_JS
        aud = js[js.index("kind==='aud'"):js.index("kind==='pdf'")]
        self.assertIn("retryVideo(0)", aud)
        self.assertIn("pv-amsg", aud)
        self.assertIn("setInterval", aud)

    def test_chunk_upload_retries_with_backoff(self):
        js = app.CHUNK_JS
        self.assertIn("setTimeout(send", js)
        # node 可用时实际跑一遍：前两次网络错误，第三次成功，整个上传应成功
        if not shutil.which("node"):
            return
        harness = js + r"""
var calls=0, waits=[];
global.setTimeout=function(fn,ms){waits.push(ms); fn();};
global.fetch=function(url){
  if(url.indexOf('/api/chunk_init')===0) return Promise.resolve({status:200,json:function(){return Promise.resolve({ok:true,up:'u'});}});
  if(url.indexOf('/api/chunk_done')===0) return Promise.resolve({status:200,json:function(){return Promise.resolve({ok:true});}});
  calls++; if(calls<3) return Promise.reject(new Error('net'));
  return Promise.resolve({status:200,json:function(){return Promise.resolve({ok:true});}});
};
var f={name:'a',size:10,slice:function(){return {size:10};}};
chunkUpload({sid:'s',kind:'upload'},[f],{prog:{},pct:null,stat:null}).then(function(){
  if(calls!==3||waits.length!==2||!(waits[1]>waits[0])) {console.log('bad',calls,waits); process.exit(1);}
  console.log('ok');
},function(e){console.log('rejected',e.message); process.exit(1);});
"""
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(harness)
        try:
            r = subprocess.run(["node", f.name], capture_output=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stdout.decode() + r.stderr.decode())
        finally:
            os.unlink(f.name)

    def test_backdrop_tap_does_not_close_preview(self):
        js = app.PREVIEW_JS
        # 之前点舞台空白处（视频上下的黑边）就关闭，手机上很容易误触
        self.assertNotIn("ev.target===stage", js)
        self.assertNotRegex(js, r"stage\.addEventListener\('click'")
        # 仍然可以用 ✕、Esc 和返回键关闭
        self.assertIn("closeB.addEventListener('click', close)", js)
        self.assertIn("ev.key==='Escape'", js)
        self.assertIn("popstate", js)
        # 滑动切换不拦截视频/音频本身的手势（拖进度条），也不 preventDefault
        self.assertIn("closest('video,audio,iframe,pre,a,button,input')", js)
        self.assertNotIn("preventDefault", js.split("touchstart")[1])

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_page_scripts_are_valid_javascript(self):
        for name, js in (("preview", app.PREVIEW_JS), ("ui", app.UI_JS), ("dash", app.DASH_JS)):
            with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
                f.write(js)
            try:
                r = subprocess.run(["node", "--check", f.name], capture_output=True, timeout=30)
                self.assertEqual(r.returncode, 0, (name, r.stderr.decode()))
            finally:
                os.unlink(f.name)


if __name__ == '__main__':
    unittest.main()
