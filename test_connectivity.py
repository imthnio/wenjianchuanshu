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
