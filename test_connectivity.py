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
import threading
import unittest
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
