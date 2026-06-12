from __future__ import annotations

import os
import signal
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tls12_lab.common import DEFAULT_PORT, LOOPBACK_HOST, is_port_free, make_tls12_context

ROOT = Path(__file__).resolve().parents[1]


def legacy_cipher_available() -> bool:
    try:
        ctx = make_tls12_context(ssl.PROTOCOL_TLS_CLIENT)
        return any(c.get('name') == 'AES128-SHA' for c in ctx.get_ciphers())
    except ssl.SSLError:
        return False


def wait_for_port(port: int, proc: subprocess.Popen[str], timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f'process exited early: {proc.returncode}')
        try:
            with socket.create_connection((LOOPBACK_HOST, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f'timed out waiting for port {port}')


def terminate(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)


@pytest.mark.skipif(not legacy_cipher_available(), reason='OpenSSL legacy AES128-SHA cipher is unavailable')
def test_static_rsa_server_client_exchange(tmp_path: Path) -> None:
    subprocess.run([sys.executable, str(ROOT / '01_make_weak_rsa_materials.py'), '--bits', '512', '--output-dir', str(tmp_path)], check=True)
    server = subprocess.Popen(
        [sys.executable, str(ROOT / 'server_tls12_rsa.py'), '--cert', str(tmp_path / 'cert.pem'), '--key', str(tmp_path / 'key.pem'), '--timeout', '5'],
        cwd=tmp_path,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        wait_for_port(DEFAULT_PORT, server)
        client = subprocess.run(
            [sys.executable, str(ROOT / 'client_tls12_rsa.py'), '--cafile', str(tmp_path / 'cert.pem'), '--timeout', '5'],
            cwd=tmp_path,
            text=True,
            capture_output=True,
            check=True,
        )
        assert 'TLSv1.2' in client.stdout
        assert 'AES128-SHA' in client.stdout
        assert 'Discrete math makes RSA work.' in client.stdout
        server_out, _ = server.communicate(timeout=10)
        assert server.returncode == 0
        assert 'negotiated:' in server_out
        assert 'AES128-SHA' in server_out
    finally:
        terminate(server)
    assert is_port_free(LOOPBACK_HOST, DEFAULT_PORT)


@pytest.mark.skipif(not legacy_cipher_available(), reason='OpenSSL legacy AES128-SHA cipher is unavailable')
def test_demo_runner_child_cleanup() -> None:
    result = subprocess.run([sys.executable, str(ROOT / '03_run_local_demo.py'), '--timeout', '20'], cwd=ROOT, text=True, capture_output=True, check=True)
    assert 'child exit status summary' in result.stdout
    assert 'client: 0' in result.stdout
    assert 'server: 0' in result.stdout
    assert is_port_free(LOOPBACK_HOST, DEFAULT_PORT)
