#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from tls12_lab.common import DEFAULT_PORT, LOOPBACK_HOST, require_loopback_host

ROOT = Path(__file__).resolve().parent


@dataclass
class StepResult:
    name: str
    returncode: int


_children: list[subprocess.Popen[str]] = []
_interrupted = False


def _handle_signal(signum: int, _frame: object) -> None:
    global _interrupted
    _interrupted = True
    print(f'[DEMO] received signal {signum}; cleaning up')
    stop_children(_children)


def run_step(name: str, args: list[str], timeout: float, cwd: Path) -> StepResult:
    print(f'[DEMO] {name}: {" ".join(args)}')
    completed = subprocess.run(args, cwd=cwd, text=True, timeout=timeout)
    print(f'[DEMO] {name} exited with {completed.returncode}')
    if completed.returncode != 0:
        raise RuntimeError(f'{name} failed with exit status {completed.returncode}')
    return StepResult(name, completed.returncode)


def start_child(args: list[str], cwd: Path) -> subprocess.Popen[str]:
    child = subprocess.Popen(args, cwd=cwd, text=True, start_new_session=True)
    _children.append(child)
    return child


def wait_for_ready_file(ready_file: Path, child: subprocess.Popen[str], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError(f'server exited before readiness check: {child.returncode}')
        if ready_file.exists():
            return
        time.sleep(0.05)
    raise TimeoutError(f'timed out waiting for server readiness file {ready_file}')


def stop_children(children: list[subprocess.Popen[str]], timeout: float = 5.0) -> None:
    for child in list(children):
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + timeout
    for child in list(children):
        while child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.wait(timeout=timeout)


def run_demo(host: str, port: int, timeout: float) -> list[StepResult]:
    require_loopback_host(host)
    results: list[StepResult] = []
    py = sys.executable
    try:
        results.append(run_step('environment', [py, '00_check_environment.py'], timeout, ROOT))
        results.append(run_step('generate materials', [py, '01_make_weak_rsa_materials.py'], timeout, ROOT))
        results.append(run_step('recover key', [py, '02_recover_from_cert_fermat.py'], timeout, ROOT))
        print('[DEMO] starting server')
        ready_fd, ready_name = tempfile.mkstemp(
            prefix='rsa_tls12_ready_',
            dir=ROOT,
        )
        os.close(ready_fd)
        ready_path = Path(ready_name)
        ready_path.unlink(missing_ok=True)
        server = start_child([py, 'server_tls12_rsa.py', '--host', host, '--port', str(port), '--timeout', str(timeout), '--ready-file', str(ready_path)], ROOT)
        wait_for_ready_file(ready_path, server, timeout)
        ready_path.unlink(missing_ok=True)
        results.append(run_step('client', [py, 'client_tls12_rsa.py', '--host', host, '--port', str(port), '--timeout', str(timeout)], timeout, ROOT))
        server_code = server.wait(timeout=timeout)
        print(f'[DEMO] server exited with {server_code}')
        results.append(StepResult('server', server_code))
        if server_code != 0:
            raise RuntimeError(f'server failed with exit status {server_code}')
        return results
    finally:
        stop_children(_children)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run the complete local static-RSA TLS 1.2 lab flow.')
    parser.add_argument('--host', default=LOOPBACK_HOST, help='must remain 127.0.0.1')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='default: 8443')
    parser.add_argument('--timeout', type=float, default=30.0, help='per-step timeout in seconds')
    return parser.parse_args()


def main() -> int:
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    args = parse_args()
    try:
        results = run_demo(args.host, args.port, args.timeout)
    except Exception as exc:
        print(f'[DEMO] error: {exc}')
        return 130 if _interrupted else 1
    print('[DEMO] child exit status summary:')
    for result in results:
        print(f'  {result.name}: {result.returncode}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
