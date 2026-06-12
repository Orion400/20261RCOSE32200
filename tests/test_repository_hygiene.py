from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = {
    'key.pem',
    'cert.pem',
    'recovered_key.pem',
    'weak_rsa_params.txt',
}


def test_generated_artifacts_are_not_tracked() -> None:
    tracked = subprocess.run(['git', 'ls-files'], cwd=ROOT, text=True, capture_output=True, check=True).stdout.splitlines()
    bad = [path for path in tracked if path in FORBIDDEN or path.endswith(('.pcap', '.pcapng')) or '__pycache__/' in path or path.startswith('.venv/')]
    assert bad == []
