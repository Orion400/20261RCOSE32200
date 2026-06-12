from __future__ import annotations

from pathlib import Path

import pytest

from tls12_lab.common import artifact_path, ensure_output_dir, require_loopback_host


def test_loopback_validation_accepts_default() -> None:
    assert require_loopback_host('127.0.0.1') == '127.0.0.1'


def test_loopback_validation_rejects_remote() -> None:
    with pytest.raises(ValueError, match='127.0.0.1'):
        require_loopback_host('0.0.0.0')


def test_path_handling_creates_output_dir(tmp_path: Path) -> None:
    out = tmp_path / 'nested'
    assert ensure_output_dir(out) == out
    assert out.is_dir()
    assert artifact_path(out, 'key.pem') == out / 'key.pem'
