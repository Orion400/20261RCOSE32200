#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import shutil
import socket
import ssl
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from tls12_lab.common import DEFAULT_PORT, LOOPBACK_HOST, STATIC_RSA_CIPHER_NAME, STATIC_RSA_CIPHERS, is_port_free, make_tls12_context


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str
    required: bool = True


def check_python() -> Check:
    version = sys.version_info
    ok = version >= (3, 10)
    return Check("Python", ok, f"{version.major}.{version.minor}.{version.micro}")


def check_openssl() -> Check:
    return Check("OpenSSL", bool(ssl.OPENSSL_VERSION), ssl.OPENSSL_VERSION)


def check_tls12() -> Check:
    try:
        ctx = make_tls12_context(ssl.PROTOCOL_TLS_CLIENT)
    except (ssl.SSLError, ValueError) as exc:
        return Check("TLS 1.2", False, str(exc))
    ok = ctx.minimum_version == ssl.TLSVersion.TLSv1_2 and ctx.maximum_version == ssl.TLSVersion.TLSv1_2
    return Check("TLS 1.2", ok, "context restricted to TLSv1.2")


def check_cipher_string() -> Check:
    try:
        make_tls12_context(ssl.PROTOCOL_TLS_CLIENT, STATIC_RSA_CIPHERS)
    except ssl.SSLError as exc:
        return Check("Cipher string", False, str(exc))
    return Check("Cipher string", True, f"accepted {STATIC_RSA_CIPHERS}")


def check_cipher_present() -> Check:
    try:
        ctx = make_tls12_context(ssl.PROTOCOL_TLS_CLIENT, STATIC_RSA_CIPHERS)
    except ssl.SSLError as exc:
        return Check("AES128-SHA", False, str(exc))
    names = [c.get("name") for c in ctx.get_ciphers()]
    return Check("AES128-SHA", STATIC_RSA_CIPHER_NAME in names, ", ".join(names[:8]))


def check_capture_tool() -> Check:
    found = [name for name in ("tshark", "dumpcap") if shutil.which(name)]
    if found:
        return Check("Capture tool", True, ", ".join(found), required=False)
    return Check("Capture tool", False, "tshark/dumpcap not found; Wireshark steps remain manual", required=False)


def check_port() -> Check:
    ok = is_port_free(LOOPBACK_HOST, DEFAULT_PORT)
    detail = f"{LOOPBACK_HOST}:{DEFAULT_PORT} is {'free' if ok else 'in use'}"
    return Check("Port 8443", ok, detail)


def check_writable_cwd() -> Check:
    cwd = Path.cwd()
    try:
        with tempfile.NamedTemporaryFile(prefix=".rsa_tls12_check_", dir=cwd, delete=True):
            pass
    except OSError as exc:
        return Check("Writable cwd", False, str(exc))
    return Check("Writable cwd", True, str(cwd))


def check_module(name: str) -> Check:
    ok = importlib.util.find_spec(name) is not None
    return Check(f"Python module {name}", ok, "available" if ok else "not importable")


def run_checks() -> list[Check]:
    return [
        check_python(),
        check_openssl(),
        check_tls12(),
        check_cipher_string(),
        check_cipher_present(),
        check_module("cryptography"),
        check_port(),
        check_writable_cwd(),
        check_capture_tool(),
    ]


def main() -> int:
    checks = run_checks()
    for check in checks:
        status = "OK" if check.ok else ("WARN" if not check.required else "FAIL")
        required = "required" if check.required else "optional"
        print(f"[{status}] {check.name} ({required}): {check.detail}")
    print("[Need] TLS_RSA_WITH_AES_128_CBC_SHA / AES128-SHA should be available for this demo.")
    return 0 if all(check.ok or not check.required for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
