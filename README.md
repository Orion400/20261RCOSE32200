# Local TLS 1.2 Static-RSA Laboratory

This repository contains a local educational laboratory for examining the relationship between RSA, Fermat factorization, and the TLS 1.2 static-RSA handshake.

The demonstration intentionally generates a 2048-bit RSA modulus from two close primes, recovers the private key using Fermat factorization, and uses the reconstructed key to inspect a loopback-only TLS 1.2 session.

## Default workflow

Install the dependency:

```bash
python3 -m pip install -r requirements.txt

Check the environment:

python3 00_check_environment.py

Generate the intentionally weak RSA materials:

python3 01_make_weak_rsa_materials.py

Recover the private key from the certificate:

python3 02_recover_from_cert_fermat.py

Start the local TLS 1.2 server:

python3 server_tls12_rsa.py

Run the client in another terminal:

python3 client_tls12_rsa.py

The default server is restricted to 127.0.0.1:8443. The demonstration uses TLS 1.2 with the static-RSA cipher configuration AES128-SHA:@SECLEVEL=0.

Automated local run
python3 03_run_local_demo.py --timeout 30
Tests
python3 -m pytest
Detailed guide

See README_UBUNTU_WIRESHARK_GUIDE.md for the complete Ubuntu and Wireshark procedure, troubleshooting information, packet-capture instructions, and the ECDHE_RSA comparison case.

Scope

All networking and packet capture are restricted to the local machine. Generated keys, certificates, recovered materials, packet captures, caches, and virtual environments are excluded from Git tracking.
