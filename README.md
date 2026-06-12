# Local TLS 1.2 Static-RSA Laboratory

A local educational laboratory demonstrating the relationship between RSA, Fermat factorization, and the TLS 1.2 static-RSA key exchange.

The laboratory intentionally generates a 2048-bit RSA modulus from two closely spaced primes, reconstructs the private key using Fermat factorization, and uses the recovered key in a loopback-only TLS 1.2 demonstration.

## Requirements

* Python 3.10 or later
* OpenSSL with TLS 1.2 and `AES128-SHA` support
* Python packages listed in `requirements.txt`
* Wireshark, `tshark`, or `dumpcap` for optional packet capture and analysis

Install the Python dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Manual Workflow

### 1. Check the environment

```bash
python3 00_check_environment.py
```

The script checks the Python and OpenSSL versions, TLS 1.2 support, the required cipher configuration, port availability, required Python modules, and optional packet-capture tools.

### 2. Generate the intentionally weak RSA materials

```bash
python3 01_make_weak_rsa_materials.py
```

This creates:

* `key.pem`
* `cert.pem`
* `weak_rsa_params.txt`

The generated 2048-bit RSA modulus uses two intentionally close primes so that Fermat factorization can recover them efficiently.

### 3. Recover the RSA private key

```bash
python3 02_recover_from_cert_fermat.py
```

The script reads the public modulus and exponent from `cert.pem`, factors the modulus using exact integer arithmetic, reconstructs the private key, and writes:

```text
recovered_key.pem
```

### 4. Start the TLS 1.2 server

```bash
python3 server_tls12_rsa.py
```

The server listens only on:

```text
127.0.0.1:8443
```

It is restricted to TLS 1.2 and uses the following OpenSSL cipher configuration:

```text
AES128-SHA:@SECLEVEL=0
```

### 5. Run the client

Open another terminal and run:

```bash
python3 client_tls12_rsa.py
```

The client connects only to the local server and sends the following message:

```text
Discrete math makes RSA work.
```

## Automated Local Run

The complete generation, recovery, server, and client workflow can be executed automatically:

```bash
python3 03_run_local_demo.py --timeout 30
```

The runner supervises child processes, waits for server readiness, enforces timeouts, and cleans up the server process before exiting.

## Packet Capture and Analysis

Optional loopback capture and TLS analysis are provided through:

```bash
python3 04_capture_loopback.py --help
```

The capture functionality is restricted to the local loopback interface and TCP port `8443`. It requires `tshark` or `dumpcap` and does not invoke `sudo` automatically.

## ECDHE_RSA Control Case

The additional ECDHE_RSA server and client provide a local comparison with the static-RSA demonstration:

```bash
python3 server_tls12_ecdhe.py
```

In another terminal:

```bash
python3 client_tls12_ecdhe.py
```

This control case demonstrates that ECDHE_RSA uses RSA for authentication while the session secret is established through ephemeral ECDH. It does not change the original static-RSA workflow.

## Tests

Run the complete test suite with:

```bash
python3 -m pytest
```

The tests cover:

* exact square-root calculations
* Fermat factorization
* RSA key reconstruction
* loopback address validation
* TLS 1.2 negotiation
* client-server message exchange
* process cleanup
* port release
* generated-artifact tracking rules

## Detailed Guide

See [README_UBUNTU_WIRESHARK_GUIDE.md](README_UBUNTU_WIRESHARK_GUIDE.md) for the complete Ubuntu setup, Wireshark procedure, troubleshooting instructions, packet-capture analysis, and cleanup steps.

## Scope and Safety

All networking and packet capture are restricted to the local machine.

The generated keys are intentionally weak and are provided only for educational demonstration. They must not be used for real services or sensitive data.

Generated keys, certificates, recovered key material, packet captures, caches, and virtual environments are excluded from Git tracking.
