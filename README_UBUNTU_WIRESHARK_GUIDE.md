# Ubuntu + Wireshark RSA/TLS 1.2 Local Demo Guide

This lab is for a local educational presentation only. It uses a deliberately weak RSA key whose primes are close, then demonstrates why recovering the RSA private key can matter for TLS 1.2 RSA key exchange.

Do not use this against external networks or other people's traffic.

## 1. Install packages

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv wireshark tshark openssl
sudo usermod -aG wireshark $USER
```

Log out and log in again if Wireshark permission changed.

## 2. Prepare the lab

```bash
mkdir -p ~/rsa-tls12-lab
cd ~/rsa-tls12-lab
# Copy these files into this directory.
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 00_check_environment.py
```

Expected: cipher string `AES128-SHA:@SECLEVEL=0` is accepted.

## 3. Create the deliberately weak RSA key and certificate

```bash
python3 01_make_weak_rsa_materials.py
ls -l key.pem cert.pem weak_rsa_params.txt
head -30 weak_rsa_params.txt
```

Presentation point:
- `n = p*q` is large, but `p` and `q` were intentionally chosen close.
- This is not safe RSA key generation. It is only for showing Fermat factorization.

## 4. Recover the private key from the public certificate

```bash
python3 02_recover_from_cert_fermat.py
ls -l recovered_key.pem
```

Optional local verification:

```bash
diff key.pem recovered_key.pem
```

No output means the recovered key is byte-identical to the generated test key.
In a real setting, you would not have `key.pem`; this comparison is only a local lab sanity check.

## 5. Start Wireshark capture before the client connects

1. Open Wireshark.
2. Capture interface: `lo` / `Loopback`.
3. Display filter:

```text
tcp.port == 8443
```

Start capture before running the client. Full TLS handshake is needed.

## 6. Run the server and client

Terminal 1:

```bash
cd ~/rsa-tls12-lab
source .venv/bin/activate
python3 server_tls12_rsa.py
```

Terminal 2:

```bash
cd ~/rsa-tls12-lab
source .venv/bin/activate
python3 client_tls12_rsa.py
```

In Wireshark, check the Server Hello. The cipher suite should be non-PFS RSA, typically:

```text
TLS_RSA_WITH_AES_128_CBC_SHA
```

If you see ECDHE or DHE, this demo's RSA private-key decryption logic does not apply.

## 7. Before decryption: show encrypted Application Data

In Wireshark, locate TLS Application Data packets. They should look like encrypted bytes, not the readable message.

Suggested presentation line:

> Capturing packets alone does not reveal the plaintext. Before applying the recovered key, the message appears as TLS Application Data.

## 8. Add the recovered RSA key to Wireshark

Wireshark menu path may differ by version:

```text
Edit → Preferences → Protocols → TLS → RSA keys list
```

Add:

```text
IP address: 127.0.0.1
Port: 8443
Protocol: data
Key File: /home/<YOUR_USER>/rsa-tls12-lab/recovered_key.pem
```

Then apply/reload the capture.

If the UI does not show `RSA keys list`, save the capture as `demo.pcapng` and try tshark:

```bash
tshark -r demo.pcapng \
  -o "tls.keys_list:127.0.0.1,8443,data,$HOME/rsa-tls12-lab/recovered_key.pem" \
  -V | grep -a -C 2 "Discrete math"
```

## 9. After decryption: show plaintext

Expected message:

```text
Discrete math makes RSA work.
```

Presentation point:

> The recovered private key was reconstructed from public certificate values by exploiting the close-prime condition. This is why bad RSA key generation can affect TLS 1.2 RSA key exchange confidentiality.

## 10. Conditions and limits

This demo only works under these conditions:

1. TLS 1.2 is used.
2. RSA key exchange is used, not ECDHE/DHE.
3. Full handshake is captured.
4. The recovered private key matches the server certificate.
5. RSA primes are close enough for Fermat factorization.
6. The traffic is a local educational test.

Do not generalize this to TLS 1.3 or ECDHE-based TLS 1.2. Those use forward secrecy, so a server long-term RSA key alone does not decrypt past sessions.
