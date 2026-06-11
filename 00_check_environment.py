#!/usr/bin/env python3
import ssl
print('[OpenSSL]', ssl.OPENSSL_VERSION)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
try:
    ctx.set_ciphers('AES128-SHA:@SECLEVEL=0')
    print('[OK] Cipher string accepted: AES128-SHA:@SECLEVEL=0')
except ssl.SSLError as e:
    print('[FAIL] Cipher string not accepted:', e)
    raise
names = [c['name'] for c in ctx.get_ciphers()]
print('[Ciphers]', ', '.join(names[:20]))
print('[Need] TLS_RSA_WITH_AES_128_CBC_SHA / AES128-SHA should be available for this demo.')
