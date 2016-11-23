#! /usr/bin/env python

"""
Generate test vectors for decryption tests

Needs the cryptography module installed to use:

    pip install cryptography
"""

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

import hashlib
import json
import sys
import base64
import struct

b64 = lambda x: base64.b64encode(x).rstrip("=")
b64u = lambda x: base64.urlsafe_b64encode(x).rstrip("=")


def encrypt_ctr(key, iv, plaintext, counter_bits):
    counter1, counter0 = struct.unpack(">QQ", iv)
    counter = counter0 | (counter1 << 64)
    limit = 1 << counter_bits
    low = counter & (limit - 1)
    high = counter - low
    result = ""
    while (len(plaintext) + 15) / 16 + low > limit:
        iv = struct.pack(">QQ", counter >> 64, counter & ((1 << 64) - 1))
        encryptor = Cipher(
            algorithms.AES(key),
            modes.CTR(iv),
            backend=default_backend()
        ).encryptor()
        size = 16 * (limit - low)
        result += encryptor.update(plaintext[:size]) + encryptor.finalize()
        plaintext = plaintext[size:]
        low = 0
        counter = high

    iv = struct.pack(">QQ", counter >> 64, counter & ((1<<64) - 1))
    encryptor = Cipher(
        algorithms.AES(key),
        modes.CTR(iv),
        backend=default_backend()
    ).encryptor()
    result += encryptor.update(plaintext) + encryptor.finalize()
    return result


def encrypt(key, iv, plaintext, bits=64, version="v2"):
    ciphertext = encrypt_ctr(key, iv, plaintext, bits)

    info = {
        "key": {
            "k": b64u(key),
            "alg": "A256CTR",
            "kty": "oct",
            "key_ops": ["encrypt", "decrypt"],
        },
        "iv": b64(iv),
        "hashes": { "sha256": b64(hashlib.sha256(ciphertext).digest()) }
    }

    if version:
        info["v"] = version

    return b64(ciphertext), info, b64(plaintext)

json.dump([
    encrypt("\x00"*32, "\x00"*16, ""),
    encrypt("\xFF"*32, "\xFF"*8 + "\x00"*8, "Hello, World"),
    encrypt("\xFF"*32, "\xFF"*8 + "\x00"*8, "alphanumerically" * 4),
    encrypt("\xFF"*32, "\xFF"*16, "alphanumerically" * 4, 64, "v1"),
    encrypt("\xFF"*32, "\xFF"*16, "alphanumerically" * 4, 128, None),
], sys.stdout)
