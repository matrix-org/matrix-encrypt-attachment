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

b64 = lambda x: base64.b64encode(x).rstrip("=")
b64u = lambda x: base64.urlsafe_b64encode(x).rstrip("=")

def encrypt(key, iv, plaintext):
    encryptor = Cipher(
        algorithms.AES(key),
        modes.CTR(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

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
    return b64(ciphertext), info, b64(plaintext)

json.dump([
    encrypt("\x00"*32, "\x00"*16, ""),
    encrypt("\xFF"*32, "\xFF"*16, "Hello, World"),
    encrypt("\xFF"*32, "\xFF"*16, "alphanumerically" * 4),
], sys.stdout)
