/*
Copyright 2021-2022 The Matrix.org Foundation C.I.C.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import crypto from 'crypto';
import { IEncryptedFile, IEncryptedFileJWK } from '.';

export async function encryptAttachment(plaintextBuffer: Buffer): Promise<{
    data: ArrayBuffer;
    info: IEncryptedFile;
}> {
    // Generate an IV where the first 8 bytes are random and the high 8 bytes
    // are zero. We set the counter low bits to 0 since it makes it unlikely
    // that the 64 bit counter will overflow.
    const ivArray = crypto.randomBytes(16); // Uint8Array of AES IV
    ivArray.fill(0, 8);

    // generate 256 bit key
    const cryptoKey = crypto.randomBytes(32);

    // Export the Key as JWK.
    const exportedKey: IEncryptedFileJWK = {
        kty: 'oct',
        key_ops: ['encrypt', 'decrypt'],
        alg: 'A256CTR',
        // node 14+ supports base64url encoding directly, but node 12 doesn't so we implement the mapping ourselves
        k: Buffer.from(cryptoKey).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''), // URL safe base64 without padding
        ext: true,
    };

    // Encrypt the input Buffer.
    const cipher = crypto.createCipheriv('aes-256-ctr', cryptoKey, ivArray);
    const ciphertextBuffer = Buffer.concat([
        cipher.update(plaintextBuffer),
        cipher.final(),
    ]);

    // SHA-256 the encrypted data.
    const sha256Buffer = crypto.createHash('sha256').update(ciphertextBuffer).digest();

    return {
        data: ciphertextBuffer,
        info: {
            v: 'v2',
            key: exportedKey,
            iv: encodeBase64(ivArray),
            hashes: {
                sha256: encodeBase64(sha256Buffer),
            },
        },
    };
}

// this is based on https://github.com/matrix-org/matrix-content-scanner/blob/main/src/decrypt.js
export function decryptAttachment(dataBuffer: Buffer, info: IEncryptedFile): Buffer {
    if (info === undefined || info.key === undefined || info.iv === undefined ||
        info.hashes === undefined || info.hashes.sha256 === undefined) {
        throw new Error('Invalid info. Missing info.key, info.iv or info.hashes.sha256 key');
    }

    if (info.v !== 'v2') {
        throw new Error(`Unsupported protocol version: ${info.v ?? 'v0'}`);
    }

    const expectedSha256base64 = info.hashes.sha256;

    // Convert from JWK to openssl algorithm
    // See https://www.w3.org/2012/webcrypto/wiki/KeyWrap_Proposal#JSON_Web_Key
    const algorithms = {
        'oct': {
            'A256CTR': 'aes-256-ctr',
        },
    };

    const alg = algorithms[info.key.kty] ? algorithms[info.key.kty][info.key.alg] : undefined;

    if (!alg) {
        throw new Error(
            `Unsupported key type/algorithm: ` +
            `key.kty = ${info.key.kty}, kry.alg = ${info.key.alg}`);
    }

    const key = decodeBase64(info.key.k);

    // Calculate SHA 256 hash, encode as base64 without padding
    const hashDigestBase64 = encodeBase64(crypto.createHash('sha256').update(dataBuffer).digest());

    if (hashDigestBase64 !== expectedSha256base64) {
        throw new Error('Unexpected sha256 hash of encrypted data');
    }

    const iv = decodeBase64(info.iv);

    const decipher = crypto.createDecipheriv(alg, key, iv);

    return Buffer.concat([
        decipher.update(dataBuffer),
        decipher.final(),
    ]);
}

export function encodeBase64(uint8Array: Uint8Array): string {
    const padded = Buffer.from(uint8Array).toString('base64');

    // remove padding
    const inputLength = uint8Array.length;
    const outputLength = 4 * Math.floor((inputLength + 2) / 3) + (inputLength + 2) % 3 - 2;
    // Return the unpadded base64.
    return padded.slice(0, outputLength);
}

export function decodeBase64(base64: string): Uint8Array {
    // add padding if needed
    const paddedBase64 = base64 + '==='.slice(0, (4 - base64.length % 4) % 4);
    return Buffer.from(paddedBase64, 'base64');
}
