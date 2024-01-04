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

import { IEncryptedFile, IEncryptedFileJWK } from '.';

export async function encryptAttachment(plaintextBuffer: ArrayBuffer): Promise<{
    data: ArrayBuffer;
    info: IEncryptedFile;
}> {
    // Generate an IV where the first 8 bytes are random and the high 8 bytes
    // are zero. We set the counter low bits to 0 since it makes it unlikely
    // that the 64 bit counter will overflow.
    const ivArray = new Uint8Array(16); // Uint8Array of AES IV
    window.crypto.getRandomValues(ivArray.subarray(0, 8));
    // Load the encryption key.
    const cryptoKey = await window.crypto.subtle.generateKey(
        { 'name': 'AES-CTR', 'length': 256 }, true, ['encrypt', 'decrypt'],
    );
    // Export the Key as JWK.
    const exportedKey = await window.crypto.subtle.exportKey('jwk', cryptoKey);
    // Encrypt the input ArrayBuffer.
    // Use half of the iv as the counter by setting the "length" to 64.
    const ciphertextBuffer = await window.crypto.subtle.encrypt(
        { name: 'AES-CTR', counter: ivArray, length: 64 }, cryptoKey, plaintextBuffer,
    );
    // SHA-256 the encrypted data.
    const sha256Buffer = await window.crypto.subtle.digest('SHA-256', ciphertextBuffer);
    return {
        data: ciphertextBuffer,
        info: {
            v: 'v2',
            key: exportedKey as IEncryptedFileJWK,
            iv: encodeBase64(ivArray),
            hashes: {
                sha256: encodeBase64(new Uint8Array(sha256Buffer)),
            },
        },
    };
}

export async function decryptAttachment(ciphertextBuffer: ArrayBuffer, info: IEncryptedFile): Promise<ArrayBuffer> {
    if (info === undefined || info.key === undefined || info.iv === undefined
        || info.hashes === undefined || info.hashes.sha256 === undefined) {
        throw new Error('Invalid info. Missing info.key, info.iv or info.hashes.sha256 key');
    }

    if (info.v && !info.v.match(/^v[1-2]$/)) {
        throw new Error(`Unsupported protocol version: ${info.v}`);
    }

    const ivArray = decodeBase64(info.iv);
    const expectedSha256base64 = info.hashes.sha256;
    // Load the AES from the "key" key of the inf bao object.
    const cryptoKey = await window.crypto.subtle.importKey(
        'jwk', info.key, { 'name': 'AES-CTR' }, false, ['encrypt', 'decrypt'],
    );
    const digestResult = await window.crypto.subtle.digest('SHA-256', ciphertextBuffer);
    if (encodeBase64(new Uint8Array(digestResult)) != expectedSha256base64) {
        throw new Error('Mismatched SHA-256 digest');
    }
    let counterLength: number;
    if (info.v == 'v1' || info.v == 'v2') {
        // Version 1 and 2 use a 64 bit counter.
        counterLength = 64;
    } else {
        // Version 0 uses a 128 bit counter.
        counterLength = 128;
    }
    return window.crypto.subtle.decrypt(
        { name: 'AES-CTR', counter: ivArray, length: counterLength }, cryptoKey, ciphertextBuffer,
    );
}

// XXX: is this the right idiom for the Streams API? It matches the existing encrypt/decryptAttachment() signatures,
// Alternatively it could return a TransformStream object, rather than clocking itself.

// XXX: also, i think i have readable & writable the wrong way round here: the upstream should be writing to the
// writable plaintext, and the downstream should be reading from the readable ciphertext...
export async function encryptStreamedAttachment(plaintextStream: ReadableStream, ciphertextStream: WritableStream):
    Promise<IEncryptedFile> {
    // generate a full 12-bytes of IV, as it shouldn't matter if AES-GCM overflows
    // and more entropy is better.
    const baseIv = new Uint8Array(12); // Uint8Array of AES IV
    window.crypto.getRandomValues(baseIv.subarray(0, 12));
    const ivString = encodeBase64(baseIv);
    // Load the encryption key.
    const cryptoKey = await window.crypto.subtle.generateKey(
        { 'name': 'AES-GCM', 'length': 256 }, true, ['encrypt', 'decrypt'],
    );
    // Export the Key as JWK.
    const exportedKey = await window.crypto.subtle.exportKey('jwk', cryptoKey);

    // encrypt chunks from the plaintextStream and emit them to the ciphertextStream
    const reader = plaintextStream.getReader();
    const writer = ciphertextStream.getWriter();

    let blockId = 0;
    let started = false;

    const iv = new Uint8Array(16);
    iv.set(baseIv, 4);

    const onRead = async ({ done, value }) => {
        if (done) {
            await writer.ready;
            await writer.close();
            return;
        }

        const blockIdArray = new Uint32Array([blockId]);

        // concatenate the IV with the block sequence number so it gets hashed down to a 96-bit value within GCM
        // to mitigate IV reuse
        iv.set(new Uint8Array(blockIdArray.buffer), 0);

        let ciphertextBuffer;
        try {
            ciphertextBuffer = await window.crypto.subtle.encrypt(
                { name: 'AES-GCM', iv, length: 128, additionalData: blockIdArray.buffer }, cryptoKey, value,
            );
        } catch (e) {
            console.error('failed to encrypt', e);
            throw (e);
        }

        writer.ready.then(() => {
            if (!started) {
                writer.write(new Uint8Array([77, 88, 67, 0x03])); // magic number
                started = true;
            }

            const outBuffer = new Uint8Array(16 + ciphertextBuffer.byteLength);
            // We write our custom headers to make the GCM block seekable, and to let partially decrypted content
            // be visible to the recipient while benefiting from the GCM authentication tags.
            outBuffer.set([0xFF, 0xFF, 0xFF, 0xFF], 0); // registration marker
            outBuffer.set(new Uint8Array(blockIdArray.buffer), 4);
            outBuffer.set(new Uint8Array(new Uint32Array([ciphertextBuffer.byteLength]).buffer), 8);
            // TODO: calculate a CRC
            outBuffer.set([0x00, 0x00, 0x00, 0x00], 12);
            outBuffer.set(new Uint8Array(ciphertextBuffer), 16);
            writer.write(outBuffer);
        });

        blockId++;

        // Read some more, and call this function again
        return reader.read().then(onRead);
    };

    reader.read().then(onRead);

    return {
        v: 'org.matrix.msc4016.v3',
        key: exportedKey as IEncryptedFileJWK,
        iv: ivString,
        hashes: {
            // no hashes need for AES-GCM
        },
    };
}

export async function decryptStreamedAttachment(
    ciphertextStream: ReadableStream, plaintextStream: WritableStream, info: IEncryptedFile,
) {
    if (info === undefined || info.key === undefined || info.iv === undefined) {
        throw new Error('Invalid info. Missing info.key or info.iv');
    }

    if (info.v && info.v != 'org.matrix.msc4016.v3') {
        throw new Error(`Unsupported protocol version: ${info.v}`);
    }

    // Load the AES from the "key" key of the inf bao object.
    const cryptoKey = await window.crypto.subtle.importKey(
        'jwk', info.key, { 'name': 'AES-GCM' }, false, ['encrypt', 'decrypt'],
    );

    // decrypt chunks from the cipherStream and emit them to the Stream
    const reader = ciphertextStream.getReader();
    const writer = plaintextStream.getWriter();

    const bufferLen = (65536 + 16 + 16) * 2;
    let buffer = new Uint8Array(bufferLen);
    let bufferOffset = 0;

    let started = false;

    const onRead = async ({ done, value }) => {
        if (done) {
            await writer.ready;
            await writer.close();
            return;
        }

        buffer.set(value, bufferOffset);
        bufferOffset += value.length;

        // handle magic number. TODO: handle random access.
        if (!started) {
            const magicLen = 4;
            if (bufferOffset > magicLen) {
                if (buffer[0] != 77 || buffer[1] != 88 || buffer[2] != 67 || buffer[3] != 0x03) {
                    throw new Error('Can\'t decrypt stream: invalid magic number');
                }
                else {
                    started = true;
                    // rewind away the magic number
                    const newBuffer = new Uint8Array(new ArrayBuffer(bufferLen));
                    newBuffer.set(buffer.slice(magicLen));
                    buffer = newBuffer;
                    bufferOffset -= magicLen;
                }
            }
        }

        const iv = new Uint8Array(16);
        iv.set(decodeBase64(info.iv), 4);

        // handle blocks
        const headerLen = 16;
        while (bufferOffset > headerLen) {
            const header = new Uint32Array(buffer.buffer, 0, 12);
            if (header[0] != 0xFFFFFFFF) {
                // TODO: handle random access and hunt for the registration code if it's not at the beginning
                console.log('Chunk doesn\'t begin with a registration code', header, header[0]);
                throw new Error('Chunk doesn\'t begin with a registration code');
            }
            const blockId = header[1];
            const blockLength = header[2];
            // const crc = header[3];
            if (bufferOffset >= headerLen + blockLength) {
                // we can decrypt!
                // TODO: check the CRC

                // TODO: terminate stream if blockId wraps all the way around (to prevent IV reuse)
                const blockIdArray = new Uint32Array([blockId]);

                // concatenate the IV with the block sequence number so it gets hashed down to a 96-bit value within GCM
                // to mitigate IV reuse
                iv.set(new Uint8Array(blockIdArray.buffer), 0);

                let plaintextBuffer;
                try {
                    plaintextBuffer = await window.crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv, length: 128, additionalData: blockIdArray.buffer },
                        cryptoKey, buffer.slice(headerLen, headerLen + blockLength),
                    );
                } catch (e) {
                    console.error('failed to decrypt (probably invalid IV or corrupt stream)', e);
                    throw (e);
                }

                writer.ready.then(() => writer.write(plaintextBuffer));

                // wind back the buffer, if any
                const newBuffer = new Uint8Array(new ArrayBuffer(bufferLen));
                newBuffer.set(buffer.slice(headerLen + blockLength));
                buffer = newBuffer;
                bufferOffset -= (headerLen + blockLength);
            }
            else {
                break;
            }
        }

        // Read some more, and call this function again
        return reader.read().then(onRead);
    };

    reader.read().then(onRead);

    return plaintextStream;
}

export function encodeBase64(uint8Array: Uint8Array): string {
    // Misinterpt the Uint8Array as Latin-1.
    // window.btoa expects a unicode string with codepoints in the range 0-255.
    const latin1String = String.fromCharCode.apply(null, uint8Array);
    // Use the builtin base64 encoder.
    const paddedBase64 = window.btoa(latin1String);
    // Calculate the unpadded length.
    const inputLength = uint8Array.length;
    const outputLength = 4 * Math.floor((inputLength + 2) / 3) + (inputLength + 2) % 3 - 2;
    // Return the unpadded base64.
    return paddedBase64.slice(0, outputLength);
}

export function decodeBase64(base64: string): Uint8Array {
    // Pad the base64 up to the next multiple of 4.
    const paddedBase64 = base64 + '==='.slice(0, (4 - base64.length % 4) % 4);
    // Decode the base64 as a misinterpreted Latin-1 string.
    // window.atob returns a unicode string with codepoints in the range 0-255.
    const latin1String = window.atob(paddedBase64);
    // Encode the string as a Uint8Array as Latin-1.
    const uint8Array = new Uint8Array(latin1String.length);
    for (let i = 0; i < latin1String.length; i++) {
        uint8Array[i] = latin1String.charCodeAt(i);
    }
    return uint8Array;
}

export default {
    encryptAttachment,
    decryptAttachment,
    encryptStreamedAttachment,
    decryptStreamedAttachment,
    encodeBase64,
    decodeBase64,
};
