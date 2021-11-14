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
