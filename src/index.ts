import * as webcrypto from './webcrypto';

export interface IAttachmentInfo {
    key: any;
    iv: string;
    v?: string;
    hashes: {
        sha256: string;
    };
}

/**
 * Encrypt an attachment.
 * @param {ArrayBuffer} plaintextBuffer The attachment data buffer.
 * @return {Promise} A promise that resolves with an object when the attachment is encrypted.
 *      The object has a "data" key with an ArrayBuffer of encrypted data and an "info" key
 *      with an object containing the info needed to decrypt the data.
 */
export async function encryptAttachment(plaintextBuffer: ArrayBuffer): Promise<{
    data: ArrayBuffer;
    info: IAttachmentInfo;
}> {
    return webcrypto.encryptAttachment(plaintextBuffer);
}

/**
 * Decrypt an attachment.
 * @param {ArrayBuffer} ciphertextBuffer The encrypted attachment data buffer.
 * @param {Object} info The information needed to decrypt the attachment.
 * @param {Object} info.key AES-CTR JWK key object.
 * @param {string} info.iv Base64 encoded 16 byte AES-CTR IV.
 * @param {string} info.hashes.sha256 Base64 encoded SHA-256 hash of the ciphertext.
 * @return {Promise} A promise that resolves with an ArrayBuffer when the attachment is decrypted.
 */
export async function decryptAttachment(ciphertextBuffer: ArrayBuffer, info: IAttachmentInfo): Promise<ArrayBuffer> {
    return webcrypto.decryptAttachment(ciphertextBuffer, info);
}

/**
 * Encode a typed array of uint8 as base64.
 * @param {Uint8Array} uint8Array The data to encode.
 * @return {string} The base64 without padding.
 */
export function encodeBase64(uint8Array: Uint8Array): string {
    return webcrypto.encodeBase64(uint8Array);
}

/**
 * Decode a base64 string to a typed array of uint8.
 * This will decode unpadded base64, but will also accept base64 with padding.
 * @param {string} base64 The unpadded base64 to decode.
 * @return {Uint8Array} The decoded data.
 */
export function decodeBase64(base64: string): Uint8Array {
    return webcrypto.decodeBase64(base64);
}
