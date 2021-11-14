import * as webcrypto from './webcrypto';
import * as nodejs from './nodejs';

const hasWebcrypto = !!(typeof window !== 'undefined' && window.crypto?.subtle);

/**
 * Represents an `EncryptedFile` as described by https://spec.matrix.org/v1.1/client-server-api/#extensions-to-mroommessage-msgtypes
 */
export interface IEncryptedFile {
    /**
     * A JSON Web Key object containing the key used.
     */
    key: IEncryptedFileJWK;

    /**
     * The 128-bit unique counter block used by AES-CTR, encoded as unpadded base64.
     */
    iv: string;

    /**
     * Version of the encrypted attachments protocol.
     * New encryptions will be created with v2.
     * This library can decrypt v1 and v2. v0 (where `v` is `undefined`) is not supported by this library.
     */
    v: string;

    /**
     * A map from an algorithm name to a hash of the ciphertext, encoded as unpadded base64. Clients should support the SHA-256 hash, which uses the key sha256.
     */
    hashes?: {
        sha256?: string;
    };
}

/**
 * Representation of `JWK` as described by https://spec.matrix.org/v1.1/client-server-api/#extensions-to-mroommessage-msgtypes
 */
export interface IEncryptedFileJWK extends JsonWebKey {
    /**
     * Key type. Must be `oct`.
     */
    kty: string;

    /**
     *  Key operations. Must at least contain `encrypt` and `decrypt`.
     */
    key_ops: string[];

    /**
     * Algorithm. Must be `A256CTR`.
     */
    alg: string;

    /**
     *  The key, encoded as urlsafe unpadded base64.
     */
    k: string;

    /**
     * Extractable. Must be `true`. This is a W3C extension.
     */
    ext: boolean;
}

/**
 * Encrypt an attachment to latest protocol specification (currently v2).
 * @param {ArrayBuffer} plaintextBuffer The attachment data buffer.
 * @return {Promise} A promise that resolves with an object when the attachment is encrypted.
 *      The object has a "data" key with an ArrayBuffer of encrypted data and an "info" key
 *      with an object containing the info needed to decrypt the data.
 */
export async function encryptAttachment(plaintextBuffer: ArrayBuffer): Promise<{
    data: ArrayBuffer;
    info: IEncryptedFile;
}> {
    return hasWebcrypto ? webcrypto.encryptAttachment(plaintextBuffer)
        : nodejs.encryptAttachment(Buffer.from(plaintextBuffer));
}

/**
 * Decrypt an attachment that has been encrypted with v1 or v2.
 * @param {ArrayBuffer} ciphertextBuffer The encrypted attachment data buffer.
 * @param {IEncryptedFile} info The information needed to decrypt the attachment.
 * @return {Promise<ArrayBuffer>} A promise that resolves with an ArrayBuffer when the attachment is decrypted.
 */
export async function decryptAttachment(ciphertextBuffer: ArrayBuffer, info: IEncryptedFile): Promise<ArrayBuffer> {
    return hasWebcrypto ? webcrypto.decryptAttachment(ciphertextBuffer, info)
        : nodejs.decryptAttachment(Buffer.from(ciphertextBuffer), info);
}

/**
 * Encode a typed array of uint8 as unpadded base64.
 * @param {Uint8Array} uint8Array The data to encode.
 * @return {string} The base64 without padding.
 */
export function encodeBase64(uint8Array: Uint8Array): string {
    return hasWebcrypto ? webcrypto.encodeBase64(uint8Array)
        : nodejs.encodeBase64(uint8Array);
}

/**
 * Decode a base64 string to a typed array of uint8.
 * This will decode unpadded base64, but will also accept base64 with padding.
 * @param {string} base64 The unpadded base64 to decode.
 * @return {Uint8Array} The decoded data.
 */
export function decodeBase64(base64: string): Uint8Array {
    return hasWebcrypto ? webcrypto.decodeBase64(base64)
        : nodejs.decodeBase64(base64);
}
