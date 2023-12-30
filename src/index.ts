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
     * Version of the encrypted attachments protocol. See README.md for supported protocol versions.
     */
    v?: string;

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
 * Encrypt an stream of arraybuffers for MSC4016 (aka v3)
 * @param {ReadableStream} plaintextStream The readable stream of plaintext
 * @param {WritableStream} ciphertextStream The writable stream of ciphertext
 * @return {Promise} A promise that resolves with an object when the attachment is encrypted.
 *      The object has an "info" key with an object containing the info needed to decrypt the data.
 */
export async function encryptStreamedAttachment(plaintextStream: ReadableStream, ciphertextStream: WritableStream):
    Promise<IEncryptedFile> {
    return webcrypto.encryptStreamedAttachment(plaintextStream, ciphertextStream);
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
 * Decrypt a stream of arraybuffers for MSC4016 (aka v3)
 * @param {ReadableStream} ciphertextStream The readable stream of ciphertext
 * @param {WritableStream} plaintextStream The writable stream of plaintext
 * @return nothing
 */
export async function decryptStreamedAttachment(
    ciphertextStream: ReadableStream, plaintextStream: WritableStream, info: IEncryptedFile,
) {
    return webcrypto.decryptStreamedAttachment(ciphertextStream, plaintextStream, info);
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
