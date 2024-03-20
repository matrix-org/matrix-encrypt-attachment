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

function assertEq(got, want) {
    const gotJSON = JSON.stringify(got);
    const wantJSON = JSON.stringify(want);
    if (wantJSON != gotJSON) {
        throw new Error(`Want ${wantJSON} got ${gotJSON}`);
    }
}

const v2TestVectors = [
    [
        "",
        {
            "iv": "AAAAAAAAAAAAAAAAAAAAAA",
            "key": {
                "kty": "oct",
                "key_ops": [
                    "encrypt",
                    "decrypt",
                ],
                "k": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "alg": "A256CTR",
            },
            "v": "v2",
            "hashes": {
                "sha256": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
            },
        },
        "",
    ],
    [
        "5xJZTt5cQicm+9f4",
        {
            "iv": "//////////8AAAAAAAAAAA",
            "key": {
                "kty": "oct",
                "key_ops": [
                    "encrypt",
                    "decrypt",
                ],
                "k": "__________________________________________8",
                "alg": "A256CTR",
            },
            "v": "v2",
            "hashes": {
                "sha256": "YzF08lARDdOCzJpzuSwsjTNlQc4pHxpdHcXiD/wpK6k",
            },
        },
        "SGVsbG8sIFdvcmxk",
    ],
    [ // plain text YWxwaGF with protocol v2
        "zhtFStAeFx0s+9L/sSQO+WQMtldqYEHqTxMduJrCIpnkyer09kxJJuA4K+adQE4w+7jZe/vR9kIcqj9rOhDR8Q",
        {
            "iv": "//////////8AAAAAAAAAAA",
            "key": {
                "kty": "oct",
                "key_ops": [
                    "encrypt",
                    "decrypt",
                ],
                "k": "__________________________________________8",
                "alg": "A256CTR",
            },
            "v": "v2",
            "hashes": {
                "sha256": "IOq7/dHHB+mfHfxlRY5XMeCWEwTPmlf4cJcgrkf6fVU",
            },
        },
        "YWxwaGFudW1lcmljYWxseWFscGhhbnVtZXJpY2FsbHlhbHBoYW51bWVyaWNhbGx5YWxwaGFudW1lcmljYWxseQ",
    ],
];

const v1TestVectors = [
    [ // plain text YWxwaGF with protocol v1
        "tJVNBVJ/vl36UQt4Y5e5m84bRUrQHhcdLPvS/7EkDvlkDLZXamBB6k8THbiawiKZ5Mnq9PZMSSbgOCvmnUBOMA",
        {
            "iv": "/////////////////////w",
            "key": {
                "kty": "oct",
                "key_ops": [
                    "encrypt",
                    "decrypt",
                ],
                "k": "__________________________________________8",
                "alg": "A256CTR",
            },
            "v": "v1",
            "hashes": {
                "sha256": "LYG/orOViuFwovJpv2YMLSsmVKwLt7pY3f8SYM7KU5E",
            },
        },
        "YWxwaGFudW1lcmljYWxseWFscGhhbnVtZXJpY2FsbHlhbHBoYW51bWVyaWNhbGx5YWxwaGFudW1lcmljYWxseQ",
    ],
];

const v0TestVectors = [
    [ // plain text YWxwaGF with protocol v0
        "tJVNBVJ/vl36UQt4Y5e5myqUL3M8OtjRVQljZ+LlwbJeucRIM7CeKDJGGOjlJ1bqpqUdl6zytXJ3dCyvnUi4eQ",
        {
            "iv": "/////////////////////w",
            "key": {
                "kty": "oct",
                "key_ops": [
                    "encrypt",
                    "decrypt",
                ],
                "k": "__________________________________________8",
                "alg": "A256CTR",
            },
            "hashes": {
                "sha256": "/K4w3G4zlLK312k66KxNPKDkWCn2QAH5aphAkuncTrQ",
            },
        },
        "YWxwaGFudW1lcmljYWxseWFscGhhbnVtZXJpY2FsbHlhbHBoYW51bWVyaWNhbGx5YWxwaGFudW1lcmljYWxseQ",
    ],
];

const browserTestVectors = [
    ...v2TestVectors,
    ...v1TestVectors,
    ...v0TestVectors,
];

const nodejsTestVectors = [
    ...v2TestVectors,
];

describe("DecryptAttachment", function() {
    const decryptTestVectors = typeof window === "undefined" ? nodejsTestVectors : browserTestVectors;
    decryptTestVectors.forEach(function(vector) {
        const inputCiphertext = vector[0];
        const inputInfo = vector[1];
        const want = vector[2];
        it(`decrypts ${inputInfo.v || "v0"} ${JSON.stringify([inputCiphertext, inputInfo])}`, function() {
            return MatrixEncryptAttachment
                .decryptAttachment(MatrixEncryptAttachment.decodeBase64(inputCiphertext), inputInfo)
                .then(function(got) {
                    assertEq(MatrixEncryptAttachment.encodeBase64(new Uint8Array(got)), want);
                });
        });
    });
});
