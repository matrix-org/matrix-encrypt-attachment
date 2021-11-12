function assertEq(got, want) {
    const gotJSON = JSON.stringify(got);
    const wantJSON = JSON.stringify(want);
    if (wantJSON != gotJSON) {
        throw new Error('Want ' + wantJSON + ' got ' + gotJSON);
    }
}

const decryptTestVectors = [
    [
        '',
        {
            'iv': 'AAAAAAAAAAAAAAAAAAAAAA',
            'key': {
                'kty': 'oct',
                'key_ops': [
                    'encrypt',
                    'decrypt',
                ],
                'k': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                'alg': 'A256CTR',
            },
            'v': 'v2',
            'hashes': {
                'sha256': '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU',
            },
        },
        '',
    ],
    [ // v2
        '5xJZTt5cQicm+9f4',
        {
            'iv': '//////////8AAAAAAAAAAA',
            'key': {
                'kty': 'oct',
                'key_ops': [
                    'encrypt',
                    'decrypt',
                ],
                'k': '__________________________________________8',
                'alg': 'A256CTR',
            },
            'v': 'v2',
            'hashes': {
                'sha256': 'YzF08lARDdOCzJpzuSwsjTNlQc4pHxpdHcXiD/wpK6k',
            },
        },
        'SGVsbG8sIFdvcmxk',
    ],
    [ // protocol v2 with plain text YWxwaGF
        'zhtFStAeFx0s+9L/sSQO+WQMtldqYEHqTxMduJrCIpnkyer09kxJJuA4K+adQE4w+7jZe/vR9kIcqj9rOhDR8Q',
        {
            'iv': '//////////8AAAAAAAAAAA',
            'key': {
                'kty': 'oct',
                'key_ops': [
                    'encrypt',
                    'decrypt',
                ],
                'k': '__________________________________________8',
                'alg': 'A256CTR',
            },
            'v': 'v2',
            'hashes': {
                'sha256': 'IOq7/dHHB+mfHfxlRY5XMeCWEwTPmlf4cJcgrkf6fVU',
            },
        },
        'YWxwaGFudW1lcmljYWxseWFscGhhbnVtZXJpY2FsbHlhbHBoYW51bWVyaWNhbGx5YWxwaGFudW1lcmljYWxseQ',
    ],
    [ // protocol v1 with plain text YWxwaGF
        'tJVNBVJ/vl36UQt4Y5e5m84bRUrQHhcdLPvS/7EkDvlkDLZXamBB6k8THbiawiKZ5Mnq9PZMSSbgOCvmnUBOMA',
        {
            'iv': '/////////////////////w',
            'key': {
                'kty': 'oct',
                'key_ops': [
                    'encrypt',
                    'decrypt',
                ],
                'k': '__________________________________________8',
                'alg': 'A256CTR',
            },
            'v': 'v1',
            'hashes': {
                'sha256': 'LYG/orOViuFwovJpv2YMLSsmVKwLt7pY3f8SYM7KU5E',
            },
        },
        'YWxwaGFudW1lcmljYWxseWFscGhhbnVtZXJpY2FsbHlhbHBoYW51bWVyaWNhbGx5YWxwaGFudW1lcmljYWxseQ',
    ],
    [ // protocol v0 with plain text YWxwaGF
        'tJVNBVJ/vl36UQt4Y5e5myqUL3M8OtjRVQljZ+LlwbJeucRIM7CeKDJGGOjlJ1bqpqUdl6zytXJ3dCyvnUi4eQ',
        {
            'iv': '/////////////////////w',
            'key': {
                'kty': 'oct',
                'key_ops': [
                    'encrypt',
                    'decrypt',
                ],
                'k': '__________________________________________8',
                'alg': 'A256CTR',
            },
            'v': 'v1',
            'hashes': {
                'sha256': '/K4w3G4zlLK312k66KxNPKDkWCn2QAH5aphAkuncTrQ',
            },
        },
        'YWxwaGFudW1lcmljYWxseWFscGhhbnVtZXJpY2FsbHlhbHBoYW51bWVyaWNhbGx5YWxwaGFudW1lcmljYWxseQ',
    ],
];

describe('DecryptAttachment', function() {
    decryptTestVectors.forEach(function(vector) {
        const inputCiphertext = vector[0];
        const inputInfo = vector[1];
        const want = vector[2];
        it('decrypts ' + JSON.stringify([inputCiphertext, inputInfo]), function() {
            return MatrixEncryptAttachment
                .decryptAttachment(MatrixEncryptAttachment.decodeBase64(inputCiphertext), inputInfo)
                .then(function(got) {
                    assertEq(MatrixEncryptAttachment.encodeBase64(new Uint8Array(got)), want);
                });
        });
    });
});
