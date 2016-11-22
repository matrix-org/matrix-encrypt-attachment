describe("DecryptAttachment", function() {
    var testVectors = [
        ["", {
            "v": "v1",
            "hashes": {
                "sha256": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
            },
            "key": {
                "alg": "A256CTR",
                "k": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "key_ops": ["encrypt", "decrypt"],
                "kty": "oct"
            },
            "iv": "AAAAAAAAAAAAAAAAAAAAAA"
        }, ""],
        ["nZxRAVw962fwUQ5/", {
            "v": "v1",
            "hashes": {
                "sha256": "geLWS2ptBew5aPLJRTK+QnI3Krdl3UaxN8qfahHWhfc"
            }, "key": {
                "alg": "A256CTR",
                "k": "__________________________________________8",
                "key_ops": ["encrypt", "decrypt"],
                "kty": "oct"
            }, "iv": "/////////////////////w"
        }, "SGVsbG8sIFdvcmxk"],
        ["tJVNBVJ/vl36UQt4Y5e5myqUL3M8OtjRVQljZ+LlwbJeucRIM7CeKDJGGOjlJ1bqpqUdl6zytXJ3dCyvnUi4eQ", {
            "iv": "/////////////////////w",
            "key": {
                "kty": "oct",
                "key_ops": [ "encrypt", "decrypt" ],
                "k": "__________________________________________8",
                "alg": "A256CTR"
            },
            "hashes": {
                "sha256": "/K4w3G4zlLK312k66KxNPKDkWCn2QAH5aphAkuncTrQ"
             }
        }, "YWxwaGFudW1lcmljYWxseWFscGhhbnVtZXJpY2FsbHlhbHBoYW51bWVyaWNhbGx5YWxwaGFudW1lcmljYWxseQ"],
        ["tJVNBVJ/vl36UQt4Y5e5m84bRUrQHhcdLPvS/7EkDvlkDLZXamBB6k8THbiawiKZ5Mnq9PZMSSbgOCvmnUBOMA", {
            "v": "v1",
            "hashes": {
                "sha256": "LYG/orOViuFwovJpv2YMLSsmVKwLt7pY3f8SYM7KU5E"
            },
            "key": {
                "kty": "oct",
                "key_ops": ["encrypt","decrypt"],
                "k": "__________________________________________8",
                "alg": "A256CTR"
            },
            "iv": "/////////////////////w"
        }, "YWxwaGFudW1lcmljYWxseWFscGhhbnVtZXJpY2FsbHlhbHBoYW51bWVyaWNhbGx5YWxwaGFudW1lcmljYWxseQ"]
    ];

    testVectors.forEach(function (vector) {
        var inputCiphertext = vector[0];
        var inputInfo = vector[1];
        var want = vector[2];
        it("decrypts " + JSON.stringify([inputCiphertext, inputInfo]), function() {
            return decryptAttachment(decodeBase64(inputCiphertext), inputInfo).then(function(got) {
                assertEq(encodeBase64(new Uint8Array(got)), want);
            });
        });
    });
});
