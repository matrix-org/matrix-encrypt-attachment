describe("DecryptAttachment", function() {
    var testVectors = [
        ["gxI1eiER6jOxtn6y/gX+hg", {
            key: {
                alg: "A256GCM",
                k: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                kty: "oct",
                key_ops: ["encrypt","decrypt"],
            },
            iv: "AAAAAAAAAAAAAAAAAAAAAA",
            hashes: { sha256: "YhVyrkrEseY7Zu9Z/UolrKFbTkps0rSirf6MXspgwVo" },
        }, ""],
        ["8cviqGwcc+gCiyV6Qwhcc43V/izXoHBKRH9vyw", {
            iv: "/////////////////////w",
            key: {
                kty: "oct",
                key_ops: ["encrypt", "decrypt" ],
                k: "__________________________________________8",
                alg: "A256GCM"
            },
            hashes: { sha256: "9vNkVndnOLSsQ5UvmKB/W5g/4ScVYHlSQS3QliU+Xvo" }
        }, "SGVsbG8sIFdvcmxk"],
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
