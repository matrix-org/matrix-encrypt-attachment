describe("EncryptAttachment", function() {
    var testVectors = ["", "SGVsbG8sIFdvcmxk"];

    testVectors.forEach(function(want) {
        it("roundtrips " + JSON.stringify(want), function() {
            return encryptAttachment(decodeBase64(want)).then(function(encryptResult) {
                return decryptAttachment(encryptResult.data, encryptResult.info);
            }).then(function(decryptResult) {
                assertEq(encodeBase64(new Uint8Array(decryptResult)), want);
            });
        });
    });
});
