function assertEq(got, want) {
    const gotJSON = JSON.stringify(got);
    const wantJSON = JSON.stringify(want);
    if (wantJSON != gotJSON) {
        throw new Error('Want ' + wantJSON + ' got ' + gotJSON);
    }
}

describe('EncryptAttachment', function() {
    const testVectors = ['', 'SGVsbG8sIFdvcmxk'];

    testVectors.forEach(function(want) {
        it('roundtrips ' + JSON.stringify(want), function() {
            return MatrixEncryptAttachment.encryptAttachment(MatrixEncryptAttachment.decodeBase64(want))
                .then(function(encryptResult) {
                    return MatrixEncryptAttachment.decryptAttachment(encryptResult.data, encryptResult.info);
                }).then(function(decryptResult) {
                    assertEq(MatrixEncryptAttachment.encodeBase64(new Uint8Array(decryptResult)), want);
                });
        });
    });
});
