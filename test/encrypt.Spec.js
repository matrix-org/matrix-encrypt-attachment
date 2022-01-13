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

describe('EncryptAttachment', function() {
    const testVectors = ['', 'SGVsbG8sIFdvcmxk'];

    testVectors.forEach(function(want) {
        it(`roundtrips ${JSON.stringify(want)}`, function() {
            return MatrixEncryptAttachment.encryptAttachment(MatrixEncryptAttachment.decodeBase64(want))
                .then(function(encryptResult) {
                    return MatrixEncryptAttachment.decryptAttachment(encryptResult.data, encryptResult.info);
                }).then(function(decryptResult) {
                    assertEq(MatrixEncryptAttachment.encodeBase64(new Uint8Array(decryptResult)), want);
                });
        });
    });
});
