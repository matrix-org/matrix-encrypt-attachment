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

// eslint-disable-next-line valid-jsdoc
/**
 * Test if two things are equal after JSON stringification.
 * The arguments must be numbers, strings or arrays otherwise the behaviour is
 * undefined.
 */
function assertEq(got, want) {
    const gotJSON = JSON.stringify(got);
    const wantJSON = JSON.stringify(want);
    if (wantJSON != gotJSON) {
        throw new Error(`Want ${wantJSON} got ${gotJSON}`);
    }
}

describe('Base64', function() {
    const testVectors = [
        [[], ''],
        [[255], '/w'],
        [[255, 255], '//8'],
        [[255, 255, 255], '////'],
        [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 'AAECAwQFBgcICQ'],
    ];

    testVectors.forEach(function(vector) {
        const input = vector[0];
        const want = vector[1];
        it(`encodes ${JSON.stringify(input)} correctly`, function() {
            const got = MatrixEncryptAttachment.encodeBase64(new Uint8Array(input));
            assertEq(got, want);
        });
    });
    testVectors.forEach(function(vector) {
        const input = vector[1];
        const want = vector[0];
        it(`decodes ${JSON.stringify(input)} correctly`, function() {
            const got = Array.prototype.slice.call(MatrixEncryptAttachment.decodeBase64(input));
            assertEq(got, want);
        });
    });
});
