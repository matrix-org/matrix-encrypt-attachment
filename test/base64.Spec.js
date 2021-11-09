
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
        throw new Error('Want ' + wantJSON + ' got ' + gotJSON);
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
        it('encodes ' + JSON.stringify(input) + ' correctly', function() {
            const got = encodeBase64(new Uint8Array(input));
            assertEq(got, want);
        });
    });
    testVectors.forEach(function(vector) {
        const input = vector[1];
        const want = vector[0];
        it('decodes ' + JSON.stringify(input) + ' correctly', function() {
            const got = Array.prototype.slice.call(decodeBase64(input));
            assertEq(got, want);
        });
    });
});
