// For testing in NodeJS we load the CommonJS module into global namespace so that we reuse the existing tests

/* eslint-disable */
const path = require('path');
global.MatrixEncryptAttachment = require(path.join('..', require('../package.json').main));
/* eslint-enable */
