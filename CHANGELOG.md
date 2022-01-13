# 1.0.0 (2022-01-13)


### Bug Fixes

* encryptAttachment "unknown encoding base64url" error on node 12 ([dd7ac6b](https://github.com/matrix-org/matrix-encrypt-attachment/commit/dd7ac6b5d43525a31a3e9f94cb98777600d69489))
* **nodejs:** correctly encode JWK.k as URL safe base64 without padding ([f3b7a8a](https://github.com/matrix-org/matrix-encrypt-attachment/commit/f3b7a8a1c3633868ed24318c81546c3e52571602))
* tests on node 12 ([53a5540](https://github.com/matrix-org/matrix-encrypt-attachment/commit/53a55400426df0cdd0a21f6f04bf309a3a88cf89))

Changes in [0.3.0](https://github.com/matrix-org/browser-encrypt-attachment/releases/tag/v0.3.0) (2016-11-23)
===================================================================================================
[Full Changelog](https://github.com/matrix-org/browser-encrypt-attachment/compare/v0.2.0...v0.3.0)

Changes:

 * Set the 64 bit counter to 0 to avoid overflow to make Android compatibility easier. (PR #4)

Changes in [0.2.0](https://github.com/matrix-org/browser-encrypt-attachment/releases/tag/v0.2.0) (2016-11-22)
===================================================================================================
[Full Changelog](https://github.com/matrix-org/browser-encrypt-attachment/compare/v0.1.0...v0.2.0)

Breaking changes:

 * Use a 64 bit counter in AES-CTR to make iOS compatibility easier. (PR #3)

Changes in [0.1.0](https://github.com/matrix-org/browser-encrypt-attachment/releases/tag/v0.1.0) (2016-11-11)
===================================================================================================
[Full Changelog](https://github.com/matrix-org/browser-encrypt-attachment/compare/v0.0.0...v0.1.0)

Breaking changes:

 * Use AES-CTR rather than AES-GCM to make iOS compatibility easier. (PR #2)
