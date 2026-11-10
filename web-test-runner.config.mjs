import { readFileSync } from "node:fs";

import { playwrightLauncher } from "@web/test-runner-playwright";

// The specs are plain scripts that use the global `MatrixEncryptAttachment` exported by the
// browserify bundle, so load that bundle before the test framework and the specs.
const { browser: bundle } = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));

export default {
    files: "test/**/*Spec.js",
    browsers: [
        playwrightLauncher({ product: "chromium" }),
        playwrightLauncher({ product: "firefox" }),
        playwrightLauncher({ product: "webkit" }),
    ],
    testRunnerHtml: (testFramework) => `<!DOCTYPE html>
<html>
  <body>
    <script src="/${bundle}"></script>
    <script type="module" src="${testFramework}"></script>
  </body>
</html>`,
};
