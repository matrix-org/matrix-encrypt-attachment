module.exports = {
    plugins: [
        'matrix-org',
    ],
    env: {
        browser: true,
    },
    overrides: [
        {
            files: ['*.ts'],
            extends: [
                'plugin:matrix-org/typescript',
            ],
            parserOptions: {
                project: ['./tsconfig.json'],
            },
        },
        {
            files: ['*.js'],
            extends: [
                'plugin:matrix-org/javascript',
            ],
            env: {
                es6: true,
            }
        },
    ],
};
