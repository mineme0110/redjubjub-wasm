/** @type {import('next').NextConfig} */
const nextConfig = {
    webpack: (config, { isServer }) => {
        config.experiments = {
            ...config.experiments,
            asyncWebAssembly: true,
        };

        // Log webpack configuration for debugging
        console.log('Webpack config:', {
            experiments: config.experiments,
            wasmLoading: config.module.rules.find(rule => rule.test?.test?.('.wasm')),
        });

        return config;
    },
};

module.exports = nextConfig; 