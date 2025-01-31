const nextConfig = {
    webpack: (config, { isServer }) => {
        config.experiments = {
            ...config.experiments,
            asyncWebAssembly: true,
        };

        config.resolve.fallback = {
            ...config.resolve.fallback,
            fs: false,
        };

        return config;
    },
};

module.exports = nextConfig;