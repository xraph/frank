import type {StorybookConfig} from '@storybook/react-vite';
import {mergeConfig} from 'vite';
import * as path from 'path';

const config: StorybookConfig = {
    stories: [
        '../src/**/*.stories.@(js|jsx|mjs|ts|tsx)',
        '../stories/**/*.stories.@(js|jsx|mjs|ts|tsx)',
    ],

    addons: [
        '@storybook/addon-essentials',
        '@storybook/addon-interactions',
        '@storybook/addon-links',
        '@storybook/addon-docs',
        '@storybook/addon-controls',
        '@storybook/addon-viewport',
        '@storybook/addon-backgrounds',
        '@storybook/addon-measure',
        '@storybook/addon-outline',
        {
            name: '@storybook/addon-styling',
            options: {
                postCss: {
                    implementation: require.resolve('postcss'),
                },
            },
        },
    ],

    framework: {
        name: '@storybook/react-vite',
        options: {},
    },

    core: {
        builder: '@storybook/builder-vite',
    },

    typescript: {
        check: false,
        reactDocgen: 'react-docgen-typescript',
        reactDocgenTypescriptOptions: {
            shouldExtractLiteralValuesFromEnum: true,
            propFilter: (prop) => (prop.parent ? !/node_modules/.test(prop.parent.fileName) : true),
        },
    },

    docs: {
        autodocs: 'tag',
        defaultName: 'Documentation',
    },

    async viteFinal(config) {
        return mergeConfig(config, {
            resolve: {
                alias: {
                    '@': path.resolve(__dirname, '../src'),
                    '@/components': path.resolve(__dirname, '../src/components'),
                    '@/hooks': path.resolve(__dirname, '../src/hooks'),
                    '@/utils': path.resolve(__dirname, '../src/utils'),
                    '@/config': path.resolve(__dirname, '../src/config'),
                    '@/styles': path.resolve(__dirname, '../src/styles'),
                    '@/types': path.resolve(__dirname, '../src/types'),
                },
            },
            css: {
                postcss: path.resolve(__dirname, '../postcss.config.js'),
            },
            define: {
                global: 'globalThis',
            },
        });
    },

    features: {
        experimentalRSC: false,
    },

    staticDirs: ['../public'],
};

export default config;