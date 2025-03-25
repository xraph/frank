import {defaultPlugins, defineConfig} from '@hey-api/openapi-ts';

export default defineConfig({
    input: '../../gen/http/openapi3.json',
    output: 'vanilla',
    plugins: [
        ...defaultPlugins,
        '@hey-api/client-fetch',
        '@hey-api/client-next',
        {
            name: '@tanstack/react-query',
        },
        {
            bundle: true,
            name: '@hey-api/client-next',
        },
        // 'zod',
        {
            name: '@hey-api/sdk',
            // validator: true,
        },
        {
            dates: true,
            name: '@hey-api/transformers',
        },
    ],
});