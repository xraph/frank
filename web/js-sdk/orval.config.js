module.exports = {
  frankClient: {
    input: {
      target: '../../gen/http/openapi3.json',
    },
    output: {
      mode: 'tags-split',
      target: './vanilla',
      schemas: './model',
      // client: 'react-query',
      // client: 'swr',
      client: 'fetch',
      // httpClient: 'fetch',
      mock: false,
      override: {
        mutator: {
          path: './mutator/custom-instance.ts',
          name: 'customInstance',
        },
      },
      prettier: true,
      clean: true,
    },
  },
  frankClientReact: {
    input: {
      target: '../../gen/http/openapi3.json',
    },
    output: {
      mode: 'tags-split',
      target: './react',
      schemas: './model',
      client: 'react-query',
      // client: 'swr',
      httpClient: 'fetch',
      mock: false,
      override: {
        mutator: {
          path: './mutator/custom-instance.ts',
          name: 'customInstance',
        },
        // operations: {},
        query: {
          useQuery: true,
          useInfinite: true,
          // useInfiniteQueryParam: 'pageParam',
          useMutation: true,
        },
      },
      prettier: true,
      clean: false,
    },
  },
};
