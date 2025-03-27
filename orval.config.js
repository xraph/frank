module.exports = {
  frankClient: {
    input: {
      target: './gen/http/openapi3.json',
    },
    output: {
      mode: 'tags-split',
      target: './web/js-sdk/src',
      schemas: './web/js-sdk/src/model',
      client: 'react-query',
      mock: true,
      override: {
        mutator: {
          path: './web/js-sdk/src/api/mutator/custom-instance.ts',
          name: 'customInstance',
        },
        operations: {},
        query: {
          useQuery: true,
          useInfinite: true,
          useInfiniteQueryParam: 'pageParam',
          useMutation: true,
        },
      },
      prettier: true,
      clean: true,
    },
  },
};
